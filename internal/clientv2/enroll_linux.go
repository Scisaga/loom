//go:build linux

package clientv2

import (
	"context"
	"errors"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type PrivateEnrollmentAPI interface {
	Preflight(context.Context, wire.EnrollmentIntentPreflightRequestV1, string) (wire.EnrollmentIntentPreflightResponseV1, error)
	Challenge(context.Context, wire.EnrollmentClaimCoreV2) (wire.EnrollmentPoPChallengeV1, error)
	SubmitClaim(context.Context, wire.EnrollmentClaimSubmissionV2) (wire.EnrollmentClaimResultV2, error)
}

type LinuxEnrollmentAttemptV2 struct {
	Descriptor    *wire.InviteBootstrapDescriptorV2
	ProofBundle   *wire.InviteProofBundleV2
	VerifiedProof wire.VerifiedInviteProofV2
	API           PrivateEnrollmentAPI
	IdentityPath  string
	PendingPath   string
	RequestID     string
	Now           func() time.Time
}

type LinuxEnrollmentAttemptResultV2 struct {
	ClaimCoreHash string
	IdentityHash  string
	Result        wire.EnrollmentClaimResultV2
	Progress      enrollmentv2.VerifiedEnrollmentProgressV1
	Completion    enrollmentv2.VerifiedEnrollmentCompletionV1
}

type verifiedEnrollmentInputs struct {
	descriptor wire.InviteBootstrapDescriptorV2
	record     wire.CertifiedInviteRecordV2
	policy     wire.InviteIssuancePolicyV2
	commitment wire.DeviceEnrollmentIntentCommitmentV1
	head       wire.HeadEntryV2
	set        wire.ControlSetV1
}

// RunLinuxEnrollmentAttempt 执行一次已建 capability tunnel 内的完整尝试。调用顺序固定为
// token-free preflight → 本地 keys/stable core → server challenge → token+detached PoP；
// 网络重试必须复用 IdentityPath/PendingPath/RequestID。
func RunLinuxEnrollmentAttempt(ctx context.Context, attempt LinuxEnrollmentAttemptV2) (LinuxEnrollmentAttemptResultV2, error) {
	inputs, err := bindVerifiedEnrollmentInputs(attempt)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	return runLinuxEnrollmentAttempt(ctx, attempt, inputs)
}

func bindVerifiedEnrollmentInputs(attempt LinuxEnrollmentAttemptV2) (verifiedEnrollmentInputs, error) {
	if attempt.Descriptor == nil || attempt.ProofBundle == nil || attempt.API == nil || attempt.Now == nil ||
		attempt.IdentityPath == "" || attempt.PendingPath == "" || attempt.RequestID == "" {
		return verifiedEnrollmentInputs{}, errors.New("[Linux] Enrollment attempt 输入不完整")
	}
	now := attempt.Now().UTC()
	if now.IsZero() {
		return verifiedEnrollmentInputs{}, errors.New("[Linux] Enrollment 可信时间无效")
	}
	bundle := attempt.ProofBundle
	descriptor := attempt.Descriptor
	recordHash, err := wire.CertifiedInviteRecordHash(&bundle.CertifiedInviteRecord, &bundle.InviteIssuancePolicy)
	if err != nil || recordHash != attempt.VerifiedProof.CertifiedInviteRecordHash() {
		return verifiedEnrollmentInputs{}, errors.New("[Linux] proof evidence 与 exact Invite record 不匹配")
	}
	verifiedHead := attempt.VerifiedProof.Head()
	verifiedSet := attempt.VerifiedProof.ControlSet()
	setHash, err := wire.ControlSetHash(&verifiedSet)
	if err != nil || verifiedHead.Body.Payload.ControlSetHash != setHash ||
		!wire.EqualCanonical(verifiedHead, bundle.RecordHead) {
		return verifiedEnrollmentInputs{}, errors.New("[Linux] proof evidence 与 record head/ControlSet 不匹配")
	}
	if err := wire.VerifyInviteDescriptorBindings(descriptor, &bundle.CertifiedInviteRecord,
		&bundle.InviteIssuancePolicy, &bundle.DeviceEnrollmentIntentCommitment,
		&bundle.BootstrapIssuerAuthorizationProof, now); err != nil {
		return verifiedEnrollmentInputs{}, err
	}
	return verifiedEnrollmentInputs{
		descriptor: clonePrivateClientValue(*descriptor), record: clonePrivateClientValue(bundle.CertifiedInviteRecord),
		policy: clonePrivateClientValue(bundle.InviteIssuancePolicy), commitment: clonePrivateClientValue(bundle.DeviceEnrollmentIntentCommitment),
		head: verifiedHead, set: verifiedSet,
	}, nil
}

func runLinuxEnrollmentAttempt(ctx context.Context, attempt LinuxEnrollmentAttemptV2,
	inputs verifiedEnrollmentInputs) (LinuxEnrollmentAttemptResultV2, error) {
	recordHash, _ := wire.CertifiedInviteRecordHash(&inputs.record, &inputs.policy)
	preflightRequest := wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: inputs.record.ClusterID, InviteID: inputs.record.InviteID,
		CertifiedInviteRecordHash: recordHash, CapabilityID: inputs.descriptor.BootstrapTunnelCapability.CapabilityID,
	}
	preflightRequest, err := wire.AuthorizeInitialEnrollmentPreflight(preflightRequest, inputs.descriptor.Token)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	preflight, err := attempt.API.Preflight(ctx, preflightRequest, inputs.record.DeviceEnrollmentIntentCommitmentHash)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	if err := wire.VerifyEnrollmentIntentPreflight(&preflight, &preflightRequest,
		inputs.record.DeviceEnrollmentIntentCommitmentHash); err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	if preflight.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent.Platform != "linux-server" ||
		!wire.EqualCanonical(preflight.DeviceEnrollmentIntentCommitment, inputs.commitment) {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[Linux] preflight intent/platform 与 certified Invite 不匹配")
	}
	// 只有完整 token-free preflight 通过后才生成 Device key/CSR。
	identity, err := OpenOrCreateEnrollmentIdentity(attempt.IdentityPath)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	openingHash, _ := wire.IntentOpeningHash(&preflight.DeviceEnrollmentIntentOpening)
	intentHash, _ := wire.EnrollmentIntentHash(&preflight.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent)
	setHash, _ := wire.ControlSetHash(&inputs.set)
	pending, err := OpenOrCreatePendingClaim(attempt.PendingPath, identity, ClaimCoreInputV2{
		ClusterID: inputs.record.ClusterID, InviteID: inputs.record.InviteID, RequestID: attempt.RequestID,
		CertifiedInviteRecordHash: recordHash, DeviceEnrollmentIntentCommitmentHash: inputs.record.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash: openingHash, AcceptedDeviceEnrollmentIntentHash: intentHash,
		BaseRecoveryEpoch: inputs.head.Body.Payload.RecoveryEpoch, BaseControlEpoch: inputs.head.Body.Payload.ControlEpoch,
		BaseControlSetHash: setHash, BaseHeadHash: inputs.head.HeadHash,
	})
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	challenge, err := attempt.API.Challenge(ctx, pending.ClaimCore)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	now := attempt.Now().UTC()
	challengeHash, err := wire.EnrollmentChallengeHash(&challenge, pending.ClaimCoreHash, now)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	pop := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: inputs.record.ClusterID, InviteID: inputs.record.InviteID, RequestID: attempt.RequestID,
		ClaimCoreHash: pending.ClaimCoreHash, TokenCommitment: inputs.record.TokenCommitment, ChallengeHash: challengeHash,
	}
	signature, err := identity.SignPoP(&pop)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	submission := wire.EnrollmentClaimSubmissionV2{
		Schema: 2, Token: inputs.descriptor.Token, ClaimCore: pending.ClaimCore,
		Challenge: challenge, PoPBody: pop, ProofSignature: signature,
	}
	// 在 token 离开进程前再执行一次与 server voter 相同的完整本地校验。
	if _, err := wire.VerifyEnrollmentClaimSubmission(&submission, &inputs.record, &inputs.policy,
		&preflight.DeviceEnrollmentIntentOpening, inputs.descriptor.EnrollmentServiceRef.ServiceID, now); err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	result, err := attempt.API.SubmitClaim(ctx, submission)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	resultNow := attempt.Now().UTC()
	if resultNow.IsZero() {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[Linux] Enrollment result 可信时间无效")
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	var progress enrollmentv2.VerifiedEnrollmentProgressV1
	var completion enrollmentv2.VerifiedEnrollmentCompletionV1
	if result.Status == "completed" {
		completion, err = enrollmentv2.VerifyEnrollmentCompletionReceipt(result.CompletionReceipt, &result,
			enrollmentv2.EnrollmentCompletionExpectedV1{
				Record: inputs.record, Policy: inputs.policy,
				Opening: preflight.DeviceEnrollmentIntentOpening, ClaimCore: pending.ClaimCore,
				BaseHead: inputs.head, BaseControlSet: inputs.set, TrustedTime: resultNow,
			})
		if err != nil {
			return LinuxEnrollmentAttemptResultV2{}, err
		}
	} else if len(result.ProgressReceipt) != 0 {
		progress, err = enrollmentv2.VerifyEnrollmentProgressReceipt(result.ProgressReceipt, &result,
			enrollmentv2.EnrollmentProgressExpectedV1{
				Record: inputs.record, Policy: inputs.policy,
				Opening: preflight.DeviceEnrollmentIntentOpening, ClaimCore: pending.ClaimCore,
				BaseHead: inputs.head, BaseControlSet: inputs.set,
			})
		if err != nil {
			return LinuxEnrollmentAttemptResultV2{}, err
		}
		if _, err := RecordPendingProgress(attempt.PendingPath, identity, ClaimCoreInputV2{
			ClusterID: inputs.record.ClusterID, InviteID: inputs.record.InviteID, RequestID: attempt.RequestID,
			CertifiedInviteRecordHash:            recordHash,
			DeviceEnrollmentIntentCommitmentHash: inputs.record.DeviceEnrollmentIntentCommitmentHash,
			DeviceEnrollmentIntentOpeningHash:    openingHash,
			AcceptedDeviceEnrollmentIntentHash:   intentHash,
			BaseRecoveryEpoch:                    inputs.head.Body.Payload.RecoveryEpoch,
			BaseControlEpoch:                     inputs.head.Body.Payload.ControlEpoch,
			BaseControlSetHash:                   setHash, BaseHeadHash: inputs.head.HeadHash,
		}, progress); err != nil {
			return LinuxEnrollmentAttemptResultV2{}, err
		}
	}
	return LinuxEnrollmentAttemptResultV2{ClaimCoreHash: pending.ClaimCoreHash, IdentityHash: identityHash,
		Result: result, Progress: progress, Completion: completion}, nil
}

func clonePrivateClientValue[T any](value T) T {
	body, _ := wire.MarshalCanonical(value)
	var result T
	_, _ = wire.DecodeStrict(body, 64<<20, &result)
	return result
}
