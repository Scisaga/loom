package windowsv2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"time"

	"loom/internal/clientsecret"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

var ErrResumeRequired = errors.New("[Windows resume] transaction 已提交；必须导入 exact .loom-resume，禁止重发 Invite token")

type PrivateEnrollmentAPI interface {
	Preflight(context.Context, wire.EnrollmentIntentPreflightRequestV1, string) (wire.EnrollmentIntentPreflightResponseV1, error)
	Challenge(context.Context, wire.EnrollmentClaimCoreV2) (wire.EnrollmentPoPChallengeV1, error)
	SubmitClaim(context.Context, wire.EnrollmentClaimSubmissionV2) (wire.EnrollmentClaimResultV2, error)
}

type EnrollmentAttempt struct {
	Descriptor    *wire.InviteBootstrapDescriptorV2
	ProofBundle   *wire.InviteProofBundleV2
	VerifiedProof wire.VerifiedInviteProofV2
	API           PrivateEnrollmentAPI
	IdentityPath  string
	JournalPath   string
	Protector     clientsecret.Protector
	RequestID     string
	Random        io.Reader
	Now           func() time.Time
}

type EnrollmentAttemptResult struct {
	ClaimCoreHash string
	IdentityHash  string
	Result        wire.EnrollmentClaimResultV2
	Progress      enrollmentv2.VerifiedEnrollmentProgressV1
	Completion    enrollmentv2.VerifiedEnrollmentCompletionV1
}

type verifiedEnrollmentInputs struct {
	descriptor wire.InviteBootstrapDescriptorV2
	bundle     wire.InviteProofBundleV2
	record     wire.CertifiedInviteRecordV2
	policy     wire.InviteIssuancePolicyV2
	commitment wire.DeviceEnrollmentIntentCommitmentV1
	head       wire.HeadEntryV2
	set        wire.ControlSetV1
}

// RunEnrollmentAttempt 固定执行 token-free preflight → protected signer/core →
// fresh challenge → token+PoP。journal 写后回读成功前 token 不会进入请求。
func RunEnrollmentAttempt(ctx context.Context, attempt EnrollmentAttempt) (EnrollmentAttemptResult, error) {
	inputs, err := bindEnrollmentInputs(attempt)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if ctx == nil {
		return EnrollmentAttemptResult{}, errors.New("[Windows] Enrollment context 缺失")
	}
	recordHash, _ := wire.CertifiedInviteRecordHash(&inputs.record, &inputs.policy)
	preflightRequest := wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: inputs.record.ClusterID, InviteID: inputs.record.InviteID,
		CertifiedInviteRecordHash: recordHash,
		CapabilityID:              inputs.descriptor.BootstrapTunnelCapability.CapabilityID,
	}
	preflight, err := attempt.API.Preflight(ctx, preflightRequest,
		inputs.record.DeviceEnrollmentIntentCommitmentHash)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if err := wire.VerifyEnrollmentIntentPreflight(&preflight, &preflightRequest,
		inputs.record.DeviceEnrollmentIntentCommitmentHash); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if preflight.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent.Platform != "windows-desktop" ||
		!wire.EqualCanonical(preflight.DeviceEnrollmentIntentCommitment, inputs.commitment) {
		return EnrollmentAttemptResult{}, errors.New("[Windows] preflight intent/platform 与 certified Invite 不匹配")
	}
	wrappingProfile, err := selectWindowsWrappingProfile(
		preflight.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent.WrappingKeyProfiles)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	// 只有 token-free opening 完整通过后才创建 DPAPI identity/wrapping keys。
	identity, err := OpenOrCreateIdentity(attempt.IdentityPath, attempt.Protector, attempt.Random)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	defer identity.Close()
	store, err := newJournalStore(attempt.JournalPath, attempt.Protector)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	journal, err := openOrCreateEnrollmentJournal(store, identity, inputs, preflight,
		attempt.RequestID, wrappingProfile, attempt.Random)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if journal.Result != nil && journal.Result.Status == "completed" {
		completion, err := verifyCompletedResult(*journal.Result, journal, inputs, attempt.Now().UTC())
		if err != nil {
			return EnrollmentAttemptResult{}, err
		}
		return EnrollmentAttemptResult{ClaimCoreHash: journal.ClaimCoreHash, IdentityHash: identityHash,
			Result: *journal.Result, Completion: completion}, nil
	}
	if journal.Progress != nil {
		return EnrollmentAttemptResult{}, ErrResumeRequired
	}
	challenge, err := attempt.API.Challenge(ctx, journal.ClaimCore)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	now := attempt.Now().UTC()
	challengeHash, err := wire.EnrollmentChallengeHash(&challenge, journal.ClaimCoreHash, now)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	pop := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: inputs.record.ClusterID, InviteID: inputs.record.InviteID,
		RequestID: journal.ClaimCore.RequestID, ClaimCoreHash: journal.ClaimCoreHash,
		TokenCommitment: inputs.record.TokenCommitment, ChallengeHash: challengeHash,
	}
	signature, err := identity.SignEnrollmentPoP(&pop)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	submission := wire.EnrollmentClaimSubmissionV2{
		Schema: 2, Token: inputs.descriptor.Token, ClaimCore: journal.ClaimCore,
		Challenge: challenge, PoPBody: pop, ProofSignature: signature,
	}
	if _, err := wire.VerifyEnrollmentClaimSubmission(&submission, &inputs.record, &inputs.policy,
		&preflight.DeviceEnrollmentIntentOpening,
		inputs.descriptor.EnrollmentServiceRef.ServiceID, now); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	result, err := attempt.API.SubmitClaim(ctx, submission)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	output := EnrollmentAttemptResult{ClaimCoreHash: journal.ClaimCoreHash,
		IdentityHash: identityHash, Result: result}
	if result.Status == "completed" {
		output.Completion, err = verifyCompletedResult(result, journal, inputs, attempt.Now().UTC())
	} else if len(result.ProgressReceipt) != 0 {
		output.Progress, err = enrollmentv2.VerifyEnrollmentProgressReceipt(result.ProgressReceipt,
			&result, enrollmentv2.EnrollmentProgressExpectedV1{
				Record: inputs.record, Policy: inputs.policy,
				Opening: preflight.DeviceEnrollmentIntentOpening, ClaimCore: journal.ClaimCore,
				BaseHead: inputs.head, BaseControlSet: inputs.set,
			})
		if err == nil {
			err = recordJournalProgress(journal, output.Progress)
		}
	} else {
		err = errors.New("[Windows] pending Enrollment result 缺 progress receipt")
	}
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	resultCopy := cloneValue(result)
	journal.Result = &resultCopy
	if err := store.write(journal, identity); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	return output, nil
}

func bindEnrollmentInputs(attempt EnrollmentAttempt) (verifiedEnrollmentInputs, error) {
	if attempt.Descriptor == nil || attempt.ProofBundle == nil || attempt.API == nil ||
		attempt.Protector == nil || attempt.Now == nil || attempt.IdentityPath == "" ||
		attempt.JournalPath == "" || attempt.RequestID == "" {
		return verifiedEnrollmentInputs{}, errors.New("[Windows] Enrollment attempt 输入不完整")
	}
	now := attempt.Now().UTC()
	if now.IsZero() {
		return verifiedEnrollmentInputs{}, errors.New("[Windows] Enrollment 可信时间无效")
	}
	bundle, descriptor := attempt.ProofBundle, attempt.Descriptor
	recordHash, err := wire.CertifiedInviteRecordHash(&bundle.CertifiedInviteRecord,
		&bundle.InviteIssuancePolicy)
	if err != nil || recordHash != attempt.VerifiedProof.CertifiedInviteRecordHash() {
		return verifiedEnrollmentInputs{}, errors.New("[Windows] proof evidence 与 exact Invite record 不匹配")
	}
	head, set := attempt.VerifiedProof.Head(), attempt.VerifiedProof.ControlSet()
	setHash, err := wire.ControlSetHash(&set)
	if err != nil || head.Body.Payload.ControlSetHash != setHash ||
		!wire.EqualCanonical(head, bundle.RecordHead) {
		return verifiedEnrollmentInputs{}, errors.New("[Windows] proof evidence 与 record Head/ControlSet 不匹配")
	}
	if err := wire.VerifyInviteDescriptorBindings(descriptor, &bundle.CertifiedInviteRecord,
		&bundle.InviteIssuancePolicy, &bundle.DeviceEnrollmentIntentCommitment,
		&bundle.BootstrapIssuerAuthorizationProof, now); err != nil {
		return verifiedEnrollmentInputs{}, err
	}
	return verifiedEnrollmentInputs{
		descriptor: cloneValue(*descriptor), bundle: cloneValue(*bundle),
		record: cloneValue(bundle.CertifiedInviteRecord), policy: cloneValue(bundle.InviteIssuancePolicy),
		commitment: cloneValue(bundle.DeviceEnrollmentIntentCommitment), head: head, set: set,
	}, nil
}

func openOrCreateEnrollmentJournal(store *journalStore, identity *Identity,
	inputs verifiedEnrollmentInputs, preflight wire.EnrollmentIntentPreflightResponseV1,
	requestID, wrappingProfile string, random io.Reader,
) (*EnrollmentJournalV1, error) {
	if journal, err := store.load(identity); err == nil {
		if journal.ClaimCore.RequestID != requestID || !wire.EqualCanonical(journal.Descriptor, inputs.descriptor) ||
			!wire.EqualCanonical(journal.ProofBundle, inputs.bundle) ||
			!wire.EqualCanonical(journal.Preflight, preflight) {
			return nil, errors.New("[Windows] existing journal 与本次 Invite/preflight/request 分叉")
		}
		return journal, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	defer clear(nonce)
	recordHash, _ := wire.CertifiedInviteRecordHash(&inputs.record, &inputs.policy)
	openingHash, _ := wire.IntentOpeningHash(&preflight.DeviceEnrollmentIntentOpening)
	intentHash, _ := wire.EnrollmentIntentHash(&preflight.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent)
	setHash, _ := wire.ControlSetHash(&inputs.set)
	core, coreHash, err := identity.PrepareClaimCore(ClaimCoreInput{
		ClusterID: inputs.record.ClusterID, InviteID: inputs.record.InviteID, RequestID: requestID,
		CertifiedInviteRecordHash:            recordHash,
		DeviceEnrollmentIntentCommitmentHash: inputs.record.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    openingHash, AcceptedDeviceEnrollmentIntentHash: intentHash,
		BaseRecoveryEpoch: inputs.head.Body.Payload.RecoveryEpoch,
		BaseControlEpoch:  inputs.head.Body.Payload.ControlEpoch, BaseControlSetHash: setHash,
		BaseHeadHash: inputs.head.HeadHash, ClientNonce: nonce, WrappingProfile: wrappingProfile,
	}, random)
	if err != nil {
		return nil, err
	}
	descriptorHash, _ := wire.HashObject(wire.DomainInviteDescriptor, &inputs.descriptor)
	proofHash, _ := wire.HashObject(wire.DomainInviteProofBundle, &inputs.bundle)
	journal := &EnrollmentJournalV1{
		Schema: 1, Descriptor: inputs.descriptor, DescriptorHash: descriptorHash,
		ProofBundle: inputs.bundle, ProofBundleHash: proofHash, Preflight: cloneValue(preflight),
		ClaimCore: core, ClaimCoreHash: coreHash,
	}
	if err := store.write(journal, identity); err != nil {
		return nil, err
	}
	return store.load(identity)
}

func verifyCompletedResult(result wire.EnrollmentClaimResultV2, journal *EnrollmentJournalV1,
	inputs verifiedEnrollmentInputs, now time.Time,
) (enrollmentv2.VerifiedEnrollmentCompletionV1, error) {
	if now.IsZero() {
		return enrollmentv2.VerifiedEnrollmentCompletionV1{}, errors.New("[Windows] completion 可信时间无效")
	}
	return enrollmentv2.VerifyEnrollmentCompletionReceipt(result.CompletionReceipt, &result,
		enrollmentv2.EnrollmentCompletionExpectedV1{
			Record: inputs.record, Policy: inputs.policy,
			Opening: journal.Preflight.DeviceEnrollmentIntentOpening, ClaimCore: journal.ClaimCore,
			BaseHead: inputs.head, BaseControlSet: inputs.set, TrustedTime: now,
		})
}

func selectWindowsWrappingProfile(profiles []string) (string, error) {
	for _, profile := range profiles {
		if profile == WrappingKeyProfile {
			return profile, nil
		}
	}
	return "", errors.New("[Windows] intent 未授权 Windows DPAPI/CNG P-256 wrapping profile")
}

func NewRequestID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	body := make([]byte, 18)
	if _, err := io.ReadFull(random, body); err != nil {
		return "", err
	}
	defer clear(body)
	return "windows-" + base64.RawURLEncoding.EncodeToString(body), nil
}

func cloneValue[T any](value T) T {
	body, _ := wire.MarshalCanonical(value)
	var cloned T
	_, _ = wire.DecodeStrict(body, 64<<20, &cloned)
	clear(body)
	return cloned
}
