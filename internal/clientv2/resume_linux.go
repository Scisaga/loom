//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const MaximumLinuxResumeDescriptorBytes = 1 << 20

// DecodeLinuxResumeDescriptor 只接受 exact canonical `.loom-resume` JSON。签名、
// authority 和本机 pending binding 在 RunLinuxResumeAttempt 前后完整验证（D130）。
func DecodeLinuxResumeDescriptor(raw []byte) (wire.EnrollmentResumeDescriptorV1, error) {
	if len(raw) == 0 || len(raw) > MaximumLinuxResumeDescriptorBytes {
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[D130 Linux resume] descriptor 大小无效")
	}
	var descriptor wire.EnrollmentResumeDescriptorV1
	canonical, err := wire.DecodeStrict(raw, MaximumLinuxResumeDescriptorBytes, &descriptor)
	if err != nil || !bytes.Equal(canonical, raw) || descriptor.Schema != 1 {
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[D130 Linux resume] descriptor 必须是 exact canonical wire")
	}
	return descriptor, nil
}

// ReadLinuxResumeDescriptor 支持普通 `.loom-resume` 文件或 path="-" 的标准输入。
// 文件 carrier 禁止 symlink/device/FIFO；秘密状态仍只从 root-owned pending 目录读取（D129、D130）。
func ReadLinuxResumeDescriptor(path string, stdin io.Reader) (wire.EnrollmentResumeDescriptorV1, error) {
	if path == "-" {
		if stdin == nil {
			return wire.EnrollmentResumeDescriptorV1{}, errors.New("[D130 Linux resume] stdin 不能为空")
		}
		raw, err := io.ReadAll(io.LimitReader(stdin, MaximumLinuxResumeDescriptorBytes+1))
		if err != nil {
			return wire.EnrollmentResumeDescriptorV1{}, err
		}
		return DecodeLinuxResumeDescriptor(raw)
	}
	if path == "" || filepath.Clean(path) != path {
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[D130 Linux resume] file path 非规范")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[D130 Linux resume] 无法建立 carrier handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 1 || info.Size() > MaximumLinuxResumeDescriptorBytes {
		return wire.EnrollmentResumeDescriptorV1{}, errors.New("[D130 Linux resume] carrier 必须是有界普通文件")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaximumLinuxResumeDescriptorBytes+1))
	if err != nil {
		return wire.EnrollmentResumeDescriptorV1{}, err
	}
	return DecodeLinuxResumeDescriptor(raw)
}

type PrivateEnrollmentResumeAPI interface {
	Preflight(context.Context, wire.EnrollmentIntentPreflightRequestV1, string) (wire.EnrollmentIntentPreflightResponseV1, error)
	Challenge(context.Context, wire.EnrollmentClaimCoreV2) (wire.EnrollmentPoPChallengeV1, error)
	SubmitResume(context.Context, wire.EnrollmentResumeSubmissionV1) (wire.EnrollmentClaimResultV2, error)
}

var _ PrivateEnrollmentResumeAPI = (*PrivateEnrollmentClient)(nil)

type LinuxResumeAttemptV1 struct {
	Descriptor     *wire.EnrollmentResumeDescriptorV1
	ProofBundle    *wire.InviteProofBundleV2
	Catalog        *wire.BootstrapEndpointCatalogV1
	Trust          wire.InviteProofTrustV2
	API            PrivateEnrollmentResumeAPI
	IdentityPath   string
	PendingPath    string
	ClientProtocol int64
	Now            func() time.Time
}

// RunLinuxResumeAttempt 在已由 descriptor capability 建立的临时 tunnel 内恢复一次
// committed transaction。它不读取或发送 Invite token，只重用原 core/key 并签 fresh challenge（D130）。
func RunLinuxResumeAttempt(ctx context.Context,
	attempt LinuxResumeAttemptV1) (LinuxEnrollmentAttemptResultV2, error) {
	if attempt.Descriptor == nil || attempt.ProofBundle == nil || attempt.Catalog == nil ||
		attempt.API == nil || attempt.Now == nil || attempt.IdentityPath == "" ||
		attempt.PendingPath == "" || attempt.ClientProtocol < 1 {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] attempt 输入不完整")
	}
	now := attempt.Now().UTC()
	if now.IsZero() {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] 可信时间无效")
	}
	descriptor := attempt.Descriptor
	bundle := attempt.ProofBundle
	verifiedProof, err := wire.VerifyResumeInviteProofBundle(bundle, descriptor, now, attempt.Trust)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	recordHash, err := wire.CertifiedInviteRecordHash(&bundle.CertifiedInviteRecord,
		&bundle.InviteIssuancePolicy)
	if err != nil || recordHash != verifiedProof.CertifiedInviteRecordHash() ||
		descriptor.ClusterID != bundle.ClusterID || descriptor.InviteID != bundle.InviteID {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] proof evidence/descriptor 不匹配")
	}
	verifiedHead := verifiedProof.Head()
	verifiedSet := verifiedProof.ControlSet()
	setHash, err := wire.ControlSetHash(&verifiedSet)
	if err != nil || !wire.EqualCanonical(verifiedHead, bundle.RecordHead) ||
		verifiedHead.Body.Payload.ControlSetHash != setHash {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] proof evidence Head/ControlSet 不匹配")
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(attempt.Catalog)
	if err != nil || catalogHash != descriptor.BootstrapCatalogHash ||
		wire.ValidateBootstrapEndpointCatalogAt(attempt.Catalog, now, attempt.ClientProtocol) != nil ||
		attempt.Catalog.BootstrapIngressSetHash != descriptor.ResumeTunnelCapability.Body.AllowedIngressSetHash {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] catalog/hash/ingress binding 无效")
	}
	catalogHead, catalogSet, previousSet, ok := verifiedProof.AuthorityForHead(attempt.Catalog.ParentHeadHash)
	if !ok || wire.VerifyConfigQCAuthority(attempt.Catalog.ParentHeadHash,
		attempt.Catalog.BootstrapIngressSet.ConfigQC, &catalogHead, &catalogSet, previousSet) != nil {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] catalog QC authority 未通过 Invite lineage")
	}
	identity, err := LoadEnrollmentIdentityForResume(attempt.IdentityPath)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	pending, err := LoadPendingClaimForResume(attempt.PendingPath, identity)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	core := pending.ClaimCore
	if core.ClusterID != descriptor.ClusterID || core.InviteID != descriptor.InviteID ||
		core.RequestID != descriptor.RequestID || core.CertifiedInviteRecordHash != recordHash ||
		core.DeviceEnrollmentIntentCommitmentHash != bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash ||
		core.BaseHeadHash != verifiedHead.HeadHash || core.BaseRecoveryEpoch != verifiedHead.Body.Payload.RecoveryEpoch ||
		core.BaseControlEpoch != verifiedHead.Body.Payload.ControlEpoch || core.BaseControlSetHash != setHash {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] pending core 未绑定 exact Invite authority")
	}
	if err := wire.VerifyEnrollmentResumeDescriptorBindings(descriptor, pending.Progress.Expected,
		attempt.Catalog, &bundle.BootstrapIssuerAuthorizationProof,
		&bundle.InviteIssuancePolicy, now, attempt.ClientProtocol); err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}

	preflightRequest := wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: core.ClusterID, InviteID: core.InviteID,
		CertifiedInviteRecordHash: recordHash,
		CapabilityID:              descriptor.ResumeTunnelCapability.CapabilityID,
	}
	preflight, err := attempt.API.Preflight(ctx, preflightRequest,
		bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	if err := wire.VerifyEnrollmentIntentPreflight(&preflight, &preflightRequest,
		bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash); err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	opening := preflight.DeviceEnrollmentIntentOpening
	openingHash, err := wire.IntentOpeningHash(&opening)
	intentHash, intentErr := wire.EnrollmentIntentHash(&opening.DeviceEnrollmentIntent)
	if err != nil || intentErr != nil || opening.DeviceEnrollmentIntent.Platform != "linux-server" ||
		openingHash != core.DeviceEnrollmentIntentOpeningHash ||
		intentHash != core.AcceptedDeviceEnrollmentIntentHash ||
		!wire.EqualCanonical(preflight.DeviceEnrollmentIntentCommitment,
			bundle.DeviceEnrollmentIntentCommitment) {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] preflight 未恢复 exact committed opening")
	}
	challenge, err := attempt.API.Challenge(ctx, core)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	challengeNow := attempt.Now().UTC()
	if challengeNow.IsZero() {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] challenge 可信时间无效")
	}
	if err := wire.VerifyEnrollmentResumeDescriptorBindings(descriptor, pending.Progress.Expected,
		attempt.Catalog, &bundle.BootstrapIssuerAuthorizationProof,
		&bundle.InviteIssuancePolicy, challengeNow, attempt.ClientProtocol); err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	challengeHash, err := wire.EnrollmentChallengeHash(&challenge, pending.ClaimCoreHash, challengeNow)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	pop := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
		ClaimCoreHash: pending.ClaimCoreHash, TokenCommitment: bundle.CertifiedInviteRecord.TokenCommitment,
		ChallengeHash: challengeHash,
	}
	signature, err := identity.SignPoP(&pop)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	submission := wire.EnrollmentResumeSubmissionV1{
		Schema: 1, ClaimCore: core, Challenge: challenge, PoPBody: pop, ProofSignature: signature,
	}
	if _, err := wire.VerifyEnrollmentResumeSubmission(&submission,
		descriptor.ResumeTunnelCapability.Body.ResumeBinding, &bundle.CertifiedInviteRecord,
		&bundle.InviteIssuancePolicy, &opening, descriptor.EnrollmentServiceRef.ServiceID, challengeNow); err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	result, err := attempt.API.SubmitResume(ctx, submission)
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	resultNow := attempt.Now().UTC()
	if resultNow.IsZero() {
		return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] result 可信时间无效")
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	var progress enrollmentv2.VerifiedEnrollmentProgressV1
	var completion enrollmentv2.VerifiedEnrollmentCompletionV1
	proofExpected := enrollmentv2.EnrollmentProgressExpectedV1{
		Record: bundle.CertifiedInviteRecord, Policy: bundle.InviteIssuancePolicy,
		Opening: opening, ClaimCore: core, BaseHead: verifiedHead, BaseControlSet: verifiedSet,
	}
	requiredTransactionFloors := []string{
		pending.Progress.Expected.EnrollmentTransactionStateHash,
		descriptor.EnrollmentTransactionStateHash,
	}
	if result.Status == "completed" {
		completion, err = enrollmentv2.VerifyEnrollmentCompletionReceipt(result.CompletionReceipt,
			&result, enrollmentv2.EnrollmentCompletionExpectedV1{
				Record: proofExpected.Record, Policy: proofExpected.Policy, Opening: proofExpected.Opening,
				ClaimCore: proofExpected.ClaimCore, BaseHead: proofExpected.BaseHead,
				BaseControlSet: proofExpected.BaseControlSet, TrustedTime: resultNow,
			})
		for _, required := range requiredTransactionFloors {
			if err == nil && !completion.IncludesTransactionStateHash(required) {
				err = errors.New("[D130 Linux resume] completion receipt 不包含本机与 descriptor transaction floor")
			}
		}
	} else {
		if len(result.ProgressReceipt) == 0 {
			return LinuxEnrollmentAttemptResultV2{}, errors.New("[D130 Linux resume] pending 响应缺 progress receipt")
		}
		progress, err = enrollmentv2.VerifyEnrollmentProgressReceipt(result.ProgressReceipt,
			&result, proofExpected)
		for _, required := range requiredTransactionFloors {
			if err == nil && !progress.IncludesTransactionStateHash(required) {
				err = errors.New("[D130 Linux resume] progress receipt 不包含本机与 descriptor transaction floor")
			}
		}
		if err == nil {
			_, err = RecordPendingProgress(attempt.PendingPath, identity,
				claimCoreInputFromPending(core), progress)
		}
	}
	if err != nil {
		return LinuxEnrollmentAttemptResultV2{}, err
	}
	return LinuxEnrollmentAttemptResultV2{ClaimCoreHash: pending.ClaimCoreHash,
		IdentityHash: identityHash, Result: result, Progress: progress, Completion: completion}, nil
}

func claimCoreInputFromPending(core wire.EnrollmentClaimCoreV2) ClaimCoreInputV2 {
	return ClaimCoreInputV2{
		ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
		CertifiedInviteRecordHash:            core.CertifiedInviteRecordHash,
		DeviceEnrollmentIntentCommitmentHash: core.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    core.DeviceEnrollmentIntentOpeningHash,
		AcceptedDeviceEnrollmentIntentHash:   core.AcceptedDeviceEnrollmentIntentHash,
		BaseRecoveryEpoch:                    core.BaseRecoveryEpoch, BaseControlEpoch: core.BaseControlEpoch,
		BaseControlSetHash: core.BaseControlSetHash, BaseHeadHash: core.BaseHeadHash,
		ClientNonce: core.ClientNonce,
	}
}
