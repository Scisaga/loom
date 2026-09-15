package enrollmentv2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"loom/internal/wire"
)

const (
	maximumPrivateRequestBytes          = 4 << 20
	PrivateEnrollmentArtifactPathPrefix = "/v2/enrollment/artifacts/sha256/"
)

// InviteMaterialV2 是 private Enrollment 从本机 certified state 读取的 exact Invite
// preimage 与包含证明。公网 distribution 不得提供 Opening（D115、D129、D131）。
type InviteMaterialV2 struct {
	Status               string
	Record               wire.CertifiedInviteRecordV2
	Policy               wire.InviteIssuancePolicyV2
	Commitment           wire.DeviceEnrollmentIntentCommitmentV1
	Opening              wire.DeviceEnrollmentIntentOpeningV1
	EnrollmentServiceRef wire.PrivateEnrollmentServiceRefV1
	ParentHead           wire.HeadEntryV2
	RecordHead           wire.HeadEntryV2
	RecordHeadQC         json.RawMessage
	ControlSet           wire.ControlSetV1
	PreviousControlSet   *wire.ControlSetV1
	InviteOperationLeaf  wire.ControlOperationLeafV1
	InviteLeafIndex      int64
	InviteTreeSize       int64
	InviteAuditPath      []string
}

// InviteMaterialReader 必须做线性化读取；PrivateService 会再次验证所有 cryptographic
// binding，reader 返回的状态字符串本身不能替代 head/QC/inclusion proof。
type InviteMaterialReader func(context.Context, string, string) (InviteMaterialV2, error)

// token 只从受保护凭据层读取；不加入 InviteMaterial，避免随副本 mutation 写入日志。
type InviteTokenReader func(context.Context, wire.CertifiedInviteRecordV2) (string, error)

// VerifiedClaimAttemptV2 只能由 PrivateService 在验 initial token 或 exact resume
// binding、opening/core、服务端签发 challenge 和 detached PoP 后产生。processor 可以把 initial
// exact submission 发给 enrollment voters，但不得把其中 token、challenge、CSR 或签名字节写入
// Raft/CRDT/log；resume 永远不触发新的 admission（D129、D130）。
type VerifiedClaimAttemptV2 struct {
	capability wire.VerifiedBootstrapCapabilityV1
	claim      wire.VerifiedEnrollmentClaimV2
	submission wire.EnrollmentClaimSubmissionV2
	material   InviteMaterialV2
}

func (attempt VerifiedClaimAttemptV2) Capability() wire.VerifiedBootstrapCapabilityV1 {
	return attempt.capability
}

func (attempt VerifiedClaimAttemptV2) Claim() wire.VerifiedEnrollmentClaimV2 {
	return attempt.claim
}

func (attempt VerifiedClaimAttemptV2) Submission() wire.EnrollmentClaimSubmissionV2 {
	return clonePrivateValue(attempt.submission)
}

func (attempt VerifiedClaimAttemptV2) InviteContext() InviteContext {
	return InviteContext{
		ClusterID: attempt.material.Record.ClusterID, InviteID: attempt.material.Record.InviteID,
		Status: attempt.material.Status, CertifiedInviteRecordHash: attempt.claimRecordHash(),
		DeviceEnrollmentIntentCommitmentHash: attempt.claim.CommitmentHash(),
		DeviceEnrollmentIntentOpeningHash:    attempt.claim.OpeningHash(), TokenCommitment: attempt.claim.TokenCommitment(),
		ExpiresAt:                      attempt.material.Record.ExpiresAt,
		MaximumReservationRetrySeconds: attempt.material.Policy.MaximumReservationRetrySeconds,
	}
}

func (attempt VerifiedClaimAttemptV2) claimRecordHash() string {
	return attempt.submission.ClaimCore.CertifiedInviteRecordHash
}

func (attempt VerifiedClaimAttemptV2) AdmissionAttestation() (wire.EnrollmentAdmissionAttestationBodyV1, error) {
	return admissionAttestationForVerified(&attempt.material, &attempt.submission, attempt.claim)
}

func admissionAttestationForVerified(material *InviteMaterialV2, submission *wire.EnrollmentClaimSubmissionV2,
	claim wire.VerifiedEnrollmentClaimV2) (wire.EnrollmentAdmissionAttestationBodyV1, error) {
	if material == nil || submission == nil {
		return wire.EnrollmentAdmissionAttestationBodyV1{}, errors.New("[D129 Enrollment] admission material/submission 不能为空")
	}
	retryNotAfter, err := checkedAddSecondsForPrivate(material.Record.ExpiresAt, material.Policy.MaximumReservationRetrySeconds)
	if err != nil {
		return wire.EnrollmentAdmissionAttestationBodyV1{}, err
	}
	core := submission.ClaimCore
	result := wire.EnrollmentAdmissionAttestationBodyV1{
		Schema: 1, AttestationType: "enrollment_admission", ClusterID: core.ClusterID,
		InviteID: core.InviteID, RequestID: core.RequestID,
		CertifiedInviteRecordHash:            core.CertifiedInviteRecordHash,
		DeviceEnrollmentIntentCommitmentHash: core.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    core.DeviceEnrollmentIntentOpeningHash,
		TokenCommitment:                      claim.TokenCommitment(), ClaimCoreHash: claim.ClaimCoreHash(),
		IdentityKeyHash: claim.IdentityKeyHash(), WrappingKeyHash: claim.WrappingKeyHash(),
		CSRHash: claim.CSRHash(), PoPVerificationProfile: "loom-enrollment-server-nonce-detached-v2",
		BaseRecoveryEpoch: core.BaseRecoveryEpoch, BaseControlEpoch: core.BaseControlEpoch,
		BaseControlSetHash: core.BaseControlSetHash, BaseHeadHash: core.BaseHeadHash,
		AdmissionNotAfter: material.Record.ExpiresAt, RetryNotAfter: retryNotAfter,
	}
	if err := wire.ValidateEnrollmentAdmission(&result); err != nil {
		return wire.EnrollmentAdmissionAttestationBodyV1{}, err
	}
	return result, nil
}

type ClaimProcessor func(context.Context, VerifiedClaimAttemptV2) (wire.EnrollmentClaimResultV2, error)

type PrivateService struct {
	clusterID    string
	serviceID    string
	now          func() time.Time
	random       io.Reader
	challengeTTL time.Duration
	replay       *ChallengeReplayStore
	readInvite   InviteMaterialReader
	readToken    InviteTokenReader
	processClaim ClaimProcessor
	readArtifact ReleasedEnrollmentArtifactReader
}

// NewPrivateServiceWithReleasedArtifacts 在原 Enrollment API 上增加同一临时
// tunnel 内的 completion-authorized immutable artifact 读取；它不会新增公网 role（D124、D131）。
func NewPrivateServiceWithReleasedArtifacts(clusterID, serviceID string, now func() time.Time, random io.Reader,
	challengeTTL time.Duration, replay *ChallengeReplayStore, readInvite InviteMaterialReader,
	readToken InviteTokenReader, processClaim ClaimProcessor, readArtifact ReleasedEnrollmentArtifactReader) (*PrivateService, error) {
	if readArtifact == nil {
		return nil, errors.New("[D124 Enrollment] released artifact reader 不能为空")
	}
	service, err := NewPrivateService(clusterID, serviceID, now, random, challengeTTL,
		replay, readInvite, readToken, processClaim)
	if err != nil {
		return nil, err
	}
	service.readArtifact = readArtifact
	return service, nil
}

func NewPrivateService(clusterID, serviceID string, now func() time.Time, random io.Reader,
	challengeTTL time.Duration, replay *ChallengeReplayStore, readInvite InviteMaterialReader,
	readToken InviteTokenReader, processClaim ClaimProcessor) (*PrivateService, error) {
	if clusterID == "" || serviceID == "" || now == nil || replay == nil || readInvite == nil || readToken == nil || processClaim == nil ||
		challengeTTL < time.Second || challengeTTL > 2*time.Minute {
		return nil, errors.New("[D129 Enrollment] private service 配置不完整或 challenge TTL 越界")
	}
	if random == nil {
		random = rand.Reader
	}
	return &PrivateService{clusterID: clusterID, serviceID: serviceID, now: now, random: random,
		challengeTTL: challengeTTL, replay: replay, readInvite: readInvite, readToken: readToken, processClaim: processClaim}, nil
}

func (service *PrivateService) Preflight(ctx context.Context, capability wire.VerifiedBootstrapCapabilityV1,
	request *wire.EnrollmentIntentPreflightRequestV1) (wire.EnrollmentIntentPreflightResponseV1, error) {
	if request == nil {
		return wire.EnrollmentIntentPreflightResponseV1{}, errors.New("[D131 Enrollment preflight] request 不能为空")
	}
	requestHash, err := wire.EnrollmentIntentPreflightRequestHash(request)
	if err != nil {
		return wire.EnrollmentIntentPreflightResponseV1{}, err
	}
	material, err := service.boundMaterial(ctx, capability, request.ClusterID, request.InviteID,
		request.CertifiedInviteRecordHash, request.CapabilityID)
	if err != nil {
		return wire.EnrollmentIntentPreflightResponseV1{}, err
	}
	if capability.Body().Mode == "initial_claim" {
		token, err := service.readToken(ctx, material.Record)
		commitment, hashErr := wire.TokenCommitment(material.Record.ClusterID, material.Record.InviteID, token)
		if err != nil || hashErr != nil || commitment != material.Record.TokenCommitment || wire.VerifyInitialEnrollmentPreflight(request, token) != nil {
			return wire.EnrollmentIntentPreflightResponseV1{}, errors.New("[D131 Enrollment preflight] 邀请持有证明未通过")
		}
	} else {
		binding := capability.Body().ResumeBinding
		if binding == nil || wire.VerifyResumeEnrollmentPreflight(request, binding.IdentityKeyHash) != nil {
			return wire.EnrollmentIntentPreflightResponseV1{}, errors.New("[D130 Enrollment preflight] 原设备身份未通过")
		}
	}
	response := wire.EnrollmentIntentPreflightResponseV1{
		Schema: 1, ClusterID: request.ClusterID, InviteID: request.InviteID, RequestHash: requestHash,
		DeviceEnrollmentIntentCommitment: material.Commitment, DeviceEnrollmentIntentOpening: material.Opening,
	}
	if err := wire.VerifyEnrollmentIntentPreflight(&response, request, material.Record.DeviceEnrollmentIntentCommitmentHash); err != nil {
		return wire.EnrollmentIntentPreflightResponseV1{}, err
	}
	return response, nil
}

// Challenge 只接收不含 token 的稳定 core，并在返回 nonce 前耐久登记 challenge hash。
func (service *PrivateService) Challenge(ctx context.Context, capability wire.VerifiedBootstrapCapabilityV1,
	core *wire.EnrollmentClaimCoreV2) (wire.EnrollmentPoPChallengeV1, error) {
	if core == nil {
		return wire.EnrollmentPoPChallengeV1{}, errors.New("[D129 Enrollment] claim core 不能为空")
	}
	material, err := service.boundMaterial(ctx, capability, core.ClusterID, core.InviteID,
		core.CertifiedInviteRecordHash, capability.CapabilityID())
	if err != nil {
		return wire.EnrollmentPoPChallengeV1{}, err
	}
	coreHash, err := service.verifyCoreBindings(core, capability, &material)
	if err != nil {
		return wire.EnrollmentPoPChallengeV1{}, err
	}
	now := service.now().UTC().Truncate(time.Second)
	// issued_at 按已认证 Head 声明的最大时钟偏差回溯，使时钟略慢的 Device
	// 不会把服务端刚签发的 nonce 误判为“尚未生效”。expires 与 replay store
	// 仍从服务端真实时间计算，不能借偏差窗口延长 challenge 寿命（D129）。
	issued := now.Add(-time.Duration(material.RecordHead.Body.Payload.MaxClockSkewSeconds) * time.Second)
	expires := now.Add(service.challengeTTL)
	capabilityExpiry, _ := wire.ParseTimeZ(capability.Body().ExpiresAt)
	if expires.After(capabilityExpiry) {
		expires = capabilityExpiry
	}
	if capability.Body().Mode == "initial_claim" {
		inviteExpiry, _ := wire.ParseTimeZ(material.Record.ExpiresAt)
		if expires.After(inviteExpiry) {
			expires = inviteExpiry
		}
	}
	if !now.Before(expires) {
		return wire.EnrollmentPoPChallengeV1{}, errors.New("[D129 Enrollment] challenge 没有剩余有效期")
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(service.random, nonce); err != nil {
		return wire.EnrollmentPoPChallengeV1{}, errors.New("[D129 Enrollment] 生成 server nonce 失败")
	}
	challenge := wire.EnrollmentPoPChallengeV1{
		Schema: 1, ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
		EnrollmentServiceID: service.serviceID, ClaimCoreHash: coreHash,
		ServerNonce: base64.RawURLEncoding.EncodeToString(nonce), IssuedAt: issued.Format(time.RFC3339),
		ExpiresAt: expires.Format(time.RFC3339),
	}
	challengeHash, err := wire.EnrollmentChallengeHash(&challenge, coreHash, now)
	if err != nil {
		return wire.EnrollmentPoPChallengeV1{}, err
	}
	if err := service.replay.Issue(challengeHash, challenge.ExpiresAt, now); err != nil {
		return wire.EnrollmentPoPChallengeV1{}, err
	}
	return challenge, nil
}

func (service *PrivateService) SubmitClaim(ctx context.Context, capability wire.VerifiedBootstrapCapabilityV1,
	submission *wire.EnrollmentClaimSubmissionV2) (wire.EnrollmentClaimResultV2, error) {
	if submission == nil {
		return wire.EnrollmentClaimResultV2{}, errors.New("[D129 Enrollment] submission 不能为空")
	}
	if capability.Body().Mode != "initial_claim" {
		return wire.EnrollmentClaimResultV2{}, errors.New("[D130 Enrollment] resume capability 禁止携 token claim")
	}
	core := &submission.ClaimCore
	material, err := service.boundMaterial(ctx, capability, core.ClusterID, core.InviteID,
		core.CertifiedInviteRecordHash, capability.CapabilityID())
	if err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	if _, err := service.verifyCoreBindings(core, capability, &material); err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	now := service.now().UTC().Truncate(time.Second)
	verified, err := wire.VerifyEnrollmentClaimSubmission(submission, &material.Record, &material.Policy,
		&material.Opening, service.serviceID, now)
	if err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	return service.finishVerifiedClaim(ctx, capability, verified, clonePrivateValue(*submission),
		submission.Challenge.ExpiresAt, material, now)
}

// SubmitResume 只接受没有 token 字段的恢复 wire；原 Invite 即使已经过期，也只能在
// capability/retry deadline 内继续 descriptor 精确绑定的 committed transaction（D130）。
func (service *PrivateService) SubmitResume(ctx context.Context, capability wire.VerifiedBootstrapCapabilityV1,
	submission *wire.EnrollmentResumeSubmissionV1) (wire.EnrollmentClaimResultV2, error) {
	if submission == nil || capability.Body().Mode != "resume_committed_claim" ||
		capability.Body().ResumeBinding == nil {
		return wire.EnrollmentClaimResultV2{}, errors.New("[D130 resume] submission/capability mode 无效")
	}
	core := &submission.ClaimCore
	material, err := service.boundMaterial(ctx, capability, core.ClusterID, core.InviteID,
		core.CertifiedInviteRecordHash, capability.CapabilityID())
	if err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	if _, err := service.verifyCoreBindings(core, capability, &material); err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	now := service.now().UTC().Truncate(time.Second)
	verified, err := wire.VerifyEnrollmentResumeSubmission(submission,
		capability.Body().ResumeBinding, &material.Record, &material.Policy,
		&material.Opening, service.serviceID, now)
	if err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	stable := wire.EnrollmentClaimSubmissionV2{
		Schema: 2, ClaimCore: clonePrivateValue(submission.ClaimCore),
		Challenge: clonePrivateValue(submission.Challenge), PoPBody: clonePrivateValue(submission.PoPBody),
		ProofSignature: submission.ProofSignature,
	}
	return service.finishVerifiedClaim(ctx, capability, verified, stable,
		submission.Challenge.ExpiresAt, material, now)
}

func (service *PrivateService) finishVerifiedClaim(ctx context.Context,
	capability wire.VerifiedBootstrapCapabilityV1, verified wire.VerifiedEnrollmentClaimV2,
	submission wire.EnrollmentClaimSubmissionV2, challengeExpiresAt string,
	material InviteMaterialV2, now time.Time) (wire.EnrollmentClaimResultV2, error) {
	if err := service.replay.Consume(verified.ChallengeHash(), challengeExpiresAt, now); err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	result, err := service.processClaim(ctx, VerifiedClaimAttemptV2{
		capability: capability, claim: verified, submission: submission, material: material,
	})
	if err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	return result, nil
}

func (service *PrivateService) verifyCoreBindings(core *wire.EnrollmentClaimCoreV2,
	capability wire.VerifiedBootstrapCapabilityV1, material *InviteMaterialV2) (string, error) {
	coreHash, err := verifyCoreMaterialBindings(core, material)
	if err != nil {
		return "", err
	}
	if core.CertifiedInviteRecordHash != capability.Body().CommittedInviteRecordHash {
		return "", errors.New("[D129 Enrollment] claim core 未绑定 exact private intent/base authority")
	}
	if binding := capability.Body().ResumeBinding; binding != nil {
		identityHash, wrappingHash, csrHash, hashErr := wire.EnrollmentClaimBinaryHashes(core)
		if hashErr != nil || binding.RequestID != core.RequestID || binding.ClaimCoreHash != coreHash ||
			binding.IdentityKeyHash != identityHash || binding.WrappingKeyHash != wrappingHash || binding.CSRHash != csrHash {
			return "", errors.New("[D131 Enrollment] resume capability 与 stable claim/key/CSR 不匹配")
		}
	}
	return coreHash, nil
}

func (service *PrivateService) boundMaterial(ctx context.Context, capability wire.VerifiedBootstrapCapabilityV1,
	clusterID, inviteID, recordHash, capabilityID string) (InviteMaterialV2, error) {
	body := capability.Body()
	now := service.now().UTC()
	notBefore, notBeforeErr := wire.ParseTimeZ(body.NotBefore)
	expires, expiresErr := wire.ParseTimeZ(body.ExpiresAt)
	if body.ClusterID != service.clusterID || body.AllowedServiceID != service.serviceID ||
		clusterID != body.ClusterID || inviteID != body.InviteID || recordHash != body.CommittedInviteRecordHash ||
		capabilityID == "" || capabilityID != capability.CapabilityID() || notBeforeErr != nil || expiresErr != nil ||
		now.Before(notBefore) || !now.Before(expires) {
		return InviteMaterialV2{}, errors.New("[D131 Enrollment] capability/request/service/time binding 无效")
	}
	material, err := service.readInvite(ctx, clusterID, inviteID)
	if err != nil {
		return InviteMaterialV2{}, errors.New("[D129 Enrollment] Invite material 不可用")
	}
	if !oneOf(material.Status, "available", "reserved", "issued_provisional", "completed") ||
		body.Mode == "resume_committed_claim" && material.Status == "available" {
		return InviteMaterialV2{}, errors.New("[D130 Enrollment] Invite/transaction 状态不允许当前 capability mode")
	}
	if err := validateCertifiedInviteMaterial(&material, clusterID, inviteID); err != nil {
		return InviteMaterialV2{}, err
	}
	wantRecordHash, _ := wire.CertifiedInviteRecordHash(&material.Record, &material.Policy)
	policyHash, _ := wire.InviteIssuancePolicyHash(&material.Policy)
	serviceHash, _ := wire.PrivateEnrollmentServiceRefHash(&material.EnrollmentServiceRef)
	if wantRecordHash != recordHash || material.Record.ClusterID != clusterID || material.Record.InviteID != inviteID ||
		material.Record.InviteIssuancePolicyHash != policyHash || body.InviteIssuancePolicyHash != policyHash ||
		material.Record.BootstrapIssuerAuthorizationHash != body.BootstrapIssuerAuthorizationHash ||
		material.Record.BootstrapIssuerRegistryRoot != body.BootstrapIssuerRegistryRoot ||
		material.Record.EnrollmentServiceRefHash != body.EnrollmentServiceRefHash || serviceHash != body.EnrollmentServiceRefHash ||
		material.EnrollmentServiceRef.ServiceID != service.serviceID ||
		material.EnrollmentServiceRef.OverlayIP != body.AllowedDestinationIP ||
		material.EnrollmentServiceRef.TCPPort != body.AllowedDestinationPort {
		return InviteMaterialV2{}, errors.New("[D129 Enrollment] capability/record/policy/head binding 无效")
	}
	if body.Mode == "initial_claim" {
		inviteExpiry, _ := wire.ParseTimeZ(material.Record.ExpiresAt)
		if !now.Before(inviteExpiry) || expires.After(inviteExpiry) {
			return InviteMaterialV2{}, errors.New("[D131 Enrollment] initial capability/Invite 已过期或期限越界")
		}
	}
	return cloneInviteMaterial(material), nil
}

func validateCertifiedInviteMaterial(material *InviteMaterialV2, clusterID, inviteID string) error {
	if material == nil || material.Record.ClusterID != clusterID || material.Record.InviteID != inviteID {
		return errors.New("[D129 Enrollment] Invite material identity 无效")
	}
	if err := wire.ValidateCertifiedInviteRecord(&material.Record, &material.Policy); err != nil {
		return err
	}
	wantRecordHash, _ := wire.CertifiedInviteRecordHash(&material.Record, &material.Policy)
	policyHash, _ := wire.InviteIssuancePolicyHash(&material.Policy)
	serviceHash, serviceErr := wire.PrivateEnrollmentServiceRefHash(&material.EnrollmentServiceRef)
	setHash, _ := wire.ControlSetHash(&material.ControlSet)
	payload := material.RecordHead.Body.Payload
	if serviceErr != nil || material.Record.InviteIssuancePolicyHash != policyHash ||
		material.Record.EnrollmentServiceRefHash != serviceHash || material.Record.BootstrapIssuerRegistryRoot != payload.BootstrapIssuerRegistryRoot ||
		payload.ClusterID != clusterID || payload.ControlSetHash != setHash || material.Record.ParentHeadHash != payload.ParentHeadHash {
		return errors.New("[D129 Enrollment] Invite record/policy/service/head binding 无效")
	}
	if err := wire.VerifyConfigQCAuthority(material.RecordHead.HeadHash, material.RecordHeadQC,
		&material.RecordHead, &material.ControlSet, material.PreviousControlSet); err != nil {
		return err
	}
	if err := wire.ValidateHeadEntry(&material.RecordHead, &material.ParentHead); err != nil {
		return errors.New("[D129 Enrollment] Invite record head 不在 exact parent 后")
	}
	if material.InviteOperationLeaf.OperationID != material.Record.OperationID || material.InviteOperationLeaf.ObjectID != wantRecordHash ||
		wire.VerifyControlOperationInclusion(&material.InviteOperationLeaf, material.InviteLeafIndex,
			material.InviteTreeSize, material.InviteAuditPath, &material.RecordHead) != nil {
		return errors.New("[D129 Enrollment] Invite 缺 exact committed inclusion proof")
	}
	commitment, commitmentHash, err := wire.IntentCommitment(&material.Opening)
	if err != nil || commitmentHash != material.Record.DeviceEnrollmentIntentCommitmentHash ||
		!wire.EqualCanonical(commitment, material.Commitment) {
		return errors.New("[D129 Enrollment] private opening 与 certified commitment 不匹配")
	}
	openingBytes, err := wire.MarshalCanonical(material.Opening)
	if err != nil || int64(len(openingBytes)) > material.Policy.MaximumIntentOpeningBytes {
		return errors.New("[D129 Enrollment] private opening 超出 certified policy")
	}
	return nil
}

func verifyCoreMaterialBindings(core *wire.EnrollmentClaimCoreV2, material *InviteMaterialV2) (string, error) {
	if material == nil {
		return "", errors.New("[D129 Enrollment] claim material 不能为空")
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(core)
	if err != nil {
		return "", err
	}
	recordHash, _ := wire.CertifiedInviteRecordHash(&material.Record, &material.Policy)
	openingHash, _ := wire.IntentOpeningHash(&material.Opening)
	intentHash, _ := wire.EnrollmentIntentHash(&material.Opening.DeviceEnrollmentIntent)
	payload := material.RecordHead.Body.Payload
	setHash, _ := wire.ControlSetHash(&material.ControlSet)
	if core.ClusterID != material.Record.ClusterID || core.InviteID != material.Record.InviteID ||
		core.CertifiedInviteRecordHash != recordHash ||
		core.DeviceEnrollmentIntentCommitmentHash != material.Record.DeviceEnrollmentIntentCommitmentHash ||
		core.DeviceEnrollmentIntentOpeningHash != openingHash || core.AcceptedDeviceEnrollmentIntentHash != intentHash ||
		core.ClientPlatform != material.Opening.DeviceEnrollmentIntent.Platform || core.BaseRecoveryEpoch != payload.RecoveryEpoch ||
		core.BaseControlEpoch != payload.ControlEpoch || core.BaseControlSetHash != setHash || core.BaseHeadHash != material.RecordHead.HeadHash {
		return "", errors.New("[D129 Enrollment] claim core 未绑定 exact private intent/base authority")
	}
	return coreHash, nil
}

// VerifyPeerAdmissionAttempt 供每个 enrollment voter 在 control-peer mTLS 后独立
// 验证完整秘密提交；只返回错误，不暴露可持久化的 token/challenge/CSR 正文。
func VerifyPeerAdmissionAttempt(material *InviteMaterialV2, submission *wire.EnrollmentClaimSubmissionV2,
	attestation *wire.EnrollmentAdmissionAttestationBodyV1, enrollmentServiceID string, now time.Time) error {
	if material == nil || submission == nil || attestation == nil || now.IsZero() || material.Status != "available" {
		return errors.New("[D129 Enrollment] peer admission context/Invite 状态无效")
	}
	if err := validateCertifiedInviteMaterial(material, submission.ClaimCore.ClusterID, submission.ClaimCore.InviteID); err != nil {
		return err
	}
	if material.EnrollmentServiceRef.ServiceID != enrollmentServiceID {
		return errors.New("[D129 Enrollment] peer admission service 不属于 certified Invite")
	}
	expires, err := wire.ParseTimeZ(material.Record.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return errors.New("[D130 Enrollment] Invite expiry 后禁止新的 admission")
	}
	verified, err := wire.VerifyEnrollmentClaimSubmission(submission, &material.Record, &material.Policy,
		&material.Opening, enrollmentServiceID, now)
	if err != nil {
		return err
	}
	if _, err := verifyCoreMaterialBindings(&submission.ClaimCore, material); err != nil {
		return err
	}
	want, err := admissionAttestationForVerified(material, submission, verified)
	if err != nil || !wire.EqualCanonical(want, *attestation) {
		return errors.New("[D129 Enrollment] peer admission attestation 未绑定 exact verified submission")
	}
	return nil
}

// ServeHTTP 永远拒绝缺少 outer capability verifier 的直接挂载。bootstrap ingress 必须
// 在验签、revocation、ACL 与 usage budget 后调用 ServeVerifiedHTTP（D131）。
func (service *PrivateService) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writePrivateError(writer, http.StatusForbidden)
}

func (service *PrivateService) ServeVerifiedHTTP(writer http.ResponseWriter, request *http.Request,
	capability wire.VerifiedBootstrapCapabilityV1) {
	if request == nil || request.TLS == nil || !request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 ||
		request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
		request.Header.Get("Referer") != "" || request.Header.Get("Content-Encoding") != "" {
		writePrivateError(writer, http.StatusForbidden)
		return
	}
	if request.Method == http.MethodGet {
		service.serveReleasedArtifact(writer, request, capability)
		return
	}
	if request.Method != http.MethodPost || request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		writePrivateError(writer, http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumPrivateRequestBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumPrivateRequestBytes {
		writePrivateError(writer, http.StatusBadRequest)
		return
	}
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		writePrivateError(writer, http.StatusBadRequest)
		return
	}
	var response any
	status := http.StatusOK
	switch request.URL.Path {
	case "/v2/enrollment/preflight":
		var value wire.EnrollmentIntentPreflightRequestV1
		if _, err = wire.DecodeStrict(body, maximumPrivateRequestBytes, &value); err == nil {
			response, err = service.Preflight(request.Context(), capability, &value)
		}
	case "/v2/enrollment/challenge":
		var value wire.EnrollmentClaimCoreV2
		if _, err = wire.DecodeStrict(body, maximumPrivateRequestBytes, &value); err == nil {
			response, err = service.Challenge(request.Context(), capability, &value)
		}
	case "/v2/enrollment/claim":
		var result wire.EnrollmentClaimResultV2
		if capability.Body().Mode == "resume_committed_claim" {
			var value wire.EnrollmentResumeSubmissionV1
			if _, err = wire.DecodeStrict(body, maximumPrivateRequestBytes, &value); err == nil {
				result, err = service.SubmitResume(request.Context(), capability, &value)
			}
		} else {
			var value wire.EnrollmentClaimSubmissionV2
			if _, err = wire.DecodeStrict(body, maximumPrivateRequestBytes, &value); err == nil {
				result, err = service.SubmitClaim(request.Context(), capability, &value)
			}
		}
		response = result
		if err == nil && result.Status != "completed" {
			status = http.StatusAccepted
		}
	default:
		writePrivateError(writer, http.StatusNotFound)
		return
	}
	if err != nil {
		writePrivateError(writer, http.StatusForbidden)
		return
	}
	encoded, err := wire.MarshalCanonical(response)
	if err != nil {
		writePrivateError(writer, http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func (service *PrivateService) serveReleasedArtifact(writer http.ResponseWriter, request *http.Request,
	capability wire.VerifiedBootstrapCapabilityV1) {
	if service.readArtifact == nil || request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		request.Header.Get("Content-Type") != "" ||
		request.Header.Get("Accept") != "application/json" ||
		!strings.HasPrefix(request.URL.Path, PrivateEnrollmentArtifactPathPrefix) {
		writePrivateError(writer, http.StatusNotFound)
		return
	}
	hexDigest := strings.TrimPrefix(request.URL.Path, PrivateEnrollmentArtifactPathPrefix)
	digest := "sha256:" + hexDigest
	if len(hexDigest) != 64 {
		writePrivateError(writer, http.StatusNotFound)
		return
	}
	if _, err := wire.ParseHash(digest); err != nil {
		writePrivateError(writer, http.StatusNotFound)
		return
	}
	body := capability.Body()
	material, err := service.boundMaterial(request.Context(), capability, body.ClusterID, body.InviteID,
		body.CommittedInviteRecordHash, capability.CapabilityID())
	if err != nil || material.Status != "completed" {
		writePrivateError(writer, http.StatusForbidden)
		return
	}
	envelope, err := service.readArtifact(request.Context(), body.ClusterID, body.InviteID, digest)
	if err != nil {
		writePrivateError(writer, http.StatusForbidden)
		return
	}
	wantDigest, err := wire.SealedSecretEnvelopeHash(&envelope)
	if err != nil || wantDigest != digest {
		writePrivateError(writer, http.StatusInternalServerError)
		return
	}
	encoded, err := wire.MarshalCanonical(envelope)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSealedArtifactBytes {
		writePrivateError(writer, http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func writePrivateError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(`{"error":"private enrollment request rejected"}`))
}

func checkedAddSecondsForPrivate(value string, seconds int64) (string, error) {
	parsed, err := wire.ParseTimeZ(value)
	if err != nil || seconds < 1 || seconds > 86400 {
		return "", errors.New("[D130 Enrollment] retry deadline 输入无效")
	}
	return parsed.Add(time.Duration(seconds) * time.Second).UTC().Format(time.RFC3339), nil
}

func clonePrivateValue[T any](value T) T {
	body, _ := wire.MarshalCanonical(value)
	var clone T
	_, _ = wire.DecodeStrict(body, 64<<20, &clone)
	return clone
}

func cloneInviteMaterial(value InviteMaterialV2) InviteMaterialV2 {
	result := value
	result.RecordHeadQC = append(json.RawMessage(nil), value.RecordHeadQC...)
	result.InviteAuditPath = append([]string(nil), value.InviteAuditPath...)
	if value.PreviousControlSet != nil {
		previous := clonePrivateValue(*value.PreviousControlSet)
		result.PreviousControlSet = &previous
	}
	result.Record = clonePrivateValue(value.Record)
	result.Policy = clonePrivateValue(value.Policy)
	result.Commitment = clonePrivateValue(value.Commitment)
	result.Opening = clonePrivateValue(value.Opening)
	result.EnrollmentServiceRef = clonePrivateValue(value.EnrollmentServiceRef)
	result.ParentHead = clonePrivateValue(value.ParentHead)
	result.RecordHead = clonePrivateValue(value.RecordHead)
	result.ControlSet = clonePrivateValue(value.ControlSet)
	result.InviteOperationLeaf = clonePrivateValue(value.InviteOperationLeaf)
	return result
}
