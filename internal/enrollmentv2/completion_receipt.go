package enrollmentv2

import (
	"bytes"
	"errors"
	"time"

	"loom/internal/wire"
)

// EnrollmentCompletionReceiptV1 是 completed 响应交给 Device 的可重放证明。
// 它只包含已经进入私有 Enrollment 事务或 certified Head 的材料；token、challenge、
// PoP signature 与 CSR DER 不会从服务端 durable state 反射回来（D129、D130）。
type EnrollmentCompletionReceiptV1 struct {
	Schema                           int                                  `json:"schema"`
	Invite                           InviteContext                        `json:"invite"`
	ClaimEvidence                    ClaimPrivateEvidenceV1               `json:"claim_evidence"`
	ClaimOperation                   ClaimOperationV2                     `json:"claim_operation"`
	AdmissionQC                      wire.StableEnrollmentAdmissionQCV1   `json:"admission_qc"`
	AdmissionControlSet              wire.ControlSetV1                    `json:"admission_control_set"`
	ReservationBaseHead              wire.HeadEntryV2                     `json:"reservation_base_head"`
	BaseToReservationHeads           []wire.HeadEntryV2                   `json:"base_to_reservation_heads,omitempty"`
	BaseToReservationTransitions     []wire.ControlSetTransitionBundleV1  `json:"base_to_reservation_transitions,omitempty"`
	ReservationCertification         CertifiedEnrollmentOperationProofV1  `json:"reservation_certification"`
	ProvisionalOperation             ProvisionalIssuanceOperationV1       `json:"provisional_operation"`
	ProvisionalIssuance              wire.EnrollmentProvisionalIssuanceV1 `json:"provisional_issuance"`
	DeviceCertificateProfile         wire.DeviceCertificateProfileStateV1 `json:"device_certificate_profile"`
	ProvisionalCertification         CertifiedEnrollmentOperationProofV1  `json:"provisional_certification"`
	ReservationToIssuanceHeads       []wire.HeadEntryV2                   `json:"reservation_to_issuance_heads,omitempty"`
	ReservationToIssuanceTransitions []wire.ControlSetTransitionBundleV1  `json:"reservation_to_issuance_transitions,omitempty"`
	ApprovalQC                       wire.StableEnrollmentApprovalQCV2    `json:"approval_qc"`
	ApprovalControlSet               wire.ControlSetV1                    `json:"approval_control_set"`
	CompletionOperation              CompletionOperationV2                `json:"completion_operation"`
	CompletionCertification          CompletionCertificationV1            `json:"completion_certification"`
	CompletionProjection             CompletionProjectionV1               `json:"completion_projection"`
}

// EnrollmentCompletionExpectedV1 只由客户端已经验证或本机生成的材料组成。
// 调用者不能用 receipt 自己填充这些值，否则会把“签名合法”误当成“属于本次加入”。
type EnrollmentCompletionExpectedV1 struct {
	Record         wire.CertifiedInviteRecordV2
	Policy         wire.InviteIssuancePolicyV2
	Opening        wire.DeviceEnrollmentIntentOpeningV1
	ClaimCore      wire.EnrollmentClaimCoreV2
	BaseHead       wire.HeadEntryV2
	BaseControlSet wire.ControlSetV1
	TrustedTime    time.Time
}

// VerifiedEnrollmentCompletionV1 是 Linux/Android 安装正式身份前必须取得的不透明证据。
type VerifiedEnrollmentCompletionV1 struct {
	envelope               wire.DeviceViewEnvelopeV2
	controlSet             wire.ControlSetV1
	resumeExpected         wire.EnrollmentResumeExpectedV1
	transactionHash        string
	transactionStateHashes []string
	resultArtifactHash     string
	claimCoreHash          string
	identityKeyHash        string
	wrappingKeyHash        string
	certifiedInviteHash    string
	baseHeadHash           string
	baseControlSetHash     string
}

func (verified VerifiedEnrollmentCompletionV1) DeviceViewEnvelope() wire.DeviceViewEnvelopeV2 {
	return clonePrivateValue(verified.envelope)
}

func (verified VerifiedEnrollmentCompletionV1) ControlSet() wire.ControlSetV1 {
	return clonePrivateValue(verified.controlSet)
}

func (verified VerifiedEnrollmentCompletionV1) TransactionStateHash() string {
	return verified.transactionHash
}

// ResumeExpected 允许 Device 在 completion 已提交、正式状态尚未原子落盘的
// 崩溃窗中接受管理员显式签发的 exact-bound resume。它不复活 Invite/token，
// 只投影刚刚由完整 receipt 重放得到的 completed transaction（D130）。
func (verified VerifiedEnrollmentCompletionV1) ResumeExpected() wire.EnrollmentResumeExpectedV1 {
	return verified.resumeExpected
}

func (verified VerifiedEnrollmentCompletionV1) IncludesTransactionStateHash(hash string) bool {
	for _, candidate := range verified.transactionStateHashes {
		if candidate == hash {
			return true
		}
	}
	return false
}

// VerifyInstallationContext 把 completion verifier 的不透明结论重新绑定到客户端
// 即将落盘的 exact result、stable core 与 Invite proof。安装层不得从 result 或
// receipt 的公开字段自行拼装一个“已验证”状态（D115、D124、D130）。
func (verified VerifiedEnrollmentCompletionV1) VerifyInstallationContext(result *wire.EnrollmentClaimResultV2,
	claimCore *wire.EnrollmentClaimCoreV2, proof wire.VerifiedInviteProofV2) error {
	if result == nil || claimCore == nil || verified.transactionHash == "" ||
		verified.resultArtifactHash == "" || verified.claimCoreHash == "" ||
		verified.identityKeyHash == "" || verified.wrappingKeyHash == "" ||
		verified.certifiedInviteHash == "" || verified.baseHeadHash == "" ||
		verified.baseControlSetHash == "" {
		return errors.New("[D130 client] completion installation evidence 不完整")
	}
	if err := wire.ValidateEnrollmentClaimResult(result); err != nil {
		return err
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(result.ResultArtifact)
	if err != nil || result.Status != "completed" || result.TransactionStateHash != verified.transactionHash ||
		result.ResultArtifactHash != verified.resultArtifactHash || resultHash != verified.resultArtifactHash {
		return errors.New("[D130 client] installation result 未绑定 verified completion")
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(claimCore)
	if err != nil || coreHash != verified.claimCoreHash {
		return errors.New("[D130 client] installation core 未绑定 verified completion")
	}
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(claimCore)
	if err != nil || identityHash != verified.identityKeyHash || wrappingHash != verified.wrappingKeyHash {
		return errors.New("[D130 client] installation keys 未绑定 verified completion")
	}
	proofHead := proof.Head()
	proofSet := proof.ControlSet()
	proofSetHash, err := wire.ControlSetHash(&proofSet)
	if err != nil || proof.CertifiedInviteRecordHash() != verified.certifiedInviteHash ||
		proofHead.HeadHash != verified.baseHeadHash || proofSetHash != verified.baseControlSetHash {
		return errors.New("[D115 client] installation 未延续 exact verified Invite authority")
	}
	if !wire.EqualCanonical(result.ResultArtifact.InitialDeviceView, verified.envelope.Payload) {
		return errors.New("[D130 client] installation Device view 未绑定 result artifact")
	}
	return nil
}

func completionReceiptForRecord(record *DurableRecord) ([]byte, error) {
	if record == nil || record.State.Status != "completed" || record.ProvisionalOperation == nil ||
		record.ProvisionalIssuance == nil || record.DeviceCertificateProfile == nil ||
		record.ProvisionalCertification == nil || record.ApprovalQC == nil ||
		record.ApprovalControlSet == nil || record.CompletionOperation == nil ||
		record.CompletionCertification == nil || record.CompletionProjection == nil {
		return nil, errors.New("[D130 Enrollment] completed receipt 缺 durable proof material")
	}
	receipt := EnrollmentCompletionReceiptV1{
		Schema: 1, Invite: record.Invite, ClaimEvidence: record.ClaimEvidence,
		ClaimOperation: record.ClaimOperation, AdmissionQC: record.AdmissionQC,
		AdmissionControlSet: record.AdmissionControlSet, ReservationBaseHead: record.ReservationBaseHead,
		BaseToReservationHeads:       append([]wire.HeadEntryV2(nil), record.BaseToReservationHeads...),
		BaseToReservationTransitions: cloneControlSetTransitions(record.BaseToReservationTransitions),
		ReservationCertification:     record.ReservationCertification,
		ProvisionalOperation:         *record.ProvisionalOperation, ProvisionalIssuance: *record.ProvisionalIssuance,
		DeviceCertificateProfile:         *record.DeviceCertificateProfile,
		ProvisionalCertification:         *record.ProvisionalCertification,
		ReservationToIssuanceHeads:       append([]wire.HeadEntryV2(nil), record.ReservationToIssuanceHeads...),
		ReservationToIssuanceTransitions: cloneControlSetTransitions(record.ReservationToIssuanceTransitions),
		ApprovalQC:                       *record.ApprovalQC, ApprovalControlSet: *record.ApprovalControlSet,
		CompletionOperation:     *record.CompletionOperation,
		CompletionCertification: *record.CompletionCertification,
		CompletionProjection:    *record.CompletionProjection,
	}
	return wire.MarshalCanonical(receipt)
}

// VerifyEnrollmentCompletionReceipt 从客户端已验 Invite Head 开始，重放
// reservation → issuance → completion 的完整 reducer、Head/QC/inclusion 与 Device view
// proof。只有返回不透明 evidence 后，客户端才可安装证书或清理 bootstrap secret（D130）。
func VerifyEnrollmentCompletionReceipt(raw []byte, result *wire.EnrollmentClaimResultV2,
	expected EnrollmentCompletionExpectedV1) (VerifiedEnrollmentCompletionV1, error) {
	if len(raw) == 0 || result == nil || expected.TrustedTime.IsZero() ||
		result.Status != "completed" || result.ResultArtifact == nil {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D130 client] completion receipt/context 不完整")
	}
	var receipt EnrollmentCompletionReceiptV1
	canonical, err := wire.DecodeStrict(raw, 32<<20, &receipt)
	if err != nil || !bytes.Equal(canonical, raw) || receipt.Schema != 1 {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D130 client] completion receipt 不是 exact canonical wire")
	}
	if err := wire.ValidateCertifiedInviteRecord(&expected.Record, &expected.Policy); err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	if err := wire.ValidateIntentOpening(&expected.Opening); err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(&expected.ClaimCore)
	if err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	identityHash, wrappingHash, csrHash, err := wire.EnrollmentClaimBinaryHashes(&expected.ClaimCore)
	if err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	recordHash, _ := wire.CertifiedInviteRecordHash(&expected.Record, &expected.Policy)
	openingHash, _ := wire.IntentOpeningHash(&expected.Opening)
	intentHash, _ := wire.EnrollmentIntentHash(&expected.Opening.DeviceEnrollmentIntent)
	baseSetHash, setErr := wire.ControlSetHash(&expected.BaseControlSet)
	if setErr != nil || expected.ClaimCore.CertifiedInviteRecordHash != recordHash ||
		expected.ClaimCore.DeviceEnrollmentIntentCommitmentHash != expected.Record.DeviceEnrollmentIntentCommitmentHash ||
		expected.ClaimCore.DeviceEnrollmentIntentOpeningHash != openingHash ||
		expected.ClaimCore.AcceptedDeviceEnrollmentIntentHash != intentHash ||
		expected.ClaimCore.BaseHeadHash != expected.BaseHead.HeadHash ||
		expected.ClaimCore.BaseRecoveryEpoch != expected.BaseHead.Body.Payload.RecoveryEpoch ||
		expected.ClaimCore.BaseControlEpoch != expected.BaseHead.Body.Payload.ControlEpoch ||
		expected.ClaimCore.BaseControlSetHash != baseSetHash ||
		expected.BaseHead.Body.Payload.ControlSetHash != baseSetHash {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D130 client] 本机 claim 未绑定已验 Invite authority")
	}
	wantInvite := InviteContext{
		ClusterID: expected.Record.ClusterID, InviteID: expected.Record.InviteID, Status: "available",
		CertifiedInviteRecordHash:            recordHash,
		DeviceEnrollmentIntentCommitmentHash: expected.Record.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    openingHash, TokenCommitment: expected.Record.TokenCommitment,
		ExpiresAt:                      expected.Record.ExpiresAt,
		MaximumReservationRetrySeconds: expected.Policy.MaximumReservationRetrySeconds,
	}
	wantEvidence := ClaimPrivateEvidenceV1{Schema: 1, Opening: expected.Opening,
		WrappingPublicKey:  expected.ClaimCore.WrappingPublicKey,
		WrappingKeyProfile: expected.ClaimCore.WrappingKeyProfile}
	operation := &receipt.ClaimOperation
	if !wire.EqualCanonical(receipt.Invite, wantInvite) ||
		!wire.EqualCanonical(receipt.ClaimEvidence, wantEvidence) ||
		!wire.EqualCanonical(receipt.AdmissionControlSet, expected.BaseControlSet) ||
		!wire.EqualCanonical(receipt.ReservationBaseHead, expected.BaseHead) ||
		operation.ClusterID != expected.ClaimCore.ClusterID || operation.InviteID != expected.ClaimCore.InviteID ||
		operation.RequestID != expected.ClaimCore.RequestID || operation.CertifiedInviteRecordHash != recordHash ||
		operation.DeviceEnrollmentIntentCommitmentHash != expected.Record.DeviceEnrollmentIntentCommitmentHash ||
		operation.DeviceEnrollmentIntentOpeningHash != openingHash || operation.TokenCommitment != expected.Record.TokenCommitment ||
		operation.ClaimCoreHash != coreHash || operation.IdentityKeyHash != identityHash ||
		operation.WrappingKeyHash != wrappingHash || operation.CSRHash != csrHash {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D130 client] receipt 未绑定本机 stable claim/core/key")
	}
	reserved, err := Reserve(receipt.Invite, receipt.ClaimOperation, &receipt.AdmissionQC,
		&receipt.AdmissionControlSet, receipt.ClaimOperation.ReservedAt)
	if err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	issued, err := RecordProvisional(reserved, receipt.ProvisionalOperation)
	if err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	completed, err := Complete(issued, receipt.CompletionOperation, &receipt.ApprovalQC,
		&receipt.ApprovalControlSet)
	if err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	reservedHash, reservedHashErr := TransactionHash(reserved)
	issuedHash, issuedHashErr := TransactionHash(issued)
	if reservedHashErr != nil || issuedHashErr != nil {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D130 client] receipt 中间 transaction state 不可重放")
	}
	record := DurableRecord{
		InviteID: receipt.Invite.InviteID, TokenCommitment: receipt.Invite.TokenCommitment,
		Invite: receipt.Invite, ClaimEvidence: receipt.ClaimEvidence,
		ClaimOperation: receipt.ClaimOperation, AdmissionQC: receipt.AdmissionQC,
		AdmissionControlSet: receipt.AdmissionControlSet, ReservationBaseHead: receipt.ReservationBaseHead,
		BaseToReservationHeads:       append([]wire.HeadEntryV2(nil), receipt.BaseToReservationHeads...),
		BaseToReservationTransitions: cloneControlSetTransitions(receipt.BaseToReservationTransitions),
		ReservationCertification:     receipt.ReservationCertification,
		ProvisionalOperation:         &receipt.ProvisionalOperation, ProvisionalIssuance: &receipt.ProvisionalIssuance,
		DeviceCertificateProfile: &receipt.DeviceCertificateProfile, ResultArtifact: result.ResultArtifact,
		ProvisionalCertification:         &receipt.ProvisionalCertification,
		ReservationToIssuanceHeads:       append([]wire.HeadEntryV2(nil), receipt.ReservationToIssuanceHeads...),
		ReservationToIssuanceTransitions: cloneControlSetTransitions(receipt.ReservationToIssuanceTransitions),
		ApprovalQC:                       &receipt.ApprovalQC, ApprovalControlSet: &receipt.ApprovalControlSet,
		CompletionOperation:     &receipt.CompletionOperation,
		CompletionCertification: &receipt.CompletionCertification,
		CompletionProjection:    &receipt.CompletionProjection, State: completed,
	}
	if err := validateDurableRecord(&record); err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	wrappingEvidence := EnrollmentApprovalEvidenceV1{
		ClaimEvidence: record.ClaimEvidence, ClaimOperation: record.ClaimOperation,
		ResultArtifact: *record.ResultArtifact,
	}
	if err := verifyApprovalWrappingKey(&wrappingEvidence); err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	completedHash, err := TransactionHash(completed)
	if err != nil || result.TransactionStateHash != completedHash ||
		receipt.CompletionProjection.CompletedTransactionStateHash != completedHash {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D130 client] completed transaction state hash 不可重放")
	}
	claimOperationHash, claimHashErr := wire.HashObject(DomainClaimOperation, receipt.ClaimOperation)
	admissionQCHash, admissionHashErr := wire.EnrollmentAdmissionQCHash(&receipt.AdmissionQC)
	if claimHashErr != nil || admissionHashErr != nil ||
		claimOperationHash != completed.ClaimOperationHash ||
		admissionQCHash != receipt.ClaimOperation.AdmissionQCHash {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D130 client] completed resume binding 不可重放")
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(result.ResultArtifact)
	if err != nil || result.ResultArtifactHash != resultHash ||
		receipt.CompletionProjection.ResultArtifactHash != resultHash {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D130 client] completed result artifact 未绑定 receipt")
	}
	issuanceTime, err := wire.ParseTimeZ(receipt.ProvisionalCertification.Head.Body.Payload.CommittedLogicalTime)
	if err != nil || expected.TrustedTime.UTC().Before(issuanceTime) {
		return VerifiedEnrollmentCompletionV1{}, errors.New("[D102 client] trusted time 早于 certificate issuance Head")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(result.ResultArtifact)
	if err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	intent := expected.Opening.DeviceEnrollmentIntent
	if err := wire.ValidateDeviceCertificateProfileRef(&intent.DeviceCertificateProfileRef,
		&receipt.DeviceCertificateProfile); err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	if _, err := wire.VerifyDeviceCertificateAt(certificateDER, &receipt.DeviceCertificateProfile,
		intent.DeviceID, identityHash, intent.Platform, intent.Responsibilities.Values,
		receipt.ProvisionalIssuance.Body.IssuanceLogCoordinate, issuanceTime,
		expected.TrustedTime.UTC()); err != nil {
		return VerifiedEnrollmentCompletionV1{}, err
	}
	envelope := receipt.CompletionCertification.DeviceViewEnvelope
	return VerifiedEnrollmentCompletionV1{envelope: clonePrivateValue(envelope),
		controlSet: clonePrivateValue(receipt.CompletionCertification.Operation.ControlSet),
		resumeExpected: wire.EnrollmentResumeExpectedV1{
			ClusterID: expected.ClaimCore.ClusterID, InviteID: expected.ClaimCore.InviteID,
			RequestID: expected.ClaimCore.RequestID, ClaimCoreHash: coreHash,
			ClaimOperationHash: claimOperationHash, AdmissionQCHash: admissionQCHash,
			CSRHash: csrHash, IdentityKeyHash: identityHash, WrappingKeyHash: wrappingHash,
			EnrollmentTransactionStateHash: completedHash,
			RetryNotAfter:                  receipt.ClaimOperation.RetryNotAfter,
		},
		transactionHash:        completedHash,
		transactionStateHashes: []string{reservedHash, issuedHash, completedHash},
		resultArtifactHash:     resultHash,
		claimCoreHash:          coreHash,
		identityKeyHash:        identityHash,
		wrappingKeyHash:        wrappingHash,
		certifiedInviteHash:    recordHash,
		baseHeadHash:           expected.BaseHead.HeadHash,
		baseControlSetHash:     baseSetHash}, nil
}
