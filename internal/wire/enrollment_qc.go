package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
)

const (
	DomainEnrollmentAdmissionAttestation = "loom-enrollment-admission-attestation-v1"
	DomainEnrollmentAdmissionSignature   = "loom-enrollment-admission-signature-v1"
	DomainEnrollmentAdmissionQC          = "loom-enrollment-admission-qc-v1"
	DomainEnrollmentApprovalAttestation  = "loom-enrollment-approval-attestation-v2"
	DomainEnrollmentApprovalSignature    = "loom-enrollment-approval-signature-v2"
	DomainEnrollmentApprovalQC           = "loom-enrollment-approval-qc-v2"
)

type EnrollmentAdmissionAttestationBodyV1 struct {
	WireGuardPublicKey                   string `json:"wireguard_public_key,omitempty"`
	Schema                               int    `json:"schema"`
	AttestationType                      string `json:"attestation_type"`
	ClusterID                            string `json:"cluster_id"`
	InviteID                             string `json:"invite_id"`
	RequestID                            string `json:"request_id"`
	CertifiedInviteRecordHash            string `json:"certified_invite_record_hash"`
	DeviceEnrollmentIntentCommitmentHash string `json:"device_enrollment_intent_commitment_hash"`
	DeviceEnrollmentIntentOpeningHash    string `json:"device_enrollment_intent_opening_hash"`
	TokenCommitment                      string `json:"token_commitment"`
	ClaimCoreHash                        string `json:"claim_core_hash"`
	IdentityKeyHash                      string `json:"identity_key_hash"`
	WrappingKeyHash                      string `json:"wrapping_key_hash"`
	CSRHash                              string `json:"csr_hash"`
	PoPVerificationProfile               string `json:"pop_verification_profile"`
	BaseRecoveryEpoch                    int64  `json:"base_recovery_epoch"`
	BaseControlEpoch                     int64  `json:"base_control_epoch"`
	BaseControlSetHash                   string `json:"base_control_set_hash"`
	BaseHeadHash                         string `json:"base_head_hash"`
	AdmissionNotAfter                    string `json:"admission_not_after"`
	RetryNotAfter                        string `json:"retry_not_after"`
}

type ControlEnrollmentSignatureV1 struct {
	Algorithm       string `json:"algorithm"`
	MemberID        string `json:"member_id"`
	EnrollmentKeyID string `json:"enrollment_key_id"`
	Signature       string `json:"signature"`
}

type ControlEnrollmentSignerRefV1 struct {
	MemberID        string `json:"member_id"`
	EnrollmentKeyID string `json:"enrollment_key_id"`
}

type StableEnrollmentAdmissionQCV1 struct {
	Schema      int                                  `json:"schema"`
	QCType      string                               `json:"qc_type"`
	Attestation EnrollmentAdmissionAttestationBodyV1 `json:"attestation"`
	Signatures  []ControlEnrollmentSignatureV1       `json:"signatures"`
	SignerRefs  []ControlEnrollmentSignerRefV1       `json:"signer_refs"`
}

type EnrollmentApprovalAttestationBodyV2 struct {
	Schema                           int    `json:"schema"`
	AttestationType                  string `json:"attestation_type"`
	ClusterID                        string `json:"cluster_id"`
	InviteID                         string `json:"invite_id"`
	RequestID                        string `json:"request_id"`
	ClaimOperationHash               string `json:"claim_operation_hash"`
	ProvisionalIssuanceOperationHash string `json:"provisional_issuance_operation_hash"`
	ProvisionalIssuanceHash          string `json:"provisional_issuance_hash"`
	IssuanceHeadHash                 string `json:"issuance_head_hash"`
	IssuanceHeadQCHash               string `json:"issuance_head_qc_hash"`
	ResultingIssuanceRegistryRoot    string `json:"resulting_issuance_registry_root"`
	DeviceCertificateHash            string `json:"device_certificate_hash"`
	InitialDeviceViewHash            string `json:"initial_device_view_hash"`
	SecretArtifactRefsRoot           string `json:"secret_artifact_refs_root"`
	ResultArtifactHash               string `json:"result_artifact_hash"`
}

type StableEnrollmentApprovalQCV2 struct {
	Schema      int                                 `json:"schema"`
	QCType      string                              `json:"qc_type"`
	Attestation EnrollmentApprovalAttestationBodyV2 `json:"attestation"`
	Signatures  []ControlEnrollmentSignatureV1      `json:"enrollment_signatures"`
	SignerRefs  []ControlEnrollmentSignerRefV1      `json:"signer_refs"`
}

func SignEnrollmentAdmission(body EnrollmentAdmissionAttestationBodyV1, member ControlMemberV1, privateKey ed25519.PrivateKey) (ControlEnrollmentSignatureV1, error) {
	if err := ValidateEnrollmentAdmission(&body); err != nil {
		return ControlEnrollmentSignatureV1{}, err
	}
	return signEnrollmentPurpose(DomainEnrollmentAdmissionSignature, body, member, privateKey)
}

func VerifyEnrollmentAdmissionQC(qc *StableEnrollmentAdmissionQCV1, set *ControlSetV1) error {
	if qc == nil || set == nil || qc.Schema != 1 || qc.QCType != "stable_enrollment_admission" {
		return errors.New("[Enrollment] admission QC type/schema 无效")
	}
	if err := ValidateEnrollmentAdmission(&qc.Attestation); err != nil {
		return err
	}
	if qc.Attestation.ClusterID != set.ClusterID {
		return errors.New("[Enrollment] admission QC cluster 不匹配")
	}
	return verifyEnrollmentSignatures(DomainEnrollmentAdmissionSignature, qc.Attestation, qc.Signatures, qc.SignerRefs, set)
}

func VerifyEnrollmentAdmissionSignature(body *EnrollmentAdmissionAttestationBodyV1,
	signature *ControlEnrollmentSignatureV1, set *ControlSetV1) error {
	if err := ValidateEnrollmentAdmission(body); err != nil {
		return err
	}
	return verifyOneEnrollmentSignature(DomainEnrollmentAdmissionSignature, *body, signature, set)
}

func EnrollmentAdmissionQCHash(qc *StableEnrollmentAdmissionQCV1) (string, error) {
	return HashObject(DomainEnrollmentAdmissionQC, qc)
}

func ValidateEnrollmentAdmission(body *EnrollmentAdmissionAttestationBodyV1) error {
	if body != nil && body.WireGuardPublicKey != "" {
		if err := validateEnrollmentWireGuardPublic(body.WireGuardPublicKey); err != nil {
			return err
		}
	}
	if body == nil || body.Schema != 1 || body.AttestationType != "enrollment_admission" ||
		!validIdentifier(body.ClusterID, 128) || !validIdentifier(body.InviteID, 128) || !validIdentifier(body.RequestID, 128) ||
		body.PoPVerificationProfile != "loom-enrollment-server-nonce-detached-v2" || body.BaseRecoveryEpoch < 0 || body.BaseControlEpoch < 0 {
		return errors.New("[Enrollment] admission attestation header/profile 无效")
	}
	for _, hash := range []string{body.CertifiedInviteRecordHash, body.DeviceEnrollmentIntentCommitmentHash,
		body.DeviceEnrollmentIntentOpeningHash, body.TokenCommitment, body.ClaimCoreHash, body.IdentityKeyHash,
		body.WrappingKeyHash, body.CSRHash, body.BaseControlSetHash, body.BaseHeadHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	admission, err := ParseTimeZ(body.AdmissionNotAfter)
	if err != nil {
		return err
	}
	retry, err := ParseTimeZ(body.RetryNotAfter)
	if err != nil || retry.Before(admission) {
		return errors.New("[Enrollment] retry_not_after 早于 admission_not_after")
	}
	return nil
}

func SignEnrollmentApproval(body EnrollmentApprovalAttestationBodyV2, member ControlMemberV1, privateKey ed25519.PrivateKey) (ControlEnrollmentSignatureV1, error) {
	if err := ValidateEnrollmentApproval(&body); err != nil {
		return ControlEnrollmentSignatureV1{}, err
	}
	return signEnrollmentPurpose(DomainEnrollmentApprovalSignature, body, member, privateKey)
}

func VerifyEnrollmentApprovalQC(qc *StableEnrollmentApprovalQCV2, set *ControlSetV1) error {
	if qc == nil || set == nil || qc.Schema != 2 || qc.QCType != "stable_enrollment_approval" {
		return errors.New("[Enrollment] approval QC type/schema 无效")
	}
	if err := ValidateEnrollmentApproval(&qc.Attestation); err != nil {
		return err
	}
	if qc.Attestation.ClusterID != set.ClusterID {
		return errors.New("[Enrollment] approval QC cluster 不匹配")
	}
	return verifyEnrollmentSignatures(DomainEnrollmentApprovalSignature, qc.Attestation, qc.Signatures, qc.SignerRefs, set)
}

func VerifyEnrollmentApprovalSignature(body *EnrollmentApprovalAttestationBodyV2,
	signature *ControlEnrollmentSignatureV1, set *ControlSetV1) error {
	if err := ValidateEnrollmentApproval(body); err != nil {
		return err
	}
	return verifyOneEnrollmentSignature(DomainEnrollmentApprovalSignature, *body, signature, set)
}

func EnrollmentApprovalQCHash(qc *StableEnrollmentApprovalQCV2) (string, error) {
	return HashObject(DomainEnrollmentApprovalQC, qc)
}

func ValidateEnrollmentApproval(body *EnrollmentApprovalAttestationBodyV2) error {
	if body == nil || body.Schema != 2 || body.AttestationType != "enrollment_approval" || !validIdentifier(body.ClusterID, 128) || !validIdentifier(body.InviteID, 128) || !validIdentifier(body.RequestID, 128) {
		return errors.New("[Enrollment] approval attestation header 无效")
	}
	for _, hash := range []string{body.ClaimOperationHash, body.ProvisionalIssuanceOperationHash,
		body.ProvisionalIssuanceHash, body.IssuanceHeadHash, body.IssuanceHeadQCHash,
		body.ResultingIssuanceRegistryRoot, body.DeviceCertificateHash, body.InitialDeviceViewHash,
		body.SecretArtifactRefsRoot, body.ResultArtifactHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	return nil
}

func signEnrollmentPurpose(domain string, body any, member ControlMemberV1, privateKey ed25519.PrivateKey) (ControlEnrollmentSignatureV1, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ControlEnrollmentSignatureV1{}, errors.New("[keys] enrollment private key 长度无效")
	}
	keyID, err := ControlKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil || keyID != member.EnrollmentKeyID {
		return ControlEnrollmentSignatureV1{}, errors.New("[keys] enrollment key 与 member 不匹配")
	}
	canonical, err := MarshalCanonical(body)
	if err != nil {
		return ControlEnrollmentSignatureV1{}, err
	}
	message, _ := Frame(domain, canonical)
	return ControlEnrollmentSignatureV1{Algorithm: "ed25519", MemberID: member.MemberID, EnrollmentKeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}

func verifyEnrollmentSignatures(domain string, body any, signatures []ControlEnrollmentSignatureV1, refs []ControlEnrollmentSignerRefV1, set *ControlSetV1) error {
	if err := ValidateControlSet(set); err != nil {
		return err
	}
	quorum, _ := Quorum(len(set.Members))
	if len(signatures) < quorum || len(signatures) > len(set.Members) || len(refs) != len(signatures) {
		return errors.New("[Enrollment] enrollment signatures 未达到 committed ControlSet quorum")
	}
	if !sort.SliceIsSorted(signatures, func(i, j int) bool {
		if signatures[i].MemberID != signatures[j].MemberID {
			return signatures[i].MemberID < signatures[j].MemberID
		}
		return signatures[i].EnrollmentKeyID < signatures[j].EnrollmentKeyID
	}) {
		return errors.New("[Enrollment] enrollment signatures 未规范排序")
	}
	seen := make(map[string]struct{}, len(signatures))
	for index, signature := range signatures {
		ref := refs[index]
		if ref.MemberID != signature.MemberID || ref.EnrollmentKeyID != signature.EnrollmentKeyID ||
			index > 0 && (refs[index-1].MemberID > ref.MemberID ||
				refs[index-1].MemberID == ref.MemberID && refs[index-1].EnrollmentKeyID >= ref.EnrollmentKeyID) {
			return errors.New("[Enrollment] signer refs 必须与 signatures 同序同字段")
		}
		if _, duplicate := seen[signature.MemberID]; duplicate {
			return errors.New("[Enrollment] enrollment signer 重复")
		}
		seen[signature.MemberID] = struct{}{}
		if err := verifyOneEnrollmentSignature(domain, body, &signature, set); err != nil {
			return err
		}
	}
	return nil
}

func verifyOneEnrollmentSignature(domain string, body any, signature *ControlEnrollmentSignatureV1,
	set *ControlSetV1) error {
	if signature == nil {
		return errors.New("[Enrollment] enrollment signature 不能为空")
	}
	if err := ValidateControlSet(set); err != nil {
		return err
	}
	var member *ControlMemberV1
	for index := range set.Members {
		if set.Members[index].MemberID == signature.MemberID {
			member = &set.Members[index]
			break
		}
	}
	if member == nil || signature.Algorithm != "ed25519" || signature.EnrollmentKeyID != member.EnrollmentKeyID {
		return errors.New("[Enrollment] enrollment signer/key purpose 无效")
	}
	canonical, err := MarshalCanonical(body)
	if err != nil {
		return err
	}
	message, _ := Frame(domain, canonical)
	public, err := decodeRawURL(member.EnrollmentPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return errors.New("[keys] enrollment public key 无效")
	}
	rawSignature, err := decodeRawURL(signature.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(public), message, rawSignature) {
		return errors.New("[Enrollment] enrollment signature 无效")
	}
	return nil
}

func EnrollmentSignerRefs(signatures []ControlEnrollmentSignatureV1) []ControlEnrollmentSignerRefV1 {
	refs := make([]ControlEnrollmentSignerRefV1, len(signatures))
	for i, signature := range signatures {
		refs[i] = ControlEnrollmentSignerRefV1{MemberID: signature.MemberID, EnrollmentKeyID: signature.EnrollmentKeyID}
	}
	return refs
}

func StableEnrollmentAdmissionQC(body EnrollmentAdmissionAttestationBodyV1, signatures []ControlEnrollmentSignatureV1) StableEnrollmentAdmissionQCV1 {
	ordered := append([]ControlEnrollmentSignatureV1(nil), signatures...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].MemberID != ordered[j].MemberID {
			return ordered[i].MemberID < ordered[j].MemberID
		}
		return ordered[i].EnrollmentKeyID < ordered[j].EnrollmentKeyID
	})
	return StableEnrollmentAdmissionQCV1{Schema: 1, QCType: "stable_enrollment_admission", Attestation: body, Signatures: ordered, SignerRefs: EnrollmentSignerRefs(ordered)}
}

func StableEnrollmentApprovalQC(body EnrollmentApprovalAttestationBodyV2, signatures []ControlEnrollmentSignatureV1) StableEnrollmentApprovalQCV2 {
	ordered := append([]ControlEnrollmentSignatureV1(nil), signatures...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].MemberID != ordered[j].MemberID {
			return ordered[i].MemberID < ordered[j].MemberID
		}
		return ordered[i].EnrollmentKeyID < ordered[j].EnrollmentKeyID
	})
	return StableEnrollmentApprovalQCV2{Schema: 2, QCType: "stable_enrollment_approval", Attestation: body, Signatures: ordered, SignerRefs: EnrollmentSignerRefs(ordered)}
}
