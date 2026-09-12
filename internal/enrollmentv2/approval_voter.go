package enrollmentv2

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"loom/internal/wire"
)

type EnrollmentApprovalVoteRequestV1 struct {
	Schema      int                                      `json:"schema"`
	Attestation wire.EnrollmentApprovalAttestationBodyV2 `json:"attestation"`
}

type EnrollmentApprovalVoteResponseV1 struct {
	Schema    int                               `json:"schema"`
	Signature wire.ControlEnrollmentSignatureV1 `json:"signature"`
}

type ApprovalVotePeer interface {
	VoteApproval(context.Context, EnrollmentApprovalVoteRequestV1) (wire.ControlEnrollmentSignatureV1, error)
}

// CertifiedEnrollmentOperationProofV1 证明一个 exact enrollment operation 已经进入
// 某个 quorum-certified Head 的累计 operation tree（D104、D130）。
type CertifiedEnrollmentOperationProofV1 struct {
	Head               wire.HeadEntryV2            `json:"head"`
	ConfigQC           json.RawMessage             `json:"config_qc"`
	ControlSet         wire.ControlSetV1           `json:"control_set"`
	PreviousControlSet *wire.ControlSetV1          `json:"previous_control_set,omitempty"`
	OperationLeaf      wire.ControlOperationLeafV1 `json:"operation_leaf"`
	OperationLeafIndex int64                       `json:"operation_leaf_index"`
	OperationTreeSize  int64                       `json:"operation_tree_size"`
	OperationAuditPath []string                    `json:"operation_audit_path"`
}

type CARegistryPreimageV1 struct {
	AdminProfiles  []wire.AdminCertificateProfileV1       `json:"admin_profiles"`
	DeviceProfiles []wire.DeviceCertificateProfileStateV1 `json:"device_profiles"`
}

// EnrollmentApprovalEvidenceV1 是每个 voter 必须从本机 replicated private state
// 读取的完整 preimage。peer RPC 不携这些 Device 私有制品（D124、D130）。
type EnrollmentApprovalEvidenceV1 struct {
	Schema                         int                                     `json:"schema"`
	Invite                         InviteContext                           `json:"invite"`
	ClaimEvidence                  ClaimPrivateEvidenceV1                  `json:"claim_evidence"`
	ClaimOperation                 ClaimOperationV2                        `json:"claim_operation"`
	AdmissionQC                    wire.StableEnrollmentAdmissionQCV1      `json:"admission_qc"`
	AdmissionControlSet            wire.ControlSetV1                       `json:"admission_control_set"`
	ReservationBaseHead            wire.HeadEntryV2                        `json:"reservation_base_head"`
	BaseToReservationHeads         []wire.HeadEntryV2                      `json:"base_to_reservation_heads,omitempty"`
	BaseToReservationTransitions   []wire.ControlSetTransitionBundleV1     `json:"base_to_reservation_transitions,omitempty"`
	Reservation                    CertifiedEnrollmentOperationProofV1     `json:"reservation"`
	ReservationCARegistry          CARegistryPreimageV1                    `json:"reservation_ca_registry"`
	ProvisionalOperation           ProvisionalIssuanceOperationV1          `json:"provisional_operation"`
	ProvisionalIssuance            wire.EnrollmentProvisionalIssuanceV1    `json:"provisional_issuance"`
	DeviceCertificateProfile       wire.DeviceCertificateProfileStateV1    `json:"device_certificate_profile"`
	PreviousIssuanceRegistryLeaves []wire.EnrollmentIssuanceRegistryLeafV1 `json:"previous_issuance_registry_leaves"`
	IntermediateHeads              []wire.HeadEntryV2                      `json:"intermediate_heads"`
	ControlSetTransitions          []wire.ControlSetTransitionBundleV1     `json:"control_set_transitions,omitempty"`
	Issuance                       CertifiedEnrollmentOperationProofV1     `json:"issuance"`
	IssuanceCARegistry             CARegistryPreimageV1                    `json:"issuance_ca_registry"`
	ResultArtifact                 wire.EnrollmentResultArtifactV1         `json:"result_artifact"`
}

// ApprovalEvidenceReader 必须做线性化本地读取并只返回本机已经复制、重算过的
// issuance transaction/artifacts；leader 传来的 attestation 不能替代该读取（D130）。
type ApprovalEvidenceReader func(context.Context, string, string, string) (EnrollmentApprovalEvidenceV1, error)

type ApprovalVoter struct {
	set        wire.ControlSetV1
	member     wire.ControlMemberV1
	privateKey ed25519.PrivateKey
	now        func() time.Time
	read       ApprovalEvidenceReader
}

func NewApprovalVoter(memberID string, set wire.ControlSetV1, privateKey ed25519.PrivateKey,
	now func() time.Time, read ApprovalEvidenceReader) (*ApprovalVoter, error) {
	if memberID == "" || now == nil || read == nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("[D130 Enrollment peer] approval voter identity/key/time/reader 配置不完整")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	var member *wire.ControlMemberV1
	for index := range set.Members {
		if set.Members[index].MemberID == memberID {
			member = &set.Members[index]
			break
		}
	}
	keyID, err := wire.ControlKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil || member == nil || keyID != member.EnrollmentKeyID {
		return nil, errors.New("[D102 keys] approval voter enrollment key 不属于 committed ControlSet member")
	}
	return &ApprovalVoter{set: set, member: *member,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...), now: now, read: read}, nil
}

func (voter *ApprovalVoter) VoteApproval(ctx context.Context,
	request EnrollmentApprovalVoteRequestV1) (wire.ControlEnrollmentSignatureV1, error) {
	if voter == nil || request.Schema != 1 || wire.ValidateEnrollmentApproval(&request.Attestation) != nil {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[D130 Enrollment peer] approval vote request header 无效")
	}
	if err := ctx.Err(); err != nil {
		return wire.ControlEnrollmentSignatureV1{}, err
	}
	attestation := request.Attestation
	evidence, err := voter.read(ctx, attestation.ClusterID, attestation.InviteID, attestation.RequestID)
	if err != nil {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[D130 Enrollment peer] 本地 approval evidence 不可用")
	}
	set, err := VerifyPeerApprovalEvidence(&evidence, &attestation, voter.now().UTC())
	if err != nil {
		return wire.ControlEnrollmentSignatureV1{}, err
	}
	wantSetHash, _ := wire.ControlSetHash(&voter.set)
	gotSetHash, _ := wire.ControlSetHash(&set)
	if wantSetHash != gotSetHash {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[D130 Enrollment peer] issuance ControlSet 与 approval voter 配置不匹配")
	}
	return wire.SignEnrollmentApproval(attestation, voter.member, voter.privateKey)
}

// VerifyPeerApprovalEvidence 逐项重算 reservation/issuance Head、CA registry、
// certificate、initial view、secret refs 与 result artifact；任何裸 hash 都不能单独授权签名。
func VerifyPeerApprovalEvidence(evidence *EnrollmentApprovalEvidenceV1,
	attestation *wire.EnrollmentApprovalAttestationBodyV2, trustedTime time.Time) (wire.ControlSetV1, error) {
	if attestation == nil {
		return wire.ControlSetV1{}, errors.New("[D130 Enrollment peer] approval evidence/context 无效")
	}
	want, set, err := approvalAttestationForEvidence(evidence, trustedTime)
	if err != nil {
		return wire.ControlSetV1{}, err
	}
	if !wire.EqualCanonical(want, *attestation) {
		return wire.ControlSetV1{}, errors.New("[D130 Enrollment peer] approval attestation 未绑定 exact locally verified evidence")
	}
	return set, nil
}

// ApprovalAttestationForEvidence 供本机 coordinator 在收集远端票之前，从同一
// 完整证据确定性构造 attestation；它与 voter 走完全相同的 verifier。
func ApprovalAttestationForEvidence(evidence *EnrollmentApprovalEvidenceV1,
	trustedTime time.Time) (wire.EnrollmentApprovalAttestationBodyV2, wire.ControlSetV1, error) {
	return approvalAttestationForEvidence(evidence, trustedTime)
}

func approvalAttestationForEvidence(evidence *EnrollmentApprovalEvidenceV1,
	trustedTime time.Time) (wire.EnrollmentApprovalAttestationBodyV2, wire.ControlSetV1, error) {
	if evidence == nil || evidence.Schema != 1 || trustedTime.IsZero() {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, errors.New("[D130 Enrollment peer] approval evidence/context 无效")
	}
	claimHash, err := wire.HashObject(DomainClaimOperation, evidence.ClaimOperation)
	if err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	reservationQCHash, err := verifyCertifiedEnrollmentOperation(&evidence.Reservation,
		evidence.ClaimOperation.OperationID, claimHash)
	if err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	if err := validateReservationHeadLineage(&evidence.ReservationBaseHead,
		evidence.BaseToReservationHeads, evidence.BaseToReservationTransitions, &evidence.Reservation,
		&evidence.AdmissionQC, &evidence.AdmissionControlSet); err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	reserved, err := Reserve(evidence.Invite, evidence.ClaimOperation, &evidence.AdmissionQC,
		&evidence.AdmissionControlSet, evidence.Reservation.Head.Body.Payload.CommittedLogicalTime)
	if err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	if err := validateClaimPrivateEvidence(&evidence.ClaimEvidence, &evidence.ClaimOperation); err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	if err := verifyApprovalWrappingKey(evidence); err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	profile := &evidence.DeviceCertificateProfile
	intent := &evidence.ClaimEvidence.Opening.DeviceEnrollmentIntent
	if profile.Status != "active" || wire.ValidateDeviceCertificateProfileRef(&intent.DeviceCertificateProfileRef, profile) != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, errors.New("[D102 Device CA] approval intent 未绑定 exact active profile")
	}
	if err := verifyCARegistryAtHead(profile, &evidence.ReservationCARegistry, &evidence.Reservation.Head); err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	if err := VerifyEnrollmentHeadLineage(&evidence.Reservation.Head, evidence.IntermediateHeads,
		evidence.ControlSetTransitions, &evidence.Issuance.Head, &evidence.Issuance.ControlSet); err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	if evidence.Issuance.PreviousControlSet != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, errors.New("[D130 Enrollment peer] approval 只允许 stable issuance ControlSet")
	}
	provisionalHash, err := wire.HashObject(DomainProvisionalOperation, evidence.ProvisionalOperation)
	if err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	issuanceQCHash, err := verifyCertifiedEnrollmentOperation(&evidence.Issuance,
		evidence.ProvisionalOperation.OperationID, provisionalHash)
	if err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	issued, err := RecordProvisional(reserved, evidence.ProvisionalOperation)
	if err != nil || issued.Status != "issued_provisional" {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, errors.New("[D130 Enrollment peer] provisional operation 不能重放为 exact issued state")
	}
	if err := verifyProvisionalApprovalEvidence(evidence, reservationQCHash,
		trustedTime); err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	issuanceHash, _ := wire.EnrollmentProvisionalIssuanceHash(&evidence.ProvisionalIssuance)
	resultHash, _ := wire.EnrollmentResultArtifactHash(&evidence.ResultArtifact)
	body := evidence.ProvisionalIssuance.Body
	want := wire.EnrollmentApprovalAttestationBodyV2{
		Schema: 2, AttestationType: "enrollment_approval", ClusterID: body.ClusterID,
		InviteID: body.InviteID, RequestID: body.RequestID, ClaimOperationHash: claimHash,
		ProvisionalIssuanceOperationHash: provisionalHash, ProvisionalIssuanceHash: issuanceHash,
		IssuanceHeadHash: evidence.Issuance.Head.HeadHash, IssuanceHeadQCHash: issuanceQCHash,
		ResultingIssuanceRegistryRoot: evidence.ProvisionalOperation.ResultingIssuanceRegistryRoot,
		DeviceCertificateHash:         body.DeviceCertificateHash, InitialDeviceViewHash: body.InitialDeviceViewHash,
		SecretArtifactRefsRoot: body.SecretArtifactRefsRoot, ResultArtifactHash: resultHash,
	}
	if err := wire.ValidateEnrollmentApproval(&want); err != nil {
		return wire.EnrollmentApprovalAttestationBodyV2{}, wire.ControlSetV1{}, err
	}
	return want, evidence.Issuance.ControlSet, nil
}

func verifyCertifiedEnrollmentOperation(proof *CertifiedEnrollmentOperationProofV1,
	operationID, objectID string) (string, error) {
	if proof == nil || proof.Head.Body.Payload.HeadKind == "bootstrap" || operationID == "" {
		return "", errors.New("[D130 Enrollment peer] certified operation proof header 无效")
	}
	if err := wire.VerifyConfigQCAuthority(proof.Head.HeadHash, proof.ConfigQC, &proof.Head,
		&proof.ControlSet, proof.PreviousControlSet); err != nil {
		return "", err
	}
	if proof.OperationLeaf.OperationID != operationID || proof.OperationLeaf.ObjectID != objectID ||
		wire.VerifyControlOperationInclusion(&proof.OperationLeaf, proof.OperationLeafIndex,
			proof.OperationTreeSize, proof.OperationAuditPath, &proof.Head) != nil {
		return "", errors.New("[D130 Enrollment peer] operation 缺 exact certified inclusion proof")
	}
	return wire.ConfigQCHash(proof.ConfigQC)
}

func verifyApprovalWrappingKey(evidence *EnrollmentApprovalEvidenceV1) error {
	if err := validateClaimPrivateEvidence(&evidence.ClaimEvidence, &evidence.ClaimOperation); err != nil {
		return err
	}
	encoded := evidence.ClaimEvidence.WrappingPublicKey
	for index := range evidence.ResultArtifact.SecretArtifactRefs {
		ref := &evidence.ResultArtifact.SecretArtifactRefs[index]
		if ref.SealedBlob == nil {
			return errors.New("[D124 secret artifact] Device result secret 未使用 sealed blob")
		}
		found := false
		for _, recipient := range ref.SealedBlob.RecipientKeyVersions {
			if recipient.RecipientID == evidence.ClaimEvidence.Opening.DeviceEnrollmentIntent.DeviceID &&
				recipient.RecipientPublicKey.PublicKeySPKIDER == encoded {
				found = true
			}
		}
		if !found {
			return errors.New("[D124 secret artifact] result secret 未封装给 admitted wrapping key")
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// VerifyEnrollmentHeadLineage 验证两个 Enrollment stage 之间的完整 Head 链。
// ordinary Head 只延续既有 authority；每个 control_set_final 必须携完整 Joint→Final
// bundle，不能只凭新集合对后续 Head 的自签 QC 改写 control authority（D112、D130）。
func VerifyEnrollmentHeadLineage(from *wire.HeadEntryV2, intermediate []wire.HeadEntryV2,
	transitions []wire.ControlSetTransitionBundleV1, to *wire.HeadEntryV2,
	targetSet *wire.ControlSetV1) error {
	if from == nil || to == nil || targetSet == nil || len(intermediate) > 4096 ||
		len(transitions) > 256 || to.Body.Payload.RaftIndex <= from.Body.Payload.RaftIndex {
		return errors.New("[D130 Enrollment peer] Enrollment Head lineage 无效")
	}
	currentSetHash := from.Body.Payload.ControlSetHash
	transitionIndex := 0
	parent := *from
	for index := 0; index <= len(intermediate); index++ {
		next := to
		if index < len(intermediate) {
			next = &intermediate[index]
		}
		if err := wire.ValidateHeadEntry(next, &parent); err != nil {
			return errors.New("[D130 Enrollment peer] Enrollment Head lineage 不连续")
		}
		switch next.Body.Payload.HeadKind {
		case "ordinary":
			if next.Body.Payload.ControlSetHash != currentSetHash {
				return errors.New("[D130 Enrollment peer] ordinary Head 改写 ControlSet")
			}
		case "control_set_final":
			if transitionIndex >= len(transitions) {
				return errors.New("[D112 Enrollment peer] ControlSet Final 缺 transition bundle")
			}
			bundle := &transitions[transitionIndex]
			if !wire.EqualCanonical(bundle.Final.Head, *next) {
				return errors.New("[D112 Enrollment peer] transition bundle 未绑定 lineage Final Head")
			}
			if _, err := wire.VerifyControlSetTransitionBundle(bundle, &parent); err != nil {
				return err
			}
			oldHash, oldErr := wire.ControlSetHash(&bundle.OldControlSet)
			newHash, newErr := wire.ControlSetHash(&bundle.NewControlSet)
			if oldErr != nil || newErr != nil || oldHash != currentSetHash ||
				newHash != next.Body.Payload.ControlSetHash {
				return errors.New("[D112 Enrollment peer] transition bundle authority 链不连续")
			}
			currentSetHash = newHash
			transitionIndex++
		default:
			return errors.New("[D130 Enrollment peer] Enrollment stage 不接受未证明的 recovery authority transition")
		}
		parent = *next
	}
	targetHash, err := wire.ControlSetHash(targetSet)
	if err != nil || targetHash != currentSetHash || targetHash != to.Body.Payload.ControlSetHash ||
		transitionIndex != len(transitions) {
		return errors.New("[D112 Enrollment peer] Enrollment Head lineage target ControlSet 无效")
	}
	return nil
}

func verifyCARegistryAtHead(profile *wire.DeviceCertificateProfileStateV1,
	registry *CARegistryPreimageV1, head *wire.HeadEntryV2) error {
	if profile == nil || registry == nil || head == nil {
		return errors.New("[D102 Device CA] CA registry evidence 不完整")
	}
	root, err := wire.CAProfileRoot(registry.AdminProfiles, registry.DeviceProfiles)
	if err != nil || root != head.Body.Payload.CAProfileRoot {
		return errors.New("[D102 Device CA] CA registry preimage 与 certified Head root 不匹配")
	}
	profileHash, err := wire.DeviceCertificateProfileStateHash(profile)
	if err != nil {
		return err
	}
	found := 0
	for index := range registry.DeviceProfiles {
		candidateHash, hashErr := wire.DeviceCertificateProfileStateHash(&registry.DeviceProfiles[index])
		if hashErr == nil && candidateHash == profileHash && wire.EqualCanonical(registry.DeviceProfiles[index], *profile) {
			found++
		}
	}
	if found != 1 {
		return errors.New("[D102 Device CA] exact profile 不在 certified CA registry")
	}
	changedAt, _ := wire.ParseTimeZ(profile.StatusChangedAt)
	committedAt, _ := wire.ParseTimeZ(head.Body.Payload.CommittedLogicalTime)
	if committedAt.Before(changedAt) {
		return errors.New("[D102 Device CA] Head 早于 profile activation")
	}
	return nil
}

func verifyProvisionalApprovalEvidence(evidence *EnrollmentApprovalEvidenceV1,
	reservationQCHash string, trustedTime time.Time) error {
	body := evidence.ProvisionalIssuance.Body
	if err := wire.VerifyEnrollmentProvisionalIssuance(&evidence.ProvisionalIssuance,
		&evidence.DeviceCertificateProfile); err != nil {
		return err
	}
	issuanceHash, _ := wire.EnrollmentProvisionalIssuanceHash(&evidence.ProvisionalIssuance)
	if body.ClaimOperationHash != evidence.ProvisionalOperation.ClaimOperationHash ||
		body.ReservationHeadHash != evidence.Reservation.Head.HeadHash ||
		body.ReservationHeadQCHash != reservationQCHash ||
		evidence.ProvisionalOperation.ProvisionalIssuanceHash != issuanceHash ||
		body.IssuanceLogCoordinate.RecoveryEpoch != evidence.Issuance.Head.Body.Payload.RecoveryEpoch ||
		body.IssuanceLogCoordinate.RaftIndex != evidence.Issuance.Head.Body.Payload.RaftIndex ||
		evidence.ProvisionalOperation.IssuedAt != evidence.Issuance.Head.Body.Payload.CommittedLogicalTime {
		return errors.New("[D130 Enrollment peer] provisional issuance/head/coordinate binding 无效")
	}
	previousRoot, err := wire.EnrollmentIssuanceRegistryRoot(evidence.PreviousIssuanceRegistryLeaves)
	if err != nil || previousRoot != evidence.ProvisionalOperation.PreviousIssuanceRegistryRoot {
		return errors.New("[D130 Enrollment peer] issuance registry previous root preimage 无效")
	}
	resulting := append([]wire.EnrollmentIssuanceRegistryLeafV1(nil), evidence.PreviousIssuanceRegistryLeaves...)
	resulting = append(resulting, evidence.ProvisionalOperation.IssuanceRegistryLeaf)
	resultingRoot, err := wire.EnrollmentIssuanceRegistryRoot(resulting)
	if err != nil || resultingRoot != evidence.ProvisionalOperation.ResultingIssuanceRegistryRoot {
		return errors.New("[D130 Enrollment peer] issuance registry first-result CAS preimage 无效")
	}
	if err := verifyCARegistryAtHead(&evidence.DeviceCertificateProfile, &evidence.IssuanceCARegistry,
		&evidence.Issuance.Head); err != nil {
		return err
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(&evidence.ResultArtifact)
	if err != nil || resultHash != body.ResultArtifactHash {
		return errors.New("[D130 Enrollment peer] result artifact hash/preimage 不匹配")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(&evidence.ResultArtifact)
	if err != nil {
		return err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	viewHash, viewErr := wire.DeviceViewHash(&evidence.ResultArtifact.InitialDeviceView)
	if err != nil || viewErr != nil || certificateHash != body.DeviceCertificateHash ||
		viewHash != body.InitialDeviceViewHash ||
		evidence.ResultArtifact.InitialDeviceView.Active.SecretArtifactRefsRoot != body.SecretArtifactRefsRoot {
		return errors.New("[D130 Enrollment peer] certificate/view/secret refs 未绑定 provisional issuance")
	}
	intent := evidence.ClaimEvidence.Opening.DeviceEnrollmentIntent
	view := evidence.ResultArtifact.InitialDeviceView
	active := view.Active
	if view.DeviceID != intent.DeviceID || view.DeviceGeneration != 1 || active.IdentitySPKIHash != evidence.ClaimOperation.IdentityKeyHash ||
		!wire.EqualCanonical(active.Membership, intent.Membership) ||
		!wire.EqualCanonical(active.Responsibilities, intent.Responsibilities) ||
		!wire.EqualCanonical(active.Grants, intent.Grants) {
		return errors.New("[D130 Enrollment peer] initial Device view 未投影 exact enrollment intent/key")
	}
	approvedAt, err := wire.ParseTimeZ(evidence.Issuance.Head.Body.Payload.CommittedLogicalTime)
	if err != nil || trustedTime.Before(approvedAt) {
		return errors.New("[D130 Enrollment peer] approval trusted time 早于 issuance Head")
	}
	if _, err := wire.VerifyDeviceCertificateAt(certificateDER, &evidence.DeviceCertificateProfile,
		intent.DeviceID, evidence.ClaimOperation.IdentityKeyHash, intent.Platform,
		intent.Responsibilities.Values, body.IssuanceLogCoordinate, approvedAt, trustedTime); err != nil {
		return err
	}
	return nil
}
