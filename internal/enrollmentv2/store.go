package enrollmentv2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"loom/internal/wire"
)

// DurableRecord 保存跨 control 可复制、可独立重验的稳定事务制品；raw token、
// challenge、CSR 正文和 PoP 签名字节不得越过私有请求验证边界。
type DurableRecord struct {
	InviteID                         string                                `json:"invite_id"`
	TokenCommitment                  string                                `json:"token_commitment"`
	Invite                           InviteContext                         `json:"invite"`
	ClaimEvidence                    ClaimPrivateEvidenceV1                `json:"claim_evidence"`
	ClaimOperation                   ClaimOperationV2                      `json:"claim_operation"`
	AdmissionQC                      wire.StableEnrollmentAdmissionQCV1    `json:"admission_qc"`
	AdmissionControlSet              wire.ControlSetV1                     `json:"admission_control_set"`
	ReservationBaseHead              wire.HeadEntryV2                      `json:"reservation_base_head"`
	BaseToReservationHeads           []wire.HeadEntryV2                    `json:"base_to_reservation_heads,omitempty"`
	BaseToReservationTransitions     []wire.ControlSetTransitionBundleV1   `json:"base_to_reservation_transitions,omitempty"`
	ReservationCertification         CertifiedEnrollmentOperationProofV1   `json:"reservation_certification"`
	ProvisionalOperation             *ProvisionalIssuanceOperationV1       `json:"provisional_operation,omitempty"`
	ProvisionalIssuance              *wire.EnrollmentProvisionalIssuanceV1 `json:"provisional_issuance,omitempty"`
	DeviceCertificateProfile         *wire.DeviceCertificateProfileStateV1 `json:"device_certificate_profile,omitempty"`
	ResultArtifact                   *wire.EnrollmentResultArtifactV1      `json:"result_artifact,omitempty"`
	ProvisionalCertification         *CertifiedEnrollmentOperationProofV1  `json:"provisional_certification,omitempty"`
	ReservationToIssuanceHeads       []wire.HeadEntryV2                    `json:"reservation_to_issuance_heads,omitempty"`
	ReservationToIssuanceTransitions []wire.ControlSetTransitionBundleV1   `json:"reservation_to_issuance_transitions,omitempty"`
	ApprovalQC                       *wire.StableEnrollmentApprovalQCV2    `json:"approval_qc,omitempty"`
	ApprovalControlSet               *wire.ControlSetV1                    `json:"approval_control_set,omitempty"`
	CompletionOperation              *CompletionOperationV2                `json:"completion_operation,omitempty"`
	CompletionCertification          *CompletionCertificationV1            `json:"completion_certification,omitempty"`
	CompletionProjection             *CompletionProjectionV1               `json:"completion_projection,omitempty"`
	State                            TransactionStateV2                    `json:"state"`
}

type durableState struct {
	Schema  int             `json:"schema"`
	Records []DurableRecord `json:"records"`
}

// Store 为 Enrollment reducer 提供原子耐久 CAS。相同稳定 claim 重放返回同一
// state；同一 Invite/token 的不同 core/key/request 永久冲突。
type Store struct {
	mu    sync.Mutex
	path  string
	state durableState
}

func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("[Enrollment] transaction store path 不能为空")
	}
	store := &Store{path: path, state: durableState{Schema: 6, Records: []DurableRecord{}}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var state durableState
	if _, err := wire.DecodeStrict(body, 32<<20, &state); err != nil {
		return nil, fmt.Errorf("[Enrollment] transaction store 非规范或损坏: %w", err)
	}
	if state.Schema == 2 || state.Schema == 3 || state.Schema == 4 || state.Schema == 5 {
		if len(state.Records) != 0 {
			return nil, errors.New("[Enrollment] 旧 transaction record 缺完整 Head/ControlSet transition proof，禁止迁移")
		}
		state.Schema = 6
		if err := store.persistLocked(state); err != nil {
			return nil, err
		}
	}
	if err := validateDurableState(&state); err != nil {
		return nil, err
	}
	store.state = state
	return store, nil
}

func (s *Store) Snapshot(inviteID string) (TransactionStateV2, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, found := findRecord(s.state.Records, inviteID)
	if !found {
		return TransactionStateV2{}, false
	}
	return s.state.Records[index].State, true
}

func (s *Store) SnapshotRecord(inviteID string) (DurableRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, found := findRecord(s.state.Records, inviteID)
	if !found {
		return DurableRecord{}, false
	}
	return cloneDurableRecord(s.state.Records[index]), true
}

func (s *Store) Reserve(invite InviteContext, evidence ClaimPrivateEvidenceV1, operation ClaimOperationV2,
	admission *wire.StableEnrollmentAdmissionQCV1, set *wire.ControlSetV1,
	baseHead wire.HeadEntryV2, intermediateHeads []wire.HeadEntryV2,
	transitions []wire.ControlSetTransitionBundleV1,
	certification CertifiedEnrollmentOperationProofV1) (TransactionStateV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateClaimPrivateEvidence(&evidence, &operation); err != nil {
		return TransactionStateV2{}, err
	}
	if err := validateOperationCertification(&certification, operation.OperationID,
		DomainClaimOperation, operation, &certification.ControlSet, operation.ReservedAt); err != nil {
		return TransactionStateV2{}, err
	}
	if err := validateReservationHeadLineage(&baseHead, intermediateHeads, transitions,
		&certification, admission, set); err != nil {
		return TransactionStateV2{}, err
	}
	next, err := Reserve(invite, operation, admission, set, operation.ReservedAt)
	if err != nil {
		return TransactionStateV2{}, err
	}
	index, found := findRecord(s.state.Records, invite.InviteID)
	if found {
		existing := s.state.Records[index]
		if existing.TokenCommitment == invite.TokenCommitment && sameStableClaim(existing.State, next) &&
			wire.EqualCanonical(existing.Invite, invite) && wire.EqualCanonical(existing.ClaimEvidence, evidence) &&
			wire.EqualCanonical(existing.ClaimOperation, operation) &&
			wire.EqualCanonical(existing.AdmissionQC, *admission) && wire.EqualCanonical(existing.AdmissionControlSet, *set) &&
			wire.EqualCanonical(existing.ReservationBaseHead, baseHead) &&
			equalHeadSequences(existing.BaseToReservationHeads, intermediateHeads) &&
			equalControlSetTransitionSequences(existing.BaseToReservationTransitions, transitions) &&
			wire.EqualCanonical(existing.ReservationCertification, certification) {
			return existing.State, nil
		}
		return TransactionStateV2{}, errors.New("[Enrollment] 同一 Invite/token 已被不同 request/core/key 耐久预留")
	}
	for _, existing := range s.state.Records {
		if existing.TokenCommitment == invite.TokenCommitment {
			return TransactionStateV2{}, errors.New("[Enrollment] token commitment 已绑定另一 Invite")
		}
	}
	candidate := cloneDurableState(s.state)
	candidate.Records = append(candidate.Records, DurableRecord{
		InviteID: invite.InviteID, TokenCommitment: invite.TokenCommitment, Invite: invite,
		ClaimEvidence: evidence, ClaimOperation: operation, AdmissionQC: *admission,
		AdmissionControlSet: *set, ReservationBaseHead: baseHead,
		BaseToReservationHeads:       append([]wire.HeadEntryV2(nil), intermediateHeads...),
		BaseToReservationTransitions: cloneControlSetTransitions(transitions),
		ReservationCertification:     certification, State: next,
	})
	sort.Slice(candidate.Records, func(i, j int) bool { return candidate.Records[i].InviteID < candidate.Records[j].InviteID })
	if err := s.persistLocked(candidate); err != nil {
		return TransactionStateV2{}, err
	}
	s.state = cloneDurableState(candidate)
	return next, nil
}

func (s *Store) RecordProvisional(operation ProvisionalIssuanceOperationV1,
	issuance wire.EnrollmentProvisionalIssuanceV1,
	profile wire.DeviceCertificateProfileStateV1,
	result wire.EnrollmentResultArtifactV1,
	certification CertifiedEnrollmentOperationProofV1,
	intermediateHeads []wire.HeadEntryV2,
	transitions []wire.ControlSetTransitionBundleV1) (TransactionStateV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, found := findRecord(s.state.Records, operation.InviteID)
	if !found {
		return TransactionStateV2{}, errors.New("[Enrollment] provisional issuance 缺耐久 reservation")
	}
	current := s.state.Records[index].State
	if current.Status == "issued_provisional" || current.Status == "completed" {
		operationHash, err := wire.HashObject(DomainProvisionalOperation, operation)
		existing := s.state.Records[index]
		if err == nil && current.ProvisionalIssuanceOperationHash == operationHash &&
			existing.ProvisionalOperation != nil && existing.ProvisionalIssuance != nil &&
			existing.DeviceCertificateProfile != nil && existing.ResultArtifact != nil && existing.ProvisionalCertification != nil &&
			wire.EqualCanonical(*existing.ProvisionalOperation, operation) &&
			wire.EqualCanonical(*existing.ProvisionalIssuance, issuance) &&
			wire.EqualCanonical(*existing.DeviceCertificateProfile, profile) &&
			wire.EqualCanonical(*existing.ResultArtifact, result) &&
			wire.EqualCanonical(*existing.ProvisionalCertification, certification) &&
			equalHeadSequences(existing.ReservationToIssuanceHeads, intermediateHeads) &&
			equalControlSetTransitionSequences(existing.ReservationToIssuanceTransitions, transitions) {
			return current, nil
		}
		return TransactionStateV2{}, errors.New("[Enrollment] 同一 claim 已有不同 provisional first-result")
	}
	next, err := RecordProvisional(current, operation)
	if err != nil {
		return TransactionStateV2{}, err
	}
	if err := validateProvisionalEvidence(&operation, &issuance, &profile, &result); err != nil {
		return TransactionStateV2{}, err
	}
	if err := validateOperationCertification(&certification, operation.OperationID,
		DomainProvisionalOperation, operation, &certification.ControlSet, operation.IssuedAt); err != nil {
		return TransactionStateV2{}, err
	}
	if err := VerifyEnrollmentHeadLineage(&s.state.Records[index].ReservationCertification.Head,
		intermediateHeads, transitions, &certification.Head, &certification.ControlSet); err != nil {
		return TransactionStateV2{}, err
	}
	reservation := &s.state.Records[index].ReservationCertification
	reservationQCHash, err := wire.ConfigQCHash(reservation.ConfigQC)
	if err != nil || issuance.Body.ReservationHeadHash != reservation.Head.HeadHash ||
		issuance.Body.ReservationHeadQCHash != reservationQCHash ||
		issuance.Body.IssuanceLogCoordinate.RecoveryEpoch != certification.Head.Body.Payload.RecoveryEpoch ||
		issuance.Body.IssuanceLogCoordinate.RaftIndex != certification.Head.Body.Payload.RaftIndex {
		return TransactionStateV2{}, errors.New("[Enrollment] provisional issuance 未绑定 exact reservation/issuance Head")
	}
	previousLeaves := issuanceRegistryLeaves(s.state.Records)
	previousRoot, err := wire.EnrollmentIssuanceRegistryRoot(previousLeaves)
	if err != nil || operation.PreviousIssuanceRegistryRoot != previousRoot {
		return TransactionStateV2{}, errors.New("[Enrollment] provisional issuance previous registry root 非当前 first-result 集合")
	}
	resultingRoot, err := wire.EnrollmentIssuanceRegistryRoot(append(previousLeaves, operation.IssuanceRegistryLeaf))
	if err != nil || operation.ResultingIssuanceRegistryRoot != resultingRoot {
		return TransactionStateV2{}, errors.New("[Enrollment] provisional issuance resulting registry root 非规范结果")
	}
	candidate := cloneDurableState(s.state)
	candidate.Records[index].State = next
	candidate.Records[index].ProvisionalOperation = &operation
	candidate.Records[index].ProvisionalIssuance = &issuance
	candidate.Records[index].DeviceCertificateProfile = &profile
	candidate.Records[index].ResultArtifact = &result
	candidate.Records[index].ProvisionalCertification = &certification
	candidate.Records[index].ReservationToIssuanceHeads = append([]wire.HeadEntryV2(nil), intermediateHeads...)
	candidate.Records[index].ReservationToIssuanceTransitions = cloneControlSetTransitions(transitions)
	if err := s.persistLocked(candidate); err != nil {
		return TransactionStateV2{}, err
	}
	s.state = cloneDurableState(candidate)
	return next, nil
}

func (s *Store) Complete(operation CompletionOperationV2, approval *wire.StableEnrollmentApprovalQCV2,
	set *wire.ControlSetV1, certification CompletionCertificationV1) (TransactionStateV2, error) {
	if approval == nil || set == nil {
		return TransactionStateV2{}, errors.New("[Enrollment] completion approval/ControlSet 不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	index, found := findRecord(s.state.Records, operation.InviteID)
	if !found {
		return TransactionStateV2{}, errors.New("[Enrollment] completion 缺耐久 provisional issuance")
	}
	current := s.state.Records[index].State
	if current.Status == "completed" {
		operationHash, err := wire.HashObject(DomainCompletionOperation, operation)
		existing := s.state.Records[index]
		if err == nil && current.CompletionOperationHash == operationHash && existing.ApprovalQC != nil &&
			existing.ApprovalControlSet != nil && existing.CompletionOperation != nil &&
			existing.CompletionCertification != nil && existing.CompletionProjection != nil &&
			wire.EqualCanonical(*existing.ApprovalQC, *approval) && wire.EqualCanonical(*existing.ApprovalControlSet, *set) &&
			wire.EqualCanonical(*existing.CompletionOperation, operation) &&
			wire.EqualCanonical(*existing.CompletionCertification, certification) {
			return current, nil
		}
		return TransactionStateV2{}, errors.New("[Enrollment] completed transaction 不接受不同 completion")
	}
	next, err := Complete(current, operation, approval, set)
	if err != nil {
		return TransactionStateV2{}, err
	}
	if err := validateApprovalAgainstIssuance(&s.state.Records[index], approval); err != nil {
		return TransactionStateV2{}, err
	}
	projection, err := validateCompletionCertification(&s.state.Records[index], &operation,
		&certification, &next)
	if err != nil {
		return TransactionStateV2{}, err
	}
	candidate := cloneDurableState(s.state)
	candidate.Records[index].State = next
	candidate.Records[index].ApprovalQC = approval
	candidate.Records[index].ApprovalControlSet = set
	candidate.Records[index].CompletionOperation = &operation
	candidate.Records[index].CompletionCertification = &certification
	candidate.Records[index].CompletionProjection = &projection
	if err := s.persistLocked(candidate); err != nil {
		return TransactionStateV2{}, err
	}
	s.state = cloneDurableState(candidate)
	return next, nil
}

func (s *Store) persistLocked(candidate durableState) error {
	if err := validateDurableState(&candidate); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(candidate)
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, filepath.Base(s.path)+".tmp-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := replaceDurableFile(temporary, s.path); err != nil {
		return err
	}
	return syncDurableDirectory(directory)
}

func cloneDurableState(state durableState) durableState {
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return durableState{}
	}
	var clone durableState
	if _, err := wire.DecodeStrict(body, 32<<20, &clone); err != nil {
		return durableState{}
	}
	return clone
}

func validateDurableState(state *durableState) error {
	if state == nil || state.Schema != 6 || state.Records == nil {
		return errors.New("[Enrollment] transaction store schema 无效")
	}
	seenTokens := make(map[string]struct{}, len(state.Records))
	for index := range state.Records {
		record := &state.Records[index]
		if record.InviteID == "" || record.InviteID != record.State.InviteID || record.InviteID != record.Invite.InviteID ||
			record.TokenCommitment != record.Invite.TokenCommitment || index > 0 && state.Records[index-1].InviteID >= record.InviteID {
			return errors.New("[Enrollment] transaction records 未按 Invite ID 严格排序")
		}
		if _, err := wire.ParseHash(record.TokenCommitment); err != nil {
			return err
		}
		if _, duplicate := seenTokens[record.TokenCommitment]; duplicate {
			return errors.New("[Enrollment] transaction store 含重复 token commitment")
		}
		seenTokens[record.TokenCommitment] = struct{}{}
		if err := validateDurableRecord(record); err != nil {
			return err
		}
	}
	if err := validateRegistryHistory(state.Records); err != nil {
		return err
	}
	return nil
}

func cloneDurableRecord(record DurableRecord) DurableRecord {
	body, _ := wire.MarshalCanonical(record)
	var clone DurableRecord
	_, _ = wire.DecodeStrict(body, 32<<20, &clone)
	return clone
}

func validateDurableRecord(record *DurableRecord) error {
	if err := validateClaimPrivateEvidence(&record.ClaimEvidence, &record.ClaimOperation); err != nil {
		return err
	}
	reserved, err := Reserve(record.Invite, record.ClaimOperation, &record.AdmissionQC,
		&record.AdmissionControlSet, record.ClaimOperation.ReservedAt)
	if err != nil {
		return err
	}
	if err := validateOperationCertification(&record.ReservationCertification,
		record.ClaimOperation.OperationID, DomainClaimOperation, record.ClaimOperation,
		&record.ReservationCertification.ControlSet, record.ClaimOperation.ReservedAt); err != nil {
		return err
	}
	if err := validateReservationHeadLineage(&record.ReservationBaseHead,
		record.BaseToReservationHeads, record.BaseToReservationTransitions, &record.ReservationCertification,
		&record.AdmissionQC, &record.AdmissionControlSet); err != nil {
		return err
	}
	if record.State.Status == "reserved" {
		if record.ProvisionalOperation != nil || record.ProvisionalIssuance != nil ||
			record.DeviceCertificateProfile != nil || record.ResultArtifact != nil || record.ApprovalQC != nil ||
			record.ApprovalControlSet != nil || record.CompletionOperation != nil ||
			record.CompletionCertification != nil || record.CompletionProjection != nil ||
			len(record.ReservationToIssuanceHeads) != 0 || len(record.ReservationToIssuanceTransitions) != 0 ||
			!wire.EqualCanonical(reserved, record.State) {
			return errors.New("[Enrollment] reserved durable record tagged union 无效")
		}
		return nil
	}
	if record.State.Status != "issued_provisional" && record.State.Status != "completed" {
		return errors.New("[Enrollment] durable store 不接受未携 certified abort evidence 的状态")
	}
	if record.ProvisionalOperation == nil || record.ProvisionalIssuance == nil ||
		record.DeviceCertificateProfile == nil || record.ResultArtifact == nil ||
		record.ProvisionalCertification == nil {
		return errors.New("[Enrollment] issued durable record 缺 provisional stable artifacts")
	}
	if err := validateProvisionalEvidence(record.ProvisionalOperation, record.ProvisionalIssuance,
		record.DeviceCertificateProfile, record.ResultArtifact); err != nil {
		return err
	}
	if err := validateOperationCertification(record.ProvisionalCertification,
		record.ProvisionalOperation.OperationID, DomainProvisionalOperation, *record.ProvisionalOperation,
		&record.ProvisionalCertification.ControlSet, record.ProvisionalOperation.IssuedAt); err != nil {
		return err
	}
	if err := VerifyEnrollmentHeadLineage(&record.ReservationCertification.Head,
		record.ReservationToIssuanceHeads, record.ReservationToIssuanceTransitions,
		&record.ProvisionalCertification.Head, &record.ProvisionalCertification.ControlSet); err != nil {
		return err
	}
	reservationQCHash, err := wire.ConfigQCHash(record.ReservationCertification.ConfigQC)
	if err != nil || record.ProvisionalIssuance.Body.ReservationHeadHash != record.ReservationCertification.Head.HeadHash ||
		record.ProvisionalIssuance.Body.ReservationHeadQCHash != reservationQCHash ||
		record.ProvisionalIssuance.Body.IssuanceLogCoordinate.RecoveryEpoch != record.ProvisionalCertification.Head.Body.Payload.RecoveryEpoch ||
		record.ProvisionalIssuance.Body.IssuanceLogCoordinate.RaftIndex != record.ProvisionalCertification.Head.Body.Payload.RaftIndex {
		return errors.New("[Enrollment] durable provisional 未绑定 exact reservation/issuance Head")
	}
	issued, err := RecordProvisional(reserved, *record.ProvisionalOperation)
	if err != nil {
		return err
	}
	if record.State.Status == "issued_provisional" {
		if record.ApprovalQC != nil || record.ApprovalControlSet != nil || record.CompletionOperation != nil ||
			record.CompletionCertification != nil || record.CompletionProjection != nil ||
			!wire.EqualCanonical(issued, record.State) {
			return errors.New("[Enrollment] issued durable record tagged union 无效")
		}
		return nil
	}
	if record.ApprovalQC == nil || record.ApprovalControlSet == nil || record.CompletionOperation == nil ||
		record.CompletionCertification == nil || record.CompletionProjection == nil {
		return errors.New("[Enrollment] completed durable record 缺 approval/completion stable artifacts")
	}
	if err := validateApprovalAgainstIssuance(record, record.ApprovalQC); err != nil {
		return err
	}
	completed, err := Complete(issued, *record.CompletionOperation, record.ApprovalQC, record.ApprovalControlSet)
	if err != nil {
		return err
	}
	if !wire.EqualCanonical(completed, record.State) {
		return errors.New("[Enrollment] completed durable record 与 stable artifacts 不匹配")
	}
	projection, err := validateCompletionCertification(record, record.CompletionOperation,
		record.CompletionCertification, &completed)
	if err != nil || !wire.EqualCanonical(projection, *record.CompletionProjection) {
		return errors.New("[Enrollment] completed durable record 的 consume/activate/release 投影无效")
	}
	return nil
}

// validateOperationCertification 把 transaction reducer 的每一步绑定到同一个
// stable ControlSet 下的 exact certified operation leaf；时间只能取承载该 leaf
// 的 Head logical time，不能由 backend 另报一个看似相同的 anchor。
func validateOperationCertification(certification *CertifiedEnrollmentOperationProofV1,
	operationID, domain string, operation any, set *wire.ControlSetV1, committedAt string) error {
	if certification == nil || set == nil || certification.PreviousControlSet != nil ||
		certification.Head.Body.Payload.HeadKind != "ordinary" ||
		certification.Head.Body.Payload.CommittedLogicalTime != committedAt {
		return errors.New("[Enrollment] operation certification header/time 无效")
	}
	if !wire.EqualCanonical(certification.ControlSet, *set) {
		return errors.New("[Enrollment] operation certification 使用错误 stable ControlSet")
	}
	objectID, err := wire.HashObject(domain, operation)
	if err != nil {
		return err
	}
	if _, err := verifyCertifiedEnrollmentOperation(certification, operationID, objectID); err != nil {
		return err
	}
	return nil
}

func validateReservationHeadLineage(baseHead *wire.HeadEntryV2, intermediate []wire.HeadEntryV2,
	transitions []wire.ControlSetTransitionBundleV1,
	certification *CertifiedEnrollmentOperationProofV1,
	admission *wire.StableEnrollmentAdmissionQCV1, set *wire.ControlSetV1) error {
	if baseHead == nil || certification == nil || admission == nil || set == nil {
		return errors.New("[Enrollment] reservation Head lineage 输入不完整")
	}
	attestation := &admission.Attestation
	setHash, err := wire.ControlSetHash(set)
	if err != nil || baseHead.HeadHash != attestation.BaseHeadHash ||
		baseHead.Body.Payload.ClusterID != attestation.ClusterID ||
		baseHead.Body.Payload.RecoveryEpoch != attestation.BaseRecoveryEpoch ||
		baseHead.Body.Payload.ControlEpoch != attestation.BaseControlEpoch ||
		baseHead.Body.Payload.ControlSetHash != attestation.BaseControlSetHash ||
		baseHead.Body.Payload.ControlSetHash != setHash {
		return errors.New("[Enrollment] reservation base Head 未绑定 admission authority")
	}
	if err := wire.ValidateHeadEntry(baseHead, nil); err != nil {
		return err
	}
	if err := VerifyEnrollmentHeadLineage(baseHead, intermediate, transitions,
		&certification.Head, &certification.ControlSet); err != nil {
		return errors.New("[Enrollment] base→reservation Head lineage 不连续")
	}
	return nil
}

func validateProvisionalEvidence(operation *ProvisionalIssuanceOperationV1,
	issuance *wire.EnrollmentProvisionalIssuanceV1, profile *wire.DeviceCertificateProfileStateV1,
	result *wire.EnrollmentResultArtifactV1) error {
	if operation == nil || issuance == nil || profile == nil || result == nil {
		return errors.New("[Enrollment] provisional evidence 不完整")
	}
	if err := wire.VerifyEnrollmentProvisionalIssuance(issuance, profile); err != nil {
		return err
	}
	issuanceHash, err := wire.EnrollmentProvisionalIssuanceHash(issuance)
	if err != nil {
		return err
	}
	body := issuance.Body
	resultHash, resultErr := wire.EnrollmentResultArtifactHash(result)
	certificateDER, certificateErr := wire.EnrollmentResultCertificateDER(result)
	certificateHash, certificateHashErr := wire.DeviceCertificateHash(certificateDER)
	viewHash, viewErr := wire.DeviceViewHash(&result.InitialDeviceView)
	if operation.ProvisionalIssuanceHash != issuanceHash || operation.ClusterID != body.ClusterID ||
		operation.InviteID != body.InviteID || operation.RequestID != body.RequestID ||
		operation.ClaimOperationHash != body.ClaimOperationHash ||
		operation.IssuanceRegistryLeaf.ClaimOperationHash != operation.ClaimOperationHash ||
		operation.IssuanceRegistryLeaf.ProvisionalIssuanceHash != issuanceHash ||
		resultErr != nil || certificateErr != nil || certificateHashErr != nil || viewErr != nil ||
		result.ClusterID != body.ClusterID || result.InviteID != body.InviteID || result.RequestID != body.RequestID ||
		resultHash != body.ResultArtifactHash || certificateHash != body.DeviceCertificateHash ||
		viewHash != body.InitialDeviceViewHash || result.InitialDeviceView.Active.SecretArtifactRefsRoot != body.SecretArtifactRefsRoot {
		return errors.New("[Enrollment] provisional operation/envelope/registry leaf exact binding 不匹配")
	}
	issuedAt, issuedErr := wire.ParseTimeZ(operation.IssuedAt)
	statusChangedAt, changedErr := wire.ParseTimeZ(profile.StatusChangedAt)
	windowStart, startErr := wire.ParseTimeZ(profile.ProfileIntent.IssuanceNotBefore)
	windowEnd, endErr := wire.ParseTimeZ(profile.ProfileIntent.IssuanceNotAfter)
	if issuedErr != nil || changedErr != nil || startErr != nil || endErr != nil ||
		issuedAt.Before(statusChangedAt) || issuedAt.Before(windowStart) || !issuedAt.Before(windowEnd) {
		return errors.New("[Device CA] provisional issuance logical time 不在 exact active profile window")
	}
	return nil
}

func validateApprovalAgainstIssuance(record *DurableRecord, approval *wire.StableEnrollmentApprovalQCV2) error {
	if record == nil || record.ProvisionalIssuance == nil || record.ProvisionalOperation == nil ||
		record.ResultArtifact == nil || approval == nil {
		return errors.New("[Enrollment] approval 缺 exact provisional evidence")
	}
	body := record.ProvisionalIssuance.Body
	attestation := approval.Attestation
	issuanceHash, err := wire.EnrollmentProvisionalIssuanceHash(record.ProvisionalIssuance)
	if err != nil {
		return err
	}
	operationHash, err := wire.HashObject(DomainProvisionalOperation, *record.ProvisionalOperation)
	if err != nil {
		return err
	}
	if record.ProvisionalCertification == nil {
		return errors.New("[Enrollment] approval 缺 issuance Head certification")
	}
	issuanceQCHash, err := wire.ConfigQCHash(record.ProvisionalCertification.ConfigQC)
	if err != nil {
		return err
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(record.ResultArtifact)
	if err != nil {
		return err
	}
	if attestation.ClusterID != body.ClusterID || attestation.InviteID != body.InviteID ||
		attestation.RequestID != body.RequestID || attestation.ClaimOperationHash != body.ClaimOperationHash ||
		attestation.ProvisionalIssuanceOperationHash != operationHash ||
		attestation.ProvisionalIssuanceHash != issuanceHash ||
		attestation.IssuanceHeadHash != record.ProvisionalCertification.Head.HeadHash ||
		attestation.IssuanceHeadQCHash != issuanceQCHash ||
		attestation.ResultingIssuanceRegistryRoot != record.ProvisionalOperation.ResultingIssuanceRegistryRoot ||
		attestation.DeviceCertificateHash != body.DeviceCertificateHash ||
		attestation.InitialDeviceViewHash != body.InitialDeviceViewHash ||
		attestation.SecretArtifactRefsRoot != body.SecretArtifactRefsRoot ||
		attestation.ResultArtifactHash != body.ResultArtifactHash || resultHash != body.ResultArtifactHash {
		return errors.New("[Enrollment] approval QC 未逐字段绑定 exact provisional issuance")
	}
	return nil
}

func issuanceRegistryLeaves(records []DurableRecord) []wire.EnrollmentIssuanceRegistryLeafV1 {
	leaves := make([]wire.EnrollmentIssuanceRegistryLeafV1, 0, len(records))
	for index := range records {
		if operation := records[index].ProvisionalOperation; operation != nil {
			leaves = append(leaves, operation.IssuanceRegistryLeaf)
		}
	}
	return leaves
}

func validateRegistryHistory(records []DurableRecord) error {
	type issuedRecord struct {
		coordinate wire.IssuanceLogCoordinateV1
		operation  *ProvisionalIssuanceOperationV1
	}
	issued := make([]issuedRecord, 0, len(records))
	for index := range records {
		if records[index].ProvisionalOperation != nil && records[index].ProvisionalIssuance != nil {
			issued = append(issued, issuedRecord{coordinate: records[index].ProvisionalIssuance.Body.IssuanceLogCoordinate,
				operation: records[index].ProvisionalOperation})
		}
	}
	sort.Slice(issued, func(i, j int) bool { return compareIssuanceCoordinate(issued[i].coordinate, issued[j].coordinate) < 0 })
	leaves := make([]wire.EnrollmentIssuanceRegistryLeafV1, 0, len(issued))
	for index := range issued {
		if index > 0 && compareIssuanceCoordinate(issued[index-1].coordinate, issued[index].coordinate) == 0 {
			return errors.New("[Enrollment] issuance registry 含重复 Raft 坐标")
		}
		previousRoot, err := wire.EnrollmentIssuanceRegistryRoot(leaves)
		if err != nil || issued[index].operation.PreviousIssuanceRegistryRoot != previousRoot {
			return errors.New("[Enrollment] issuance registry history previous root 断裂")
		}
		leaves = append(leaves, issued[index].operation.IssuanceRegistryLeaf)
		resultingRoot, err := wire.EnrollmentIssuanceRegistryRoot(leaves)
		if err != nil || issued[index].operation.ResultingIssuanceRegistryRoot != resultingRoot {
			return errors.New("[Enrollment] issuance registry history resulting root 断裂")
		}
	}
	return nil
}

func compareIssuanceCoordinate(left, right wire.IssuanceLogCoordinateV1) int {
	if left.RecoveryEpoch < right.RecoveryEpoch ||
		left.RecoveryEpoch == right.RecoveryEpoch && left.RaftIndex < right.RaftIndex {
		return -1
	}
	if left.RecoveryEpoch == right.RecoveryEpoch && left.RaftIndex == right.RaftIndex {
		return 0
	}
	return 1
}

func findRecord(records []DurableRecord, inviteID string) (int, bool) {
	index := sort.Search(len(records), func(i int) bool { return records[i].InviteID >= inviteID })
	return index, index < len(records) && records[index].InviteID == inviteID
}

func sameStableClaim(left, right TransactionStateV2) bool {
	return left.ClusterID == right.ClusterID && left.InviteID == right.InviteID && left.RequestID == right.RequestID &&
		left.ClaimCoreHash == right.ClaimCoreHash && left.IdentityKeyHash == right.IdentityKeyHash &&
		left.WrappingKeyHash == right.WrappingKeyHash && left.ClaimOperationHash == right.ClaimOperationHash
}
