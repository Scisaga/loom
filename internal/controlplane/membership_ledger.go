package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"loom/internal/wire"
)

type MembershipLedgerPhase string

const (
	MembershipLedgerCandidate                  MembershipLedgerPhase = "candidate"
	MembershipLedgerLearners                   MembershipLedgerPhase = "learners"
	MembershipLedgerJointCommittedNotCertified MembershipLedgerPhase = "joint_committed_not_certified"
	MembershipLedgerJointFinalizationOnly      MembershipLedgerPhase = "joint_finalization_only"
	MembershipLedgerFinalCommittedNotCertified MembershipLedgerPhase = "final_committed_not_certified"
	MembershipLedgerFinal                      MembershipLedgerPhase = "final"
)

// CandidateEvidence 是 learner 对已安装 parent/log/private directory 的声明；
// CreateMembershipLedger 会把它与不透明的 active Device identity 交叉验证后再持久化。
type CandidateEvidence struct {
	DeviceID                     string `json:"device_id"`
	DeviceCertificateHash        string `json:"device_certificate_hash"`
	OverlayReachable             bool   `json:"overlay_reachable"`
	InstalledHeadHash            string `json:"installed_head_hash"`
	LastLogIndex                 int64  `json:"last_log_index"`
	InstalledDirectoryObjectHash string `json:"installed_directory_object_hash"`
}

// CertifiedLearnerEvidenceV1 只保存由 active Device identity 与私有目录安装结果
// 交叉验证后的投影；调用方自报 active=true 不能进入 ledger（D100、D124）。
type CertifiedLearnerEvidenceV1 struct {
	MemberID                     string `json:"member_id"`
	DeviceID                     string `json:"device_id"`
	DeviceCertificateHash        string `json:"device_certificate_hash"`
	OverlayReachable             bool   `json:"overlay_reachable"`
	InstalledHeadHash            string `json:"installed_head_hash"`
	InstalledLogIndex            int64  `json:"installed_log_index"`
	InstalledDirectoryObjectHash string `json:"installed_directory_object_hash"`
	CaughtUp                     bool   `json:"caught_up"`
	CaughtUpThroughIndex         int64  `json:"caught_up_through_index"`
	CheckpointHash               string `json:"checkpoint_hash,omitempty"`
}

type MembershipLedgerCandidateV1 struct {
	Schema                   int                                      `json:"schema"`
	ValidatedAt              string                                   `json:"validated_at"`
	ParentCurrent            wire.SignedCurrentV2                     `json:"parent_current"`
	ParentPreviousControlSet *wire.ControlSetV1                       `json:"parent_previous_control_set,omitempty"`
	OldControlSet            wire.ControlSetV1                        `json:"old_control_set"`
	NewControlSet            wire.ControlSetV1                        `json:"new_control_set"`
	OldDirectoryObject       wire.ControlPeerDirectoryPrivateObjectV1 `json:"old_directory_object"`
	NewDirectoryObject       wire.ControlPeerDirectoryPrivateObjectV1 `json:"new_directory_object"`
	OldDirectoryObjectHash   string                                   `json:"old_directory_object_hash"`
	NewDirectoryObjectHash   string                                   `json:"new_directory_object_hash"`
	MembershipApprovalProof  wire.ControlMembershipApprovalProofV1    `json:"membership_approval_proof"`
	AdminScopeHash           string                                   `json:"admin_scope_hash"`
	Learners                 []CertifiedLearnerEvidenceV1             `json:"learners"`
}

type MembershipJointCommitV1 struct {
	Body       wire.JointControlSetEntryBodyV1 `json:"body"`
	EntryHash  string                          `json:"entry_hash"`
	RaftCommit *RaftCommitReferenceV1          `json:"raft_commit"`
	Proof      *wire.JointControlSetProofV1    `json:"proof,omitempty"`
}

type MembershipFinalCommitV1 struct {
	Head                      wire.HeadEntryV2               `json:"head"`
	RaftCommit                *RaftCommitReferenceV1         `json:"raft_commit"`
	ExpectedSnapshotHash      string                         `json:"expected_snapshot_hash"`
	ExpectedEffectiveSSOTHash string                         `json:"expected_effective_ssot_hash"`
	QC                        *wire.JointHeadReplicationQCV1 `json:"qc,omitempty"`
}

type MembershipLedgerStateV1 struct {
	Schema          int                                `json:"schema"`
	Phase           MembershipLedgerPhase              `json:"phase"`
	Candidate       MembershipLedgerCandidateV1        `json:"candidate"`
	Joint           *MembershipJointCommitV1           `json:"joint,omitempty"`
	Final           *MembershipFinalCommitV1           `json:"final,omitempty"`
	CertifiedBundle *wire.ControlSetTransitionBundleV1 `json:"certified_bundle,omitempty"`
}

// MembershipLedger 把 learner→Joint commit/QC→Final commit/QC 的每个安全边界
// 分别 fsync；进程恢复时不会把本地安装、commit 或未成 quorum 的签名误报为 Final（D112）。
type MembershipLedger struct {
	mu    sync.Mutex
	path  string
	state MembershipLedgerStateV1
}

// CreateMembershipLedger 只接受 control_api 产生的不透明 admin authorization 和
// authenticateDeviceIdentity 产生的 active Device identity。new voter 的目录、Device、
// checkpoint 与 exact certified parent 必须在第一次落盘前全部互相绑定（D100、D112、D124）。
func CreateMembershipLedger(path string, parent wire.SignedCurrentV2, parentPreviousSet *wire.ControlSetV1,
	oldSet, newSet wire.ControlSetV1, oldDirectory, newDirectory wire.ControlPeerDirectoryPrivateObjectV1,
	approval wire.ControlMembershipApprovalProofV1, admin wire.VerifiedAdminOperationV1,
	evidence map[string]CandidateEvidence, identities map[string]VerifiedDeviceIdentityV1,
	trustedTime time.Time) (*MembershipLedger, error) {
	if path == "" || trustedTime.IsZero() {
		return nil, errors.New("[D112 membership ledger] path/可信时间无效")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return nil, errors.New("[D112 membership ledger] ledger 已存在，必须显式恢复")
		}
		return nil, err
	}
	scope := wire.AdminResourceScopeV1{ScopeKind: "control_membership", ControlMembership: &struct{}{}}
	scopeHash, err := wire.AdminResourceScopeHash(&scope)
	if err != nil || admin.HeadHash() != parent.Head.HeadHash || admin.ScopeHash() != scopeHash ||
		!wire.EqualCanonical(admin.Operation(), approval.AdminIntentOperation) {
		return nil, errors.New("[D104 membership ledger] 缺 exact control-membership admin authorization")
	}
	oldObjectHash, err := wire.ControlPeerDirectoryPrivateObjectHash(&oldSet, &oldDirectory)
	if err != nil {
		return nil, err
	}
	newObjectHash, err := wire.ControlPeerDirectoryPrivateObjectHash(&newSet, &newDirectory)
	if err != nil {
		return nil, err
	}
	learners, err := certifyLearners(parent, oldSet, newSet, newDirectory, newObjectHash, evidence, identities)
	if err != nil {
		return nil, err
	}
	state := MembershipLedgerStateV1{Schema: 2, Phase: MembershipLedgerCandidate,
		Candidate: MembershipLedgerCandidateV1{
			Schema: 1, ValidatedAt: trustedTime.UTC().Format(time.RFC3339Nano), ParentCurrent: parent,
			ParentPreviousControlSet: cloneControlSetPointer(parentPreviousSet), OldControlSet: oldSet,
			NewControlSet: newSet, OldDirectoryObject: oldDirectory, NewDirectoryObject: newDirectory,
			OldDirectoryObjectHash: oldObjectHash, NewDirectoryObjectHash: newObjectHash,
			MembershipApprovalProof: approval, AdminScopeHash: scopeHash, Learners: learners,
		}}
	if err := validateMembershipLedgerState(&state); err != nil {
		return nil, err
	}
	ledger := &MembershipLedger{path: path, state: state}
	if err := ledger.persistLocked(state); err != nil {
		return nil, err
	}
	return ledger, nil
}

func OpenMembershipLedger(path string) (*MembershipLedger, error) {
	if path == "" {
		return nil, errors.New("[D112 membership ledger] path 不能为空")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("[D112 membership ledger] ledger 必须是 0600 普通文件")
	}
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[D112 membership ledger] ledger 不是 exact canonical JSON")
	}
	var state MembershipLedgerStateV1
	if _, err := wire.DecodeStrict(body, 64<<20, &state); err != nil {
		return nil, err
	}
	if err := validateMembershipLedgerState(&state); err != nil {
		return nil, err
	}
	return &MembershipLedger{path: path, state: state}, nil
}

func (ledger *MembershipLedger) Snapshot() MembershipLedgerStateV1 {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return cloneMembershipLedgerState(ledger.state)
}

func (ledger *MembershipLedger) BeginLearners() error {
	return ledger.update(func(state *MembershipLedgerStateV1) error {
		if state.Phase != MembershipLedgerCandidate {
			return errors.New("[D112 learner] 只能从 candidate 进入 learners")
		}
		state.Phase = MembershipLedgerLearners
		return nil
	})
}

func (ledger *MembershipLedger) MarkLearnerCaughtUp(memberID, checkpointHash string, lastAppliedIndex int64) error {
	return ledger.update(func(state *MembershipLedgerStateV1) error {
		if state.Phase != MembershipLedgerLearners {
			return errors.New("[D112 learner] 只有 learners 阶段能记录 catch-up")
		}
		if _, err := wire.ParseHash(checkpointHash); err != nil {
			return err
		}
		parentIndex := state.Candidate.ParentCurrent.Head.Body.Payload.RaftIndex
		for i := range state.Candidate.Learners {
			learner := &state.Candidate.Learners[i]
			if learner.MemberID != memberID {
				continue
			}
			if lastAppliedIndex < parentIndex || lastAppliedIndex < learner.InstalledLogIndex ||
				learner.CaughtUp && (lastAppliedIndex != learner.CaughtUpThroughIndex || checkpointHash != learner.CheckpointHash) {
				return errors.New("[D112 learner] catch-up 坐标回退或幂等结果冲突")
			}
			learner.CaughtUp = true
			learner.CaughtUpThroughIndex = lastAppliedIndex
			learner.CheckpointHash = checkpointHash
			return nil
		}
		return errors.New("[D112 learner] 未知 learner")
	})
}

func (ledger *MembershipLedger) RecordJointCommitFromRaft(storage *RaftStorage,
	body wire.JointControlSetEntryBodyV1) error {
	return ledger.update(func(state *MembershipLedgerStateV1) error {
		if state.Joint != nil {
			reference, err := committedMembershipRecordReference(storage, &state.Candidate.OldControlSet,
				&state.Candidate.NewControlSet,
				body.RaftIndex, state.Joint.EntryHash, RaftRecordJointControlSet, nil, &body)
			if err == nil && wire.EqualCanonical(state.Joint.Body, body) &&
				state.Joint.RaftCommit != nil && wire.EqualCanonical(*state.Joint.RaftCommit, *reference) {
				return nil
			}
			return errors.New("[D112 joint] 已记录的 Joint commit 不能被改写")
		}
		if state.Phase != MembershipLedgerLearners &&
			!(state.Phase == MembershipLedgerCandidate && len(state.Candidate.Learners) == 0) {
			return errors.New("[D112 joint] learner gate 尚未完成")
		}
		for _, learner := range state.Candidate.Learners {
			if !learner.CaughtUp {
				return fmt.Errorf("[D112 learner] %s 尚未 catch-up", learner.MemberID)
			}
		}
		entryHash, err := wire.VerifyJointControlSetCandidate(&state.Candidate.OldControlSet,
			&state.Candidate.NewControlSet, &state.Candidate.MembershipApprovalProof, &body,
			&state.Candidate.ParentCurrent.Head)
		if err != nil {
			return err
		}
		reference, err := committedMembershipRecordReference(storage, &state.Candidate.OldControlSet,
			&state.Candidate.NewControlSet,
			body.RaftIndex, entryHash, RaftRecordJointControlSet, nil, &body)
		if err != nil {
			return err
		}
		state.Joint = &MembershipJointCommitV1{Body: body, EntryHash: entryHash, RaftCommit: reference}
		state.Phase = MembershipLedgerJointCommittedNotCertified
		return nil
	})
}

func (ledger *MembershipLedger) CertifyJoint(signatures []wire.ControlConfigSignatureV1) error {
	return ledger.update(func(state *MembershipLedgerStateV1) error {
		if state.Joint == nil || state.Phase != MembershipLedgerJointCommittedNotCertified &&
			state.Phase != MembershipLedgerJointFinalizationOnly {
			return errors.New("[D112 joint QC] Joint 尚未 durable commit")
		}
		attestation := wire.JointConfigAttestationForEntry(&state.Joint.Body, state.Joint.EntryHash)
		qc := wire.JointConfigQC(attestation, signatures, &state.Candidate.OldControlSet, &state.Candidate.NewControlSet)
		if err := wire.VerifyJointConfigQC(&state.Joint.Body, state.Joint.EntryHash,
			&state.Candidate.OldControlSet, &state.Candidate.NewControlSet, &qc); err != nil {
			return err
		}
		proof := wire.JointControlSetProofV1{Schema: 1, JointBody: state.Joint.Body,
			JointEntryHash: state.Joint.EntryHash, JointReplicationQC: qc}
		if _, err := wire.JointControlSetProofHash(&proof, &state.Candidate.OldControlSet,
			&state.Candidate.NewControlSet); err != nil {
			return err
		}
		if state.Joint.Proof != nil && !wire.EqualCanonical(*state.Joint.Proof, proof) {
			return errors.New("[D112 joint QC] 已认证 Joint proof 的 bytes 不能改变")
		}
		state.Joint.Proof = &proof
		state.Phase = MembershipLedgerJointFinalizationOnly
		return nil
	})
}

func (ledger *MembershipLedger) RecordFinalCommitFromRaft(storage *RaftStorage, head wire.HeadEntryV2,
	expectedSnapshotHash, expectedEffectiveSSOTHash string) error {
	return ledger.update(func(state *MembershipLedgerStateV1) error {
		if state.Final != nil {
			reference, err := committedMembershipRecordReference(storage, &state.Candidate.OldControlSet,
				&state.Candidate.NewControlSet,
				head.Body.Payload.RaftIndex, head.EntryHash, RaftRecordHead, &head, nil)
			if err == nil && wire.EqualCanonical(state.Final.Head, head) && state.Final.RaftCommit != nil &&
				wire.EqualCanonical(*state.Final.RaftCommit, *reference) &&
				state.Final.ExpectedSnapshotHash == expectedSnapshotHash &&
				state.Final.ExpectedEffectiveSSOTHash == expectedEffectiveSSOTHash {
				return nil
			}
			return errors.New("[D112 Final] 已记录的 Final commit 不能被改写")
		}
		if state.Phase != MembershipLedgerJointFinalizationOnly || state.Joint == nil || state.Joint.Proof == nil {
			return errors.New("[D112 Final] 只能紧接 certified Joint")
		}
		if _, err := wire.VerifyControlSetFinalCandidate(&state.Candidate.OldControlSet,
			&state.Candidate.NewControlSet, &state.Candidate.MembershipApprovalProof,
			state.Joint.Proof, &head, &state.Candidate.ParentCurrent.Head); err != nil {
			return err
		}
		if err := wire.VerifyControlSetTransitionMaterialization(&head, expectedSnapshotHash,
			expectedEffectiveSSOTHash); err != nil {
			return err
		}
		reference, err := committedMembershipRecordReference(storage, &state.Candidate.OldControlSet,
			&state.Candidate.NewControlSet,
			head.Body.Payload.RaftIndex, head.EntryHash, RaftRecordHead, &head, nil)
		if err != nil {
			return err
		}
		state.Final = &MembershipFinalCommitV1{Head: head, RaftCommit: reference,
			ExpectedSnapshotHash: expectedSnapshotHash, ExpectedEffectiveSSOTHash: expectedEffectiveSSOTHash}
		state.Phase = MembershipLedgerFinalCommittedNotCertified
		return nil
	})
}

func (ledger *MembershipLedger) CertifyFinal(signatures []wire.ControlConfigSignatureV1) (wire.ControlSetTransitionBundleV1, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	state := cloneMembershipLedgerState(ledger.state)
	if state.Phase == MembershipLedgerFinal && state.CertifiedBundle != nil {
		qc := wire.JointHeadQC(&state.Final.Head, signatures, &state.Candidate.OldControlSet, &state.Candidate.NewControlSet)
		if state.Final.QC != nil && wire.EqualCanonical(*state.Final.QC, qc) {
			return *state.CertifiedBundle, nil
		}
		return wire.ControlSetTransitionBundleV1{}, errors.New("[D112 Final QC] 已认证 Final QC bytes 不能改变")
	}
	if state.Phase != MembershipLedgerFinalCommittedNotCertified || state.Joint == nil ||
		state.Joint.Proof == nil || state.Final == nil {
		return wire.ControlSetTransitionBundleV1{}, errors.New("[D112 Final QC] Final 尚未 durable commit")
	}
	qc := wire.JointHeadQC(&state.Final.Head, signatures, &state.Candidate.OldControlSet, &state.Candidate.NewControlSet)
	if err := wire.VerifyJointHeadQC(&state.Final.Head, &state.Candidate.OldControlSet,
		&state.Candidate.NewControlSet, &qc); err != nil {
		return wire.ControlSetTransitionBundleV1{}, err
	}
	bundle := wire.ControlSetTransitionBundleV1{Schema: 1, OldControlSet: state.Candidate.OldControlSet,
		NewControlSet: state.Candidate.NewControlSet, MembershipApprovalProof: state.Candidate.MembershipApprovalProof,
		JointProof: *state.Joint.Proof, Final: wire.FinalControlSetHeadV1{Schema: 1,
			Head: state.Final.Head, FinalJointReplicationQC: qc}}
	if _, err := wire.VerifyControlSetTransitionBundle(&bundle, &state.Candidate.ParentCurrent.Head); err != nil {
		return wire.ControlSetTransitionBundleV1{}, err
	}
	state.Final.QC = &qc
	state.CertifiedBundle = &bundle
	state.Phase = MembershipLedgerFinal
	if err := ledger.persistLocked(state); err != nil {
		return wire.ControlSetTransitionBundleV1{}, err
	}
	ledger.state = state
	return bundle, nil
}

func (ledger *MembershipLedger) update(change func(*MembershipLedgerStateV1) error) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	candidate := cloneMembershipLedgerState(ledger.state)
	if err := change(&candidate); err != nil {
		return err
	}
	if err := ledger.persistLocked(candidate); err != nil {
		return err
	}
	ledger.state = candidate
	return nil
}

func certifyLearners(parent wire.SignedCurrentV2, oldSet, newSet wire.ControlSetV1,
	newDirectory wire.ControlPeerDirectoryPrivateObjectV1, directoryObjectHash string,
	evidence map[string]CandidateEvidence, identities map[string]VerifiedDeviceIdentityV1) ([]CertifiedLearnerEvidenceV1, error) {
	oldMembers := make(map[string]struct{}, len(oldSet.Members))
	for _, member := range oldSet.Members {
		oldMembers[member.MemberID] = struct{}{}
	}
	directoryMembers := make(map[string]wire.ControlPeerDirectoryMemberV1, len(newDirectory.Directory.Members))
	for _, member := range newDirectory.Directory.Members {
		directoryMembers[member.MemberID] = member
	}
	learners := make([]CertifiedLearnerEvidenceV1, 0)
	for _, member := range newSet.Members {
		if _, exists := oldMembers[member.MemberID]; exists {
			continue
		}
		directoryMember := directoryMembers[member.MemberID]
		candidate, ok := evidence[member.MemberID]
		identity, identityOK := identities[directoryMember.DeviceID]
		if !ok || !identityOK || !candidate.OverlayReachable || candidate.DeviceID != directoryMember.DeviceID ||
			identity.IdentityStatus() != "active" || identity.DeviceID() != candidate.DeviceID ||
			candidate.InstalledHeadHash != parent.Head.HeadHash || candidate.LastLogIndex < 0 ||
			identity.authority.Head.HeadHash != parent.Head.HeadHash {
			return nil, fmt.Errorf("[D100 ControlSet] candidate %s 尚非 current active/reachable Device", member.MemberID)
		}
		if candidate.DeviceCertificateHash != identity.CertificateHash() ||
			candidate.InstalledDirectoryObjectHash != directoryObjectHash {
			return nil, fmt.Errorf("[D124 learner] candidate %s 未安装 exact identity/directory", member.MemberID)
		}
		learners = append(learners, CertifiedLearnerEvidenceV1{MemberID: member.MemberID,
			DeviceID: candidate.DeviceID, DeviceCertificateHash: candidate.DeviceCertificateHash,
			OverlayReachable: true, InstalledHeadHash: candidate.InstalledHeadHash,
			InstalledLogIndex: candidate.LastLogIndex, InstalledDirectoryObjectHash: directoryObjectHash})
	}
	if len(evidence) != len(learners) {
		return nil, errors.New("[D112 learner] evidence 含非新增 member 或缺失新增 member")
	}
	return learners, nil
}

func validateMembershipLedgerState(state *MembershipLedgerStateV1) error {
	if state == nil || state.Schema != 2 || !validMembershipLedgerPhase(state.Phase) {
		return errors.New("[D112 membership ledger] state header/phase 无效")
	}
	if err := validateMembershipLedgerCandidate(&state.Candidate); err != nil {
		return err
	}
	switch state.Phase {
	case MembershipLedgerCandidate, MembershipLedgerLearners:
		if state.Joint != nil || state.Final != nil || state.CertifiedBundle != nil {
			return errors.New("[D112 membership ledger] pre-Joint state 含未来结果")
		}
	case MembershipLedgerJointCommittedNotCertified, MembershipLedgerJointFinalizationOnly,
		MembershipLedgerFinalCommittedNotCertified, MembershipLedgerFinal:
		if err := validateMembershipJoint(state); err != nil {
			return err
		}
	}
	if state.Phase == MembershipLedgerJointCommittedNotCertified {
		if state.Joint.Proof != nil || state.Final != nil || state.CertifiedBundle != nil {
			return errors.New("[D112 joint QC] committed-not-certified state 含未来结果")
		}
		return nil
	}
	if state.Phase == MembershipLedgerJointFinalizationOnly {
		if state.Joint.Proof == nil || state.Final != nil || state.CertifiedBundle != nil {
			return errors.New("[D112 joint] finalization-only state 不完整")
		}
		return validateMembershipJointProof(state)
	}
	if state.Phase == MembershipLedgerFinalCommittedNotCertified || state.Phase == MembershipLedgerFinal {
		if err := validateMembershipJointProof(state); err != nil {
			return err
		}
		if err := validateMembershipFinal(state); err != nil {
			return err
		}
	}
	if state.Phase == MembershipLedgerFinalCommittedNotCertified {
		if state.Final.QC != nil || state.CertifiedBundle != nil {
			return errors.New("[D112 Final QC] committed-not-certified state 含 QC/bundle")
		}
		return nil
	}
	if state.Phase == MembershipLedgerFinal {
		if state.Final.QC == nil || state.CertifiedBundle == nil {
			return errors.New("[D112 Final QC] Final state 缺 QC/bundle")
		}
		want := wire.ControlSetTransitionBundleV1{Schema: 1, OldControlSet: state.Candidate.OldControlSet,
			NewControlSet: state.Candidate.NewControlSet, MembershipApprovalProof: state.Candidate.MembershipApprovalProof,
			JointProof: *state.Joint.Proof, Final: wire.FinalControlSetHeadV1{Schema: 1,
				Head: state.Final.Head, FinalJointReplicationQC: *state.Final.QC}}
		if !wire.EqualCanonical(*state.CertifiedBundle, want) {
			return errors.New("[D112 Final QC] certified bundle 与 ledger fields 不一致")
		}
		_, err := wire.VerifyControlSetTransitionBundle(state.CertifiedBundle, &state.Candidate.ParentCurrent.Head)
		return err
	}
	return nil
}

func validateMembershipLedgerCandidate(candidate *MembershipLedgerCandidateV1) error {
	if candidate == nil || candidate.Schema != 1 || candidate.ParentCurrent.Schema != 2 {
		return errors.New("[D112 membership ledger] candidate schema/current 无效")
	}
	validatedAt, err := wire.ParseTimeZ(candidate.ValidatedAt)
	if err != nil {
		return err
	}
	if _, err := wire.ParseTimeZ(candidate.ParentCurrent.PublishedAt); err != nil {
		return err
	}
	parent := &candidate.ParentCurrent.Head
	if err := wire.VerifyConfigQCAuthority(parent.HeadHash, candidate.ParentCurrent.QuorumCertificate,
		parent, &candidate.OldControlSet, candidate.ParentPreviousControlSet); err != nil {
		return err
	}
	if err := wire.VerifyControlMembershipApprovalProof(&candidate.MembershipApprovalProof,
		&candidate.OldControlSet, &candidate.NewControlSet, parent); err != nil {
		return err
	}
	if err := validateMembershipDirectory(&candidate.OldControlSet, &candidate.OldDirectoryObject,
		candidate.OldDirectoryObjectHash, validatedAt); err != nil {
		return err
	}
	if err := validateMembershipDirectory(&candidate.NewControlSet, &candidate.NewDirectoryObject,
		candidate.NewDirectoryObjectHash, validatedAt); err != nil {
		return err
	}
	oldDirectory := &candidate.OldDirectoryObject.Directory
	newDirectory := &candidate.NewDirectoryObject.Directory
	if candidate.OldDirectoryObject.ControlPeerDirectoryHash != parent.Body.Payload.ControlPeerDirectoryHash ||
		candidate.NewDirectoryObject.ControlPeerDirectoryHash != candidate.MembershipApprovalProof.Intent.NewControlPeerDirectoryHash ||
		oldDirectory.DirectoryGeneration == int64(^uint64(0)>>1) ||
		newDirectory.DirectoryGeneration != oldDirectory.DirectoryGeneration+1 ||
		newDirectory.HidingNonce == oldDirectory.HidingNonce {
		return errors.New("[D124 private directory] old/new generation、nonce 或 parent binding 无效")
	}
	scope := wire.AdminResourceScopeV1{ScopeKind: "control_membership", ControlMembership: &struct{}{}}
	scopeHash, _ := wire.AdminResourceScopeHash(&scope)
	if candidate.AdminScopeHash != scopeHash {
		return errors.New("[D104 membership ledger] admin scope marker 无效")
	}
	oldMembers := make(map[string]struct{}, len(candidate.OldControlSet.Members))
	for _, member := range candidate.OldControlSet.Members {
		oldMembers[member.MemberID] = struct{}{}
	}
	wantLearners := make([]string, 0)
	for _, member := range candidate.NewControlSet.Members {
		if _, exists := oldMembers[member.MemberID]; !exists {
			wantLearners = append(wantLearners, member.MemberID)
		}
	}
	if len(candidate.Learners) != len(wantLearners) {
		return errors.New("[D112 learner] learner 集合未 exact-match 新增 members")
	}
	directoryMembers := make(map[string]wire.ControlPeerDirectoryMemberV1, len(newDirectory.Members))
	for _, member := range newDirectory.Members {
		directoryMembers[member.MemberID] = member
	}
	for i := range candidate.Learners {
		learner := &candidate.Learners[i]
		if learner.MemberID != wantLearners[i] || learner.DeviceID != directoryMembers[learner.MemberID].DeviceID ||
			!learner.OverlayReachable || learner.InstalledHeadHash != parent.HeadHash || learner.InstalledLogIndex < 0 ||
			learner.InstalledDirectoryObjectHash != candidate.NewDirectoryObjectHash {
			return errors.New("[D112 learner] learner identity/head/directory 投影无效")
		}
		for _, hash := range []string{learner.DeviceCertificateHash, learner.InstalledHeadHash,
			learner.InstalledDirectoryObjectHash} {
			if _, err := wire.ParseHash(hash); err != nil {
				return err
			}
		}
		if learner.CaughtUp {
			if learner.CaughtUpThroughIndex < parent.Body.Payload.RaftIndex || learner.CheckpointHash == "" {
				return errors.New("[D112 learner] caught-up learner 缺 checkpoint/连续坐标")
			}
			if _, err := wire.ParseHash(learner.CheckpointHash); err != nil {
				return err
			}
		} else if learner.CaughtUpThroughIndex != 0 || learner.CheckpointHash != "" {
			return errors.New("[D112 learner] 未 catch-up learner 含完成结果")
		}
	}
	return nil
}

func validateMembershipDirectory(set *wire.ControlSetV1, object *wire.ControlPeerDirectoryPrivateObjectV1,
	wantObjectHash string, trustedTime time.Time) error {
	if err := wire.ValidateControlPeerDirectoryPrivateObject(set, object); err != nil {
		return err
	}
	if err := wire.ValidateControlPeerDirectoryAt(set, &object.Directory, trustedTime); err != nil {
		return err
	}
	got, err := wire.ControlPeerDirectoryPrivateObjectHash(set, object)
	if err != nil || got != wantObjectHash {
		return errors.New("[D124 private directory] private object hash 不匹配")
	}
	return nil
}

func validateMembershipJoint(state *MembershipLedgerStateV1) error {
	if state.Joint == nil || state.Joint.RaftCommit == nil {
		return errors.New("[D112 joint] ledger 缺 Joint commit")
	}
	entryHash, err := wire.VerifyJointControlSetCandidate(&state.Candidate.OldControlSet,
		&state.Candidate.NewControlSet, &state.Candidate.MembershipApprovalProof, &state.Joint.Body,
		&state.Candidate.ParentCurrent.Head)
	if err != nil || entryHash != state.Joint.EntryHash {
		return errors.New("[D112 joint] ledger Joint entry/hash 无效")
	}
	return validateMembershipCommitReference(state.Joint.RaftCommit, &state.Candidate.OldControlSet,
		&state.Candidate.NewControlSet,
		state.Joint.Body.RaftTerm, state.Joint.Body.RaftIndex, state.Joint.EntryHash)
}

func validateMembershipJointProof(state *MembershipLedgerStateV1) error {
	if state.Joint == nil || state.Joint.Proof == nil ||
		!wire.EqualCanonical(state.Joint.Proof.JointBody, state.Joint.Body) ||
		state.Joint.Proof.JointEntryHash != state.Joint.EntryHash {
		return errors.New("[D112 joint QC] ledger Joint proof binding 无效")
	}
	_, err := wire.JointControlSetProofHash(state.Joint.Proof, &state.Candidate.OldControlSet,
		&state.Candidate.NewControlSet)
	return err
}

func validateMembershipFinal(state *MembershipLedgerStateV1) error {
	if state.Final == nil || state.Final.RaftCommit == nil {
		return errors.New("[D112 Final] ledger 缺 Final commit")
	}
	if _, err := wire.VerifyControlSetFinalCandidate(&state.Candidate.OldControlSet,
		&state.Candidate.NewControlSet, &state.Candidate.MembershipApprovalProof, state.Joint.Proof,
		&state.Final.Head, &state.Candidate.ParentCurrent.Head); err != nil {
		return err
	}
	if err := wire.VerifyControlSetTransitionMaterialization(&state.Final.Head,
		state.Final.ExpectedSnapshotHash, state.Final.ExpectedEffectiveSSOTHash); err != nil {
		return err
	}
	return validateMembershipCommitReference(state.Final.RaftCommit, &state.Candidate.OldControlSet,
		&state.Candidate.NewControlSet,
		state.Final.Head.Body.Payload.RaftTerm, state.Final.Head.Body.Payload.RaftIndex,
		state.Final.Head.EntryHash)
}

func committedMembershipRecordReference(storage *RaftStorage, oldSet, newSet *wire.ControlSetV1,
	index int64, entryHash, kind string, head *wire.HeadEntryV2,
	joint *wire.JointControlSetEntryBodyV1) (*RaftCommitReferenceV1, error) {
	if storage == nil || oldSet == nil || newSet == nil {
		return nil, errors.New("[D112 joint Raft] commit 必须绑定本机 Raft storage/old ControlSet")
	}
	raft := storage.SnapshotRaft()
	oldHash, oldErr := wire.ControlSetHash(oldSet)
	storageHash, storageErr := wire.ControlSetHash(&storage.set)
	if oldErr != nil || storageErr != nil || oldHash != storageHash || raft.ClusterID != oldSet.ClusterID ||
		!controlSetContains(oldSet, raft.MemberID) && !controlSetContains(newSet, raft.MemberID) ||
		index < 1 || index > raft.CommitIndex ||
		index > int64(len(raft.Log)) {
		return nil, errors.New("[D112 joint Raft] membership entry 不在本机 committed prefix")
	}
	record := raft.Log[index-1]
	if record.Kind != kind || record.Term < 1 || record.Index != index || record.EntryHash != entryHash {
		return nil, errors.New("[D112 joint Raft] committed membership record 坐标/hash/kind 不匹配")
	}
	switch kind {
	case RaftRecordJointControlSet:
		if joint == nil || record.JointControlSet == nil || !wire.EqualCanonical(*record.JointControlSet, *joint) {
			return nil, errors.New("[D112 joint Raft] committed Joint payload 不匹配")
		}
	case RaftRecordHead:
		if head == nil || record.Head == nil || head.Body.Payload.HeadKind != "control_set_final" ||
			!wire.EqualCanonical(*record.Head, *head) {
			return nil, errors.New("[D112 joint Raft] committed Final payload 不匹配")
		}
	default:
		return nil, errors.New("[D112 joint Raft] membership commit record kind 无效")
	}
	return &RaftCommitReferenceV1{Schema: 1, ClusterID: raft.ClusterID, MemberID: raft.MemberID,
		Term: record.Term, Index: record.Index, EntryHash: record.EntryHash}, nil
}

func validateMembershipCommitReference(reference *RaftCommitReferenceV1, oldSet, newSet *wire.ControlSetV1,
	term, index int64, entryHash string) error {
	if reference == nil || reference.Schema != 1 || reference.ClusterID != oldSet.ClusterID ||
		!controlSetContains(oldSet, reference.MemberID) && !controlSetContains(newSet, reference.MemberID) ||
		reference.Term != term ||
		reference.Index != index || reference.EntryHash != entryHash {
		return errors.New("[D112 joint Raft] durable commit reference 无效")
	}
	return nil
}

func canonicalJointMembers(candidate *MembershipLedgerCandidateV1, memberIDs []string) ([]string, error) {
	values := append([]string(nil), memberIDs...)
	sort.Strings(values)
	union := make(map[string]struct{}, len(candidate.OldControlSet.Members)+len(candidate.NewControlSet.Members))
	for _, set := range []*wire.ControlSetV1{&candidate.OldControlSet, &candidate.NewControlSet} {
		for _, member := range set.Members {
			union[member.MemberID] = struct{}{}
		}
	}
	for i, value := range values {
		if _, exists := union[value]; !exists || i > 0 && values[i-1] == value {
			return nil, errors.New("[D112 joint] durable ack 含未知或重复 member")
		}
	}
	if err := wire.JointQuorum(&candidate.OldControlSet, &candidate.NewControlSet, values); err != nil {
		return nil, err
	}
	return values, nil
}

func validMembershipLedgerPhase(phase MembershipLedgerPhase) bool {
	switch phase {
	case MembershipLedgerCandidate, MembershipLedgerLearners, MembershipLedgerJointCommittedNotCertified,
		MembershipLedgerJointFinalizationOnly, MembershipLedgerFinalCommittedNotCertified, MembershipLedgerFinal:
		return true
	default:
		return false
	}
}

func (ledger *MembershipLedger) persistLocked(state MembershipLedgerStateV1) error {
	if err := validateMembershipLedgerState(&state); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(ledger.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, filepath.Base(ledger.path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(body)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, ledger.path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func cloneMembershipLedgerState(state MembershipLedgerStateV1) MembershipLedgerStateV1 {
	body, _ := wire.MarshalCanonical(state)
	var clone MembershipLedgerStateV1
	_, _ = wire.DecodeStrict(body, 64<<20, &clone)
	return clone
}

func cloneControlSetPointer(set *wire.ControlSetV1) *wire.ControlSetV1 {
	if set == nil {
		return nil
	}
	body, _ := json.Marshal(set)
	var clone wire.ControlSetV1
	_ = json.Unmarshal(body, &clone)
	return &clone
}
