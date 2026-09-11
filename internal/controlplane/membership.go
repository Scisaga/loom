package controlplane

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"loom/internal/wire"
)

type MembershipPhase string

const (
	MembershipCandidate MembershipPhase = "candidate"
	MembershipLearner   MembershipPhase = "learner"
	MembershipJoint     MembershipPhase = "joint"
	MembershipFinal     MembershipPhase = "final"
)

type CandidateEvidence struct {
	DeviceID          string `json:"device_id"`
	ActiveDevice      bool   `json:"active_device"`
	OverlayReachable  bool   `json:"overlay_reachable"`
	InstalledHeadHash string `json:"installed_head_hash"`
	LastLogIndex      int64  `json:"last_log_index"`
}

type LearnerState struct {
	MemberID       string            `json:"member_id"`
	Evidence       CandidateEvidence `json:"evidence"`
	CaughtUp       bool              `json:"caught_up"`
	CheckpointHash string            `json:"checkpoint_hash,omitempty"`
}

type MembershipTransition struct {
	Schema       int                         `json:"schema"`
	TransitionID string                      `json:"transition_id"`
	Phase        MembershipPhase             `json:"phase"`
	OldSet       wire.ControlSetV1           `json:"old_set"`
	NewSet       wire.ControlSetV1           `json:"new_set"`
	NewDirectory wire.ControlPeerDirectoryV1 `json:"new_directory"`
	Learners     []LearnerState              `json:"learners"`
	JointSigners []string                    `json:"joint_signers,omitempty"`
}

// NewMembershipTransition 要求新增 voter 先是已入网且能经 overlay 到达的 Device，
// 并用调用方注入的认证逻辑时间检查新目录证书，避免成员变更接纳过期身份（D112/D124）。
func NewMembershipTransition(transitionID string, oldSet, newSet wire.ControlSetV1, directory wire.ControlPeerDirectoryV1, evidence map[string]CandidateEvidence, trustedTime time.Time) (*MembershipTransition, error) {
	if transitionID == "" {
		return nil, errors.New("[D112 joint] transition ID 不能为空")
	}
	if err := wire.ValidateControlSet(&oldSet); err != nil {
		return nil, err
	}
	if err := wire.ValidateControlSet(&newSet); err != nil {
		return nil, err
	}
	if err := wire.ValidateControlPeerDirectoryAt(&newSet, &directory, trustedTime); err != nil {
		return nil, err
	}
	oldMembers := make(map[string]struct{}, len(oldSet.Members))
	for _, member := range oldSet.Members {
		oldMembers[member.MemberID] = struct{}{}
	}
	learners := make([]LearnerState, 0)
	for _, member := range newSet.Members {
		if _, existing := oldMembers[member.MemberID]; existing {
			continue
		}
		candidate, ok := evidence[member.MemberID]
		if !ok || !candidate.ActiveDevice || !candidate.OverlayReachable || candidate.DeviceID == "" || candidate.LastLogIndex < 0 {
			return nil, fmt.Errorf("[D100 ControlSet] candidate %s 尚非 active/reachable Device", member.MemberID)
		}
		learners = append(learners, LearnerState{MemberID: member.MemberID, Evidence: candidate})
	}
	return &MembershipTransition{
		Schema: 1, TransitionID: transitionID, Phase: MembershipCandidate,
		OldSet: oldSet, NewSet: newSet, NewDirectory: directory, Learners: learners,
	}, nil
}

func (transition *MembershipTransition) BeginLearners() error {
	if transition.Phase != MembershipCandidate {
		return errors.New("[D112 joint] 只能从 candidate 进入 learner")
	}
	transition.Phase = MembershipLearner
	return nil
}

func (transition *MembershipTransition) MarkCaughtUp(memberID, checkpointHash string, logIndex int64) error {
	if transition.Phase != MembershipLearner {
		return errors.New("[D112 joint] 只有 learner 阶段能记录 catch-up")
	}
	if _, err := wire.ParseHash(checkpointHash); err != nil {
		return err
	}
	for i := range transition.Learners {
		learner := &transition.Learners[i]
		if learner.MemberID != memberID {
			continue
		}
		if logIndex < learner.Evidence.LastLogIndex {
			return errors.New("[D112 joint] learner log index 回退")
		}
		learner.CaughtUp = true
		learner.CheckpointHash = checkpointHash
		learner.Evidence.LastLogIndex = logIndex
		return nil
	}
	return errors.New("[D112 joint] 未知 learner")
}

// CommitJoint 在所有 learner catch-up 后才应用 old/new 双多数规则。
func (transition *MembershipTransition) CommitJoint(signerMemberIDs []string) error {
	if transition.Phase != MembershipLearner && !(transition.Phase == MembershipCandidate && len(transition.Learners) == 0) {
		return errors.New("[D112 joint] transition 尚未处于可提交 learner 状态")
	}
	for _, learner := range transition.Learners {
		if !learner.CaughtUp {
			return fmt.Errorf("[D112 joint] learner %s 尚未 catch-up，不能投票", learner.MemberID)
		}
	}
	if err := wire.JointQuorum(&transition.OldSet, &transition.NewSet, signerMemberIDs); err != nil {
		return err
	}
	transition.JointSigners = append([]string(nil), signerMemberIDs...)
	sort.Strings(transition.JointSigners)
	transition.Phase = MembershipJoint
	return nil
}

func (transition *MembershipTransition) Finalize(signerMemberIDs []string) error {
	if transition.Phase != MembershipJoint {
		return errors.New("[D118 Final] Final 必须紧接已 committed/certified Joint")
	}
	if err := wire.JointQuorum(&transition.OldSet, &transition.NewSet, signerMemberIDs); err != nil {
		return err
	}
	transition.Phase = MembershipFinal
	return nil
}
