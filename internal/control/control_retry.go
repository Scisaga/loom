package control

import (
	"context"
	"sort"
	"time"
)

func requestForControlProposal(config ControlConfig, baseID string) ControlChangeRequest {
	request := ControlChangeRequest{Schema: 3, BaseConfigID: baseID, Operation: config.Operation, TargetNodeID: config.TargetNodeID}
	if config.Join != nil {
		request.TransactionID = config.Join.TransactionID
	}
	if config.Invalidation != nil {
		request.TransactionID, request.Reason = config.Invalidation.TransactionID, config.Invalidation.Reason
	}
	if config.Operation == "rotate" {
		for _, member := range config.Members {
			if member.NodeID == config.TargetNodeID {
				request.PublicKey = member.PublicKey
			}
		}
	}
	return request
}

// Retry derives work from an original local vote or a verified bound Invite.
// It does not persist request phases, infer completion from files, or restart
// a completed member transaction after its invitation's expiry.
func (a *Authority) pendingControlChange(ctx context.Context, local NodeConfig, now time.Time) (*ControlChangeRequest, error) {
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err = a.reloadLocked(); err != nil {
		return nil, err
	}
	if _, err = activeLocalMember(local, a.projection.Config); err != nil {
		return nil, nil
	}
	_, votes, err := a.localMemberMessages(a.projection.Config, local)
	if err != nil {
		return nil, err
	}
	var request *ControlChangeRequest
	if len(votes) > 0 {
		last := votes[len(votes)-1]
		if last.Vote.Round.ProposerControlID == local.ControlID {
			value := requestForControlProposal(last.Proposal, a.projection.ControlConfigID)
			request = &value
		}
	}
	if request == nil {
		invites := append([]Invite{}, a.projection.Invites...)
		sort.Slice(invites, func(i, j int) bool { return invites[i].ID < invites[j].ID })
		for _, invite := range invites {
			if invite.IssuerControlID != local.ControlID || !containsString(invite.Responsibilities, "control") {
				continue
			}
			state, err := a.enrollmentStateLocked(invite.ID)
			if err != nil || state != "bound" {
				continue
			}
			original, err := a.inviteLocked(invite.ID)
			if err != nil || !a.memberEnrollmentLocked(original) {
				continue
			}
			request = &ControlChangeRequest{Schema: 3, BaseConfigID: a.projection.ControlConfigID, Operation: "add", TargetNodeID: invite.DeviceID, TransactionID: invite.ID}
			break
		}
	}
	if request != nil && request.Operation == "add" {
		if original, err := a.inviteLocked(request.TransactionID); err == nil && !now.Before(time.UnixMilli(original.Payload.(Invite).ExpiresAt)) {
			request.Operation, request.Reason = "invalidate_join", "expired"
		}
	}
	return request, nil
}

func (runtime *Runtime) ReconcileControlChanges(ctx context.Context, now time.Time) error {
	request, err := runtime.Authority.pendingControlChange(ctx, runtime.Config, now)
	if err != nil || request == nil {
		return err
	}
	_, err = runtime.ChangeControl(ctx, *request, now)
	return err
}
