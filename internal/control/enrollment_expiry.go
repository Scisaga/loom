package control

import (
	"context"
	"sort"
	"time"
)

// ExpireUnboundInvites signs ordinary termination facts only for this issuer's
// still-unbound invitations. The initial scan has no side effects; every write
// rechecks the original facts under the same lock as the first claim.
func (a *Authority) ExpireUnboundInvites(ctx context.Context, now time.Time, local NodeConfig) (int, error) {
	a.mu.RLock()
	var pending []string
	for _, invite := range a.projection.Invites {
		if invite.IssuerControlID == local.ControlID && !now.Before(time.UnixMilli(invite.ExpiresAt)) {
			if state, err := a.enrollmentStateLocked(invite.ID); err == nil && state == "open" {
				pending = append(pending, invite.ID)
			}
		}
	}
	a.mu.RUnlock()
	sort.Strings(pending)
	count := 0
	for _, id := range pending {
		changed, err := func() (bool, error) {
			lock, err := lockAuthority(ctx, a.root)
			if err != nil {
				return false, err
			}
			defer lock.Close()
			a.mu.Lock()
			defer a.mu.Unlock()
			if err := a.reloadLocked(); err != nil {
				return false, err
			}
			return a.expireUnboundInviteLocked(ctx, id, now, local)
		}()
		if changed {
			count++
		}
		if err != nil {
			return count, err
		}
	}
	return count, nil
}

func (a *Authority) expireUnboundInviteLocked(ctx context.Context, id string, now time.Time, local NodeConfig) (bool, error) {
	original, err := a.inviteLocked(id)
	if err != nil {
		return false, err
	}
	invite := original.Payload.(Invite)
	if invite.IssuerControlID != local.ControlID || now.Before(time.UnixMilli(invite.ExpiresAt)) {
		return false, nil
	}
	state, err := a.enrollmentStateLocked(id)
	if err != nil || state != "open" {
		return false, nil
	}
	if _, bound, err := a.bindingLocked(id); err != nil || bound {
		return false, err
	}
	originalID, _ := MaterialID(original)
	target, _ := a.projection.CurrentTarget("invite", id)
	at := now.UnixMilli()
	termination := EnrollmentTermination{TransactionID: id, InviteMaterialID: originalID, ExpiredAt: &at}
	_, err = a.submitOperationLocked(ctx, Operation{Schema: 3, RequestID: enrollmentRequestID("expire", id),
		Operation: "invite.expire", TargetKind: "invite", TargetID: id,
		Dependencies: sortedUniqueDependencies(append(append([]string{}, target.MaterialIDs...), originalID)), Payload: termination}, local)
	return err == nil, err
}
