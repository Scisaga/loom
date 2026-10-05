package control

import (
	"sort"
	"time"
)

// WebPolicyInvite describes a pending reference, never an enrollment capability.
// Completed devices are counted from their current authorization instead.
type WebPolicyInvite struct {
	ID        string   `json:"id"`
	DeviceID  string   `json:"device_id"`
	PolicyIDs []string `json:"policy_ids"`
	ExpiresAt int64    `json:"expires_at"`
	State     string   `json:"state"`
}

func projectWebPolicyInvites(projection Projection, now time.Time) []WebPolicyInvite {
	result := []WebPolicyInvite{}
	for _, invite := range projection.Invites {
		target, found := projection.CurrentTarget("invite", invite.ID)
		if !found || target.Deleted || target.Conflicted || len(target.MaterialIDs) != 1 {
			continue
		}
		// A joined identity retains a device target after revoke/delete/conflict.
		// Its old binding must not resurrect a pending invitation reference.
		if _, joined := projection.CurrentTarget("device", invite.DeviceID); joined {
			continue
		}
		state := "open"
		for _, binding := range projection.Bindings {
			if binding.TransactionID == invite.ID {
				state = "bound"
				break
			}
		}
		if state == "open" && !now.Before(time.UnixMilli(invite.ExpiresAt)) {
			continue
		}
		result = append(result, WebPolicyInvite{ID: invite.ID, DeviceID: invite.DeviceID,
			PolicyIDs: append([]string{}, invite.PolicyIDs...), ExpiresAt: invite.ExpiresAt, State: state})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
