package control

import (
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestWebPolicyInviteReferencesFollowEnrollment(t *testing.T) {
	for _, state := range []string{"open", "expired", "bound", "completed", "revoked", "cancelled", "conflicted"} {
		t.Run(state, func(t *testing.T) {
			server, invite, id, claim, _, dependencies := enrollmentAuthorityFixture(t)
			now := server.now()
			switch state {
			case "expired":
				now = time.UnixMilli(invite.ExpiresAt)
			case "bound":
				binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: id, ClaimRequestID: claim.RequestID, DevicePublicKey: claim.DevicePublicKey, Platform: claim.Platform}
				submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: enrollmentRequestID("bind", invite.ID), Operation: "invite.bind", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(append(dependencies, id)), Payload: binding})
				now = time.UnixMilli(invite.ExpiresAt).Add(time.Hour)
			case "completed", "revoked":
				if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
					t.Fatal("device join failed")
				}
				if state == "revoked" {
					target, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
					submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-revoke", Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: target.MaterialIDs, Payload: DeleteTarget{ID: invite.DeviceID}})
				}
			case "cancelled":
				submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-cancel", Operation: "invite.cancel", TargetKind: "invite", TargetID: invite.ID, Dependencies: []string{id}, Payload: EnrollmentTermination{TransactionID: invite.ID, InviteMaterialID: id}})
			}
			projection := server.Runtime.Authority.Snapshot()
			if state == "conflicted" {
				for i := range projection.Targets {
					if projection.Targets[i].TargetKind == "invite" {
						projection.Targets[i].Conflicted = true
					}
				}
			}
			want := []WebPolicyInvite{}
			if state == "open" || state == "bound" {
				want = append(want, WebPolicyInvite{ID: invite.ID, DeviceID: invite.DeviceID, PolicyIDs: invite.PolicyIDs, ExpiresAt: invite.ExpiresAt, State: state})
			}
			if got := projectWebPolicyInvites(projection, now); !reflect.DeepEqual(got, want) {
				t.Fatalf("reference %s: got %+v, want %+v", state, got, want)
			}
		})
	}
}
