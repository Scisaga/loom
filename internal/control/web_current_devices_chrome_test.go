package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestWebChromeCurrentDevicesFollowSignedLifecycle(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for current inventory acceptance")
	}
	fixture, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	host := httptest.NewServer(fixture.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/")
	waitChromeEvaluation(t, debug, `document.querySelector('#app h1')&&document.querySelector('#connection').title.includes('local writes available')`)
	for _, state := range []string{"open", "bound", "cancelled", "expired", "completed", "revoked", "deleted", "conflicted"} {
		t.Run(state, func(t *testing.T) {
			server, invite, materialID, claim, _, dependencies := enrollmentAuthorityFixture(t)
			switch state {
			case "bound":
				binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: materialID, ClaimRequestID: claim.RequestID, DevicePublicKey: claim.DevicePublicKey, Platform: claim.Platform}
				submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-bind-current-inventory", Operation: "invite.bind", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(append(dependencies, materialID)), Payload: binding})
			case "cancelled", "expired":
				termination := EnrollmentTermination{TransactionID: invite.ID, InviteMaterialID: materialID}
				operation := "invite.cancel"
				if state == "expired" {
					operation = "invite.expire"
					termination.ExpiredAt = &invite.ExpiresAt
					server.Now = func() time.Time { return time.UnixMilli(invite.ExpiresAt) }
				}
				submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-terminate-current-inventory", Operation: operation, TargetKind: "invite", TargetID: invite.ID, Dependencies: []string{materialID}, Payload: termination})
			case "completed", "revoked", "deleted":
				if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
					t.Fatal("normal join failed")
				}
				if state != "completed" {
					target, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
					operation := "device.revoke"
					if state == "deleted" {
						operation = "device.delete"
					}
					submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-withdraw-current-inventory", Operation: operation, TargetKind: "device", TargetID: invite.DeviceID, Dependencies: target.MaterialIDs, Payload: DeleteTarget{ID: invite.DeviceID}})
				}
			}
			projection := server.Runtime.Authority.Snapshot()
			if state == "conflicted" {
				for i := range projection.Targets {
					if projection.Targets[i].TargetKind == "invite" {
						projection.Targets[i].Conflicted = true
					}
				}
			}
			snapshot := buildWebSnapshot(projection, true, true, true)
			body, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := json.Marshal(invite.DeviceID)
			want := state != "cancelled" && state != "expired" && state != "deleted"
			result := chromeDo(t, debug, `(async()=>{const {currentDevices}=await import('/assets/model.js');const source=`+string(body)+`,before=JSON.stringify(source),devices=currentDevices(source);return devices.some(v=>v.id===`+string(id)+`)===`+map[bool]string{true: "true", false: "false"}[want]+`&&JSON.stringify(source)===before})()`)
			if result != true {
				t.Fatal("current inventory disagrees with the signed lifecycle or rewrites history", state)
			}
		})
	}
}
