package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWebChromeRevokedDeviceReviewAndExplicitRegrant(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	server, invite, _, claim, _, policyDependencies := enrollmentAuthorityFixture(t, func(invite *Invite) {
		invite.DNSServers = []string{"192.0.2.53"}
	})
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("demo device did not join")
	}
	original := server.Runtime.Authority.Snapshot().DeviceAuthorizations[0]
	prior, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	public := DevicePut{ID: invite.DeviceID, Name: "Demo revised device", Responsibilities: []string{"access"},
		PolicyIDs: append([]string{}, original.PolicyIDs...), DistributionURLs: []string{"https://downloads.example/"}, DNSServers: []string{"192.0.2.54"}}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-revise-before-revoke", Operation: "device.put", TargetKind: "device", TargetID: public.ID,
		Dependencies: sortedUniqueDependencies(append(policyDependencies, prior.MaterialIDs...)), Payload: public})
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/devices/"+invite.DeviceID)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form [data-revoke-device]')`)
	chromeDo(t, debug, `(()=>{window.confirm=()=>true;document.querySelector('#device-policy-form [data-revoke-device]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form button[type=submit]')?.textContent==='Grant ordinary authorization'`)
	projection := server.Runtime.Authority.Snapshot()
	target, _ := projection.CurrentTarget("device", invite.DeviceID)
	if len(projection.DeviceAuthorizations) != 0 || target.DeviceForReview == nil || !reflect.DeepEqual(*target.DeviceForReview, public) {
		t.Fatal("revocation did not retain the last public configuration solely for review")
	}
	if _, err := server.deviceEnvelope(invite.DeviceID); err == nil {
		t.Fatal("review value authorized a device view")
	}
	if chromeDo(t, debug, `(()=>{const f=document.querySelector('#device-policy-form');return f.elements.name.value==='Demo revised device'&&f.elements.dns_servers.value==='192.0.2.54'&&f.elements.distribution_urls.value==='https://downloads.example/'&&!f.querySelector('[data-revoke-device]')&&document.body.innerText.includes('Not authorized')})()`) != true {
		t.Fatal("review form used the Invite's obsolete fields or concealed revocation")
	}
	web := buildWebSnapshot(projection, true, true, true)
	body, err := json.Marshal(web)
	if err != nil || strings.Contains(string(body), "runtime_key") || strings.Contains(string(body), original.RuntimeKey) || strings.Contains(string(body), "device_public_key") {
		t.Fatal("public review leaked identity or runtime credentials")
	}
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := reopened.Snapshot().CurrentTarget("device", invite.DeviceID)
	if len(reopened.Snapshot().DeviceAuthorizations) != 0 || !reflect.DeepEqual(target, restarted) {
		t.Fatal("restart changed revoked history or restored authorization")
	}
	dependencies, _ := json.Marshal(target.MaterialIDs)
	if chromeDo(t, debug, `(()=>{const f=document.querySelector('#device-policy-form'),t=JSON.parse(f.dataset.targets).find(v=>v.target_kind==='device'&&v.target_id===f.dataset.deviceId);return JSON.stringify(t.material_ids)===JSON.stringify(`+string(dependencies)+`)})()`) != true {
		t.Fatal("review form did not bind the current revocation")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('#device-policy-form').requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form [data-revoke-device]')`)
	reopened, err = OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	grants := reopened.Snapshot().DeviceAuthorizations
	if len(grants) != 1 {
		t.Fatal("explicit browser regrant did not persist")
	}
	want := original
	want.Name, want.Responsibilities, want.PolicyIDs, want.DistributionURLs, want.DNSServers = public.Name, public.Responsibilities, public.PolicyIDs, public.DistributionURLs, public.DNSServers
	if !reflect.DeepEqual(grants[0], want) {
		t.Fatal("regrant changed immutable identity or discarded reviewed public settings")
	}
	current, _ := reopened.Snapshot().CurrentTarget("device", invite.DeviceID)
	if current.DeviceForReview != nil {
		t.Fatal("active device retained a revoked review value")
	}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-permanent-device-delete", Operation: "device.delete", TargetKind: "device", TargetID: public.ID,
		Dependencies: current.MaterialIDs, Payload: DeleteTarget{ID: public.ID}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := debug.call(ctx, "Page.navigate", map[string]any{"url": httpServer.URL + "/devices/" + invite.DeviceID}, nil); err != nil {
		t.Fatal(err)
	}
	waitChromeEvaluation(t, debug, `document.querySelector('#app .device-heading')&&document.querySelector('#connection').textContent.includes('local writes available')&&!document.querySelector('#device-policy-form')`)
}
