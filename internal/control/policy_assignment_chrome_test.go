package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
)

func TestWebChromePolicyCopyPreservesAssignmentDraftAndSharedSource(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	server, invite, _, claim, _, dependencies := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("first join failed")
	}
	otherInvite := invite
	otherInvite.ID, otherInvite.DeviceID = "demo-other-invite", "demo-other-device"
	endpoint, _ := server.Runtime.Authority.Snapshot().CurrentTarget("endpoint", invite.Endpoint.ID)
	issued := submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-other-invite", Operation: "invite.issue", TargetKind: "invite", TargetID: otherInvite.ID, Dependencies: sortedUniqueDependencies(append(dependencies, endpoint.MaterialIDs...)), Payload: otherInvite})
	key := testKey(t)
	otherClaim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 3, NetworkID: server.Config.NetworkID, GenesisDigest: server.Config.GenesisID, TransactionID: otherInvite.ID, InviteMaterialID: issued.MaterialID, RequestID: "demo-other-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Platform: "linux"}, key)
	if err != nil {
		t.Fatal(err)
	}
	if response := enrollmentHTTP(t, server, "/enrollment/claim", otherClaim, enrollmentTunnel(otherInvite)); response.Code != http.StatusOK {
		t.Fatal("second join failed")
	}
	before := server.Runtime.Authority.Snapshot()
	source := before.NetworkIntent.Policies[0]
	original := before.DeviceAuthorizations[0]
	other := before.DeviceAuthorizations[1]
	handler := server.AdminHandler()
	var mu sync.Mutex
	var copyRequests [][]byte
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/control/operations" {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			op, err := DecodeOperation(body)
			if err == nil && op.Operation == "policy.put" && op.TargetID == "demo-copied-policy" {
				mu.Lock()
				copyRequests = append(copyRequests, append([]byte{}, body...))
				first := len(copyRequests) == 1
				mu.Unlock()
				if first {
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, r)
					if response.Code != http.StatusOK {
						t.Errorf("copy was not accepted: %s", response.Body.String())
					}
					http.Error(w, "Demo response lost after saving Policy", http.StatusBadGateway)
					return
				}
			}
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/policies?policy=demo-policy")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-policy-impact]')?.textContent.includes('2 authorized device(s)')`)
	chromeDo(t, debug, `(()=>{history.pushState({},'','/devices/demo-access');dispatchEvent(new PopStateEvent('popstate'));window.demoParent=document.querySelector('#device-policy-form');demoParent.elements.name.value='Demo draft retained';demoParent.elements.dns_servers.value='192.0.2.54';window.demoTargets=demoParent.dataset.targets;demoParent.querySelector('[data-copy-policy="demo-policy"]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#policy-form [name=id]')?.value===''`)
	if chromeDo(t, debug, `(()=>{const f=document.querySelector('#policy-form');return f.elements.service_id.disabled&&f.elements.service_id.value==='demo-service'&&f.elements.allow_direct.checked&&f.elements.action.value==='allow'})()`) != true {
		t.Fatal("copy lost source Service or rules")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('[data-return-policy]').click();return true})()`)
	if chromeDo(t, debug, `demoParent===document.querySelector('#device-policy-form')&&demoParent.dataset.targets===demoTargets&&demoParent.elements.name.value==='Demo draft retained'&&demoParent.elements.dns_servers.value==='192.0.2.54'`) != true || !reflect.DeepEqual(before.Frontier, server.Runtime.Authority.Frontier()) {
		t.Fatal("cancel discarded the parent draft or changed authority")
	}
	chromeDo(t, debug, `(()=>{demoParent.querySelector('[data-copy-policy="demo-policy"]').click();const f=document.querySelector('#policy-form');f.elements.id.value='demo-policy';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#operation-status').textContent.includes('unused ID')`)
	if !reflect.DeepEqual(before.Frontier, server.Runtime.Authority.Frontier()) {
		t.Fatal("copy ID collision changed the source")
	}
	// Another operator updates this device while its public draft is detached.
	target, _ := before.CurrentTarget("device", original.ID)
	edit := DevicePut{ID: original.ID, Name: "Demo concurrent name", Responsibilities: original.Responsibilities, PolicyIDs: original.PolicyIDs, DistributionURLs: original.DistributionURLs}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-concurrent-device", Operation: "device.put", TargetKind: "device", TargetID: original.ID, Dependencies: sortedUniqueDependencies(append(dependencies, target.MaterialIDs...)), Payload: edit})
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#policy-form');f.elements.id.value='demo-copied-policy';f.elements.name.value='Demo single device';f.elements.action.value='deny';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#operation-status').textContent==='Demo response lost after saving Policy'`)
	copyFrontier := server.Runtime.Authority.Frontier()
	chromeDo(t, debug, `(()=>{document.querySelector('#policy-form').requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `location.pathname==='/devices/demo-access'&&document.querySelector('#device-policy-form [role=alert]')?.textContent.includes('Policy saved')`)
	mu.Lock()
	same := len(copyRequests) == 2 && bytes.Equal(copyRequests[0], copyRequests[1])
	mu.Unlock()
	if !same || !reflect.DeepEqual(copyFrontier, server.Runtime.Authority.Frontier()) {
		t.Fatal("copy retry signed another Policy or changed request bytes")
	}
	if chromeDo(t, debug, `(()=>{const f=document.querySelector('#device-policy-form');return f===demoParent&&f.elements.name.value==='Demo draft retained'&&f.elements.dns_servers.value==='192.0.2.54'&&f.querySelector('[name=policy_id][value=demo-copied-policy]').checked&&!f.querySelector('[name=policy_id][value=demo-policy]').checked&&JSON.stringify(JSON.parse(f.dataset.targets).find(v=>v.target_kind==='device'&&v.target_id==='demo-access'))===JSON.stringify(JSON.parse(demoTargets).find(v=>v.target_kind==='device'&&v.target_id==='demo-access'))})()`) != true {
		t.Fatal("return changed the device baseline or lost draft fields/selection")
	}
	chromeDo(t, debug, `(()=>{demoParent.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form [role=alert]').textContent.includes('stale')`)
	projection := server.Runtime.Authority.Snapshot()
	if len(projection.NetworkIntent.Policies) != 2 || projection.DeviceAuthorizations[0].Name != edit.Name || !reflect.DeepEqual(projection.DeviceAuthorizations[0].PolicyIDs, original.PolicyIDs) || !reflect.DeepEqual(projection.DeviceAuthorizations[1], other) {
		t.Fatal("failed assignment changed authority or lost the saved Policy")
	}
	// Review the current device explicitly and select the already saved copy.
	chromeDo(t, debug, `(()=>{location.reload();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form [name=name]')?.value==='Demo concurrent name'`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#device-policy-form');f.querySelector('[name=policy_id][value=demo-copied-policy]').click();f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')`)
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	projection = reopened.Snapshot()
	for _, policy := range projection.NetworkIntent.Policies {
		if policy.ID == source.ID && !reflect.DeepEqual(policy, source) {
			t.Fatal("single device change edited the shared Policy")
		}
	}
	if !reflect.DeepEqual(projection.DeviceAuthorizations[1], other) || projection.DeviceAuthorizations[0].RuntimeKey != original.RuntimeKey || projection.DeviceAuthorizations[0].DevicePublicKey != original.DevicePublicKey {
		t.Fatal("single device assignment changed another device or identity")
	}
	denied, err := ProjectDeviceView(projection, original.ID)
	if err != nil || len(denied.Routes) != 0 || !reflect.DeepEqual(denied.PolicyIDs, []string{"demo-copied-policy"}) {
		t.Fatal("saved deny assignment did not reach the device view", err)
	}
	allowed, err := ProjectDeviceView(projection, other.ID)
	if err != nil || len(allowed.Routes) == 0 {
		t.Fatal("other device lost its existing allowed route", err)
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/policies?policy=demo-missing');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	if chromeDo(t, debug, `!document.querySelector('#policy-form')&&document.body.textContent.includes('This Policy is unavailable')`) != true {
		t.Fatal("unknown Policy silently opened a different Policy")
	}
}

func TestWebChromeNewPolicyReturnsToOriginalInvitation(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	fixture := newEndpointFixture(t)
	server := fixture.server
	submitAuthority(t, server.Runtime, authorityService("demo-service", "demo-service"))
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/devices?new=1")
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-form [name=endpoint]')?.options.length>0`)
	chromeDo(t, debug, `(()=>{window.demoParent=document.querySelector('#enrollment-form');demoParent.elements.device_id.value='demo-new-device';demoParent.elements.name.value='Demo invitation draft';demoParent.elements.dns_servers.value='192.0.2.53';window.demoTransaction=demoParent.dataset.transactionId;demoParent.querySelector('[data-new-device-policy]').click();const f=document.querySelector('#policy-form');f.elements.id.value='demo-new-policy';f.elements.name.value='Demo new policy';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-form [role=alert]')?.textContent.includes('Policy saved')`)
	if chromeDo(t, debug, `(()=>{const f=document.querySelector('#enrollment-form');return f===demoParent&&f.dataset.transactionId===demoTransaction&&f.elements.name.value==='Demo invitation draft'&&f.elements.dns_servers.value==='192.0.2.53'&&f.querySelector('[name=policy_id][value=demo-new-policy]').checked})()`) != true || len(server.Runtime.Authority.Snapshot().Invites) != 0 {
		t.Fatal("Policy creation submitted the invitation or discarded its draft")
	}
	chromeDo(t, debug, `(()=>{demoParent.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `location.pathname==='/devices/invites/'+demoTransaction&&document.querySelector('[data-enrollment-state]')?.textContent==='open'`)
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	projection := reopened.Snapshot()
	if len(projection.Invites) != 1 || !reflect.DeepEqual(projection.Invites[0].PolicyIDs, []string{"demo-new-policy"}) || projection.Invites[0].DeviceID != "demo-new-device" || len(projection.DeviceAuthorizations) != 0 {
		t.Fatal("invitation lost its saved Policy or gained device authorization")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/policies?policy=demo-new-policy');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-policy-impact]')?.textContent.includes('0 authorized device(s) · 1 pending invitation(s)')`)
	chromeDo(t, debug, `(()=>{history.pushState({},'','/services?service=demo-service');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	if chromeDo(t, debug, `document.querySelector('[data-policy-impact]').textContent.includes('demo-new-device')&&document.querySelector('a[href="/policies?new=1&service=demo-service"]')!==null`) != true {
		t.Fatal("Service omitted its Policy's pending invitation or creation context")
	}
}
