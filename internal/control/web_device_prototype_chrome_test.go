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

func TestWebChromeDeviceSectionsAndPolicyTags(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for native device interaction acceptance")
	}
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("join failed")
	}
	p := server.Runtime.Authority.Snapshot()
	policy := p.NetworkIntent.Policies[0]
	policy.ID, policy.Name, policy.Action = "demo-replacement-policy", "Demo replacement", "deny"
	service, _ := p.CurrentTarget("service", policy.ServiceID)
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-create-alternative", Operation: "policy.put", TargetKind: "policy", TargetID: policy.ID, Dependencies: service.MaterialIDs, Payload: policy})
	before := server.Runtime.Authority.Frontier()
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/devices/"+invite.DeviceID)
	waitChromeEvaluation(t, debug, `document.querySelector('.device-layout')&&document.querySelectorAll('[data-device-panel]:not([hidden])').length===1`)
	if chromeDo(t, debug, `document.querySelectorAll('.device-sidebar .device-section-link').length===3&&!document.querySelector('[data-device-panel=forward]')&&!document.querySelector('#app .card')`) != true {
		t.Fatal("pure access received a different identity page or forwarding panel")
	}
	chromeDo(t, debug, `(()=>{window.demoDraft=document.querySelector('#device-policy-form');demoDraft.elements.name.value='Demo unsaved name';document.querySelector('[data-device-section=access]').click();document.querySelector('#device-authorization-draft').open=true;return true})()`)
	if chromeDo(t, debug, `demoDraft===document.querySelector('#device-policy-form')&&demoDraft.elements.name.value==='Demo unsaved name'&&document.querySelectorAll('[data-device-panel]:not([hidden])').length===1`) != true {
		t.Fatal("section navigation discarded the draft or mixed panels")
	}
	chromeDo(t, debug, `(()=>{window.confirm=()=>false;const picker=demoDraft.querySelector('.policy-picker');picker.querySelector('details').open=true;const search=picker.querySelector('[data-policy-search]');search.value='Demo replacement';search.dispatchEvent(new Event('input',{bubbles:true}));search.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));return true})()`)
	if chromeDo(t, debug, `demoDraft.querySelector('[name=policy_id][value=demo-policy]').checked&&!demoDraft.querySelector('[value=demo-replacement-policy]').checked`) != true {
		t.Fatal("replacement bypassed confirmation")
	}
	chromeDo(t, debug, `(()=>{window.confirm=()=>true;demoDraft.querySelector('[value=demo-replacement-policy]').click();return true})()`)
	if chromeDo(t, debug, `demoDraft.querySelectorAll('[name=policy_id]:checked').length===1&&demoDraft.querySelector('.policy-picker details').open&&demoDraft.querySelector('[data-selected-policy-summary]').textContent.includes('Deny this service')`) != true {
		t.Fatal("tags stacked policies for one service, closed continuous selection, or hid deny")
	}
	chromeDo(t, debug, `(()=>{window.confirm=()=>false;demoDraft.querySelector('[name=responsibility][value=access]').click();return true})()`)
	if chromeDo(t, debug, `demoDraft.querySelector('[name=responsibility][value=access]').checked&&demoDraft.querySelector('[value=demo-replacement-policy]').checked`) != true {
		t.Fatal("removing access discarded policies without confirmation")
	}
	chromeDo(t, debug, `(()=>{window.confirm=()=>true;demoDraft.querySelector('[name=responsibility][value=access]').click();document.querySelector('[data-device-section=identity]').click();history.back();return true})()`)
	waitChromeEvaluation(t, debug, `location.search==='?section=access'&&document.querySelector('[data-device-panel=access]')?.hidden===false`)
	if chromeDo(t, debug, `demoDraft===document.querySelector('#device-policy-form')&&demoDraft.querySelectorAll('[name=policy_id]:checked').length===0&&demoDraft.querySelector('[data-device-access]').hidden`) != true || !reflect.DeepEqual(before, server.Runtime.Authority.Frontier()) {
		t.Fatal("draft selection or browser navigation wrote authority or lost input")
	}
}

func TestWebChromeReaddUsesPermanentDeletionAndExactInvitationRetry(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for native replacement acceptance")
	}
	fixture := newEndpointFixture(t)
	server := fixture.server
	bootstrap, _, _ := fixture.join(t, "old-access")
	invite := bootstrap.Material.Payload.(Invite)
	handler := server.AdminHandler()
	var mu sync.Mutex
	var attempts [][]byte
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/control/operations" {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			op, err := DecodeOperation(body)
			if err == nil && op.Operation == "invite.issue" {
				mu.Lock()
				attempts = append(attempts, append([]byte{}, body...))
				first := len(attempts) == 1
				mu.Unlock()
				if first {
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, r)
					if response.Code != http.StatusOK {
						t.Errorf("replacement invitation failed: %s", response.Body.String())
					}
					http.Error(w, "Demo response lost after issuing", http.StatusBadGateway)
					return
				}
			}
		}
		handler.ServeHTTP(w, r)
	}))
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/devices?new=1&replace="+invite.DeviceID)
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-form[data-replace-id]')`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#enrollment-form');f.elements.device_id.value='demo-readded-device';f.elements.name.value='Demo readded';f.elements.confirm_replace.checked=true;f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-status')?.textContent.includes('Old identity permanently deleted locally; new invitation is not confirmed')`)
	beforeRetry := server.Runtime.Authority.Frontier()
	old, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	if !old.Deleted || old.DeviceForReview != nil {
		t.Fatal("replacement proceeded without a permanent tombstone")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('#enrollment-form').requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `location.pathname.startsWith('/devices/invites/')&&document.querySelector('#invite-uri')`)
	mu.Lock()
	same := len(attempts) == 2 && bytes.Equal(attempts[0], attempts[1])
	mu.Unlock()
	if !same || !reflect.DeepEqual(beforeRetry, server.Runtime.Authority.Frontier()) {
		t.Fatal("replacement retry reissued identity or changed canonical bytes")
	}
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	p := reopened.Snapshot()
	old, _ = p.CurrentTarget("device", invite.DeviceID)
	if !old.Deleted || old.DeviceForReview != nil || len(p.DeviceAuthorizations) != 0 {
		t.Fatal("restart revived the old identity or granted the unclaimed replacement")
	}
	mu.Lock()
	op, err := DecodeOperation(attempts[0])
	mu.Unlock()
	if err != nil || !containsString(op.Dependencies, old.MaterialIDs[0]) {
		t.Fatal("new invitation did not depend on the verified deletion", err)
	}
	if chromeDo(t, debug, `document.querySelector('#device-enrollment').textContent.includes('demo-readded-device')&&document.querySelector('#device-enrollment [data-enrollment-state]').textContent==='open'`) != true {
		t.Fatal("delivery did not read the new unclaimed identity")
	}
	encoded, _ := chromeDo(t, debug, `document.querySelector('#invite-uri').value`).(string)
	replacement, err := DecodeInvite(encoded)
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	material, _ := MaterialID(replacement.Material)
	newClaim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 3, NetworkID: server.Config.NetworkID, GenesisDigest: server.Config.GenesisID, TransactionID: replacement.Material.TargetID, InviteMaterialID: material, RequestID: "demo-readded-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Platform: "linux"}, key)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := endpointPost(t, fixture.dialBootstrap(t, replacement), "/enrollment/claim", newClaim)
	if status != http.StatusOK {
		t.Fatal("replacement failed to join through the real bootstrap transport")
	}
	view, err := server.deviceEnvelope("demo-readded-device")
	if err != nil || view.View.DevicePublicKey != newClaim.DevicePublicKey || len(view.View.Routes) != 0 || view.View.RuntimeProfile == nil {
		t.Fatal("new identity did not obtain its deny-only runtime configuration", err)
	}
	if _, err := server.deviceEnvelope(invite.DeviceID); err == nil {
		t.Fatal("replacement restored authorization for the deleted identity")
	}
}
