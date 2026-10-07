package control

import (
	"net/http/httptest"
	"os"
	"testing"
)

func TestControlMemberBrowserUsesMajorityAndReadsCommittedTable(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	f := newMaterialFixture(t)
	peers := membershipTLSPeers(t, f)
	server := httptest.NewServer(peers[0].server.AdminHandler())
	defer server.Close()
	debug := openCommandChrome(t, server.URL+"/settings")
	waitChromeEvaluation(t, debug, `document.querySelectorAll('#control-members tbody tr').length===2&&document.querySelector('#member-change-form')`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#member-change-form');f.elements.node.value='demo-node-b';f.elements.change.value='revoke';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('#control-members tbody tr').length===1&&document.querySelector('#member-change-form [role=alert]').textContent.includes('certificate accepted')`)
	proof, err := peers[0].server.Runtime.Authority.ControlProof()
	if err != nil || len(proof.Successors) != 1 || proof.Successors[0].Config.Operation != "revoke" {
		t.Fatal("browser did not persist the original majority decision", err)
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#member-change-form');f.elements.change.value='resign';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#member-change-form [role=alert]').textContent.includes('last control')`)
	if !peers[0].server.Runtime.Writable() {
		t.Fatal("rejected browser removal stopped the last member")
	}
}

func TestControlMemberBrowserGrantsAndRevokesOnlyOrdinaryRoles(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t, func(invite *Invite) {
		invite.DeviceID, invite.Medium = "demo-pure-member", "sh"
		invite.Responsibilities, invite.PolicyIDs = []string{"control"}, []string{}
	})
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != 200 {
		t.Fatal("member claim failed")
	}
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/devices/"+invite.DeviceID)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form')`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#device-policy-form');f.querySelector('[name=responsibility][value=access]').click();f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('.device-heading')?.textContent.includes('access + control')&&!document.querySelector('#device-policy-form').submitting`)
	grants := server.Runtime.Authority.Snapshot().DeviceAuthorizations
	if len(grants) != 1 || grants[0].DevicePublicKey != claim.DevicePublicKey {
		t.Fatal("browser first grant failed to preserve the proven member identity")
	}
	root := grants[0].RuntimeKey
	chromeDo(t, debug, `(()=>{window.confirm=()=>true;document.querySelector('#device-policy-form [data-revoke-device]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form button[type=submit]')?.textContent==='Grant ordinary authorization'&&document.body.innerText.includes('Control membership remains active.')`)
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || len(view.View.Responsibilities) != 1 || view.View.Responsibilities[0] != "control" {
		t.Fatal("ordinary revocation changed membership", err)
	}
	chromeDo(t, debug, `(()=>{document.querySelector('#device-policy-form').requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form [data-revoke-device]')`)
	grants = server.Runtime.Authority.Snapshot().DeviceAuthorizations
	if len(grants) != 1 || grants[0].RuntimeKey != root {
		t.Fatal("browser regrant replaced the device's credential root")
	}
}
