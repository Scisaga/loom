package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type demoSSHChoices struct{}

func (demoSSHChoices) Targets() ([]string, error) { return []string{"demo-one", "demo-two"}, nil }
func (demoSSHChoices) Resolve(context.Context, string) (SSHTargetReadback, error) {
	return SSHTargetReadback{}, errors.New("unexpected transport")
}
func (demoSSHChoices) Run(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("unexpected transport")
}

func TestChromeSSHTargetEditsRequireNewInspectionAndPreserveExistingIdentity(t *testing.T) {
	server, invite, id, claim, _, _ := enrollmentAuthorityFixture(t)
	server.SSH = demoSSHChoices{}
	var checks, submissions atomic.Int32
	admin := server.AdminHandler()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/control/ui/ssh/check" {
			body, err := boundedBody(w, r)
			var request sshCheckRequest
			if err != nil || DecodeCanonical(body, &request, ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 4, MaxItems: 16}) != nil {
				http.Error(w, "invalid check", 400)
				return
			}
			inspection := InstallationReadback{Platform: "linux", Architecture: "amd64", CanInstall: true}
			if checks.Add(1) > 1 {
				inspection.Identity = &DeviceIdentityReadback{NetworkID: claim.NetworkID, GenesisDigest: claim.GenesisDigest, DeviceID: invite.DeviceID, TransactionID: invite.ID, InviteMaterialID: id, ClaimRequestID: claim.RequestID, DevicePublicKey: claim.DevicePublicKey, Platform: "linux"}
			}
			writeJSON(w, 200, SSHInspection{Target: SSHTargetReadback{Alias: request.Target, ResolvedHost: "demo-target.example", ResolvedPort: 2222, ConfiguredHost: "192.0.2.20", ConfiguredPort: 2222, CoordinatesDiffer: true}, Installation: inspection})
			return
		}
		if r.URL.Path == "/api/control/operations" {
			submissions.Add(1)
		}
		admin.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/devices?new=1")
	waitChromeEvaluation(t, debug, `!!document.querySelector('#enrollment-form [data-ssh-target]')`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#enrollment-form');f.elements.name.value='Demo SSH device';f.querySelector('[value=forward]').click();f.elements.ssh_target.value='demo-one';f.elements.ssh_target.dispatchEvent(new Event('change',{bubbles:true}));f.querySelector('[data-ssh-check]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-ssh-check-result]').textContent.includes('No existing device identity')`)
	if chromeDo(t, debug, `document.querySelector('[data-ssh-check-result]').textContent.includes('SSH resolves to demo-target.example:2222')`) != true {
		t.Fatal("coordinate discrepancy hidden")
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#enrollment-form');f.querySelector('[value=internet_egress]').click();f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-status').textContent.includes('Check the selected SSH target')`)
	if submissions.Load() != 0 {
		t.Fatal("changed responsibilities reused old inspection")
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#enrollment-form');f.elements.ssh_target.value='demo-two';f.elements.ssh_target.dispatchEvent(new Event('change',{bubbles:true}));f.querySelector('[data-ssh-check]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-ssh-check-result]').textContent.includes('Existing device:')`)
	chromeDo(t, debug, `(()=>{document.querySelector('#enrollment-form').requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-status').textContent.includes('Manage the existing device')`)
	if submissions.Load() != 0 || checks.Load() != 2 {
		t.Fatal("existing identity was issued another invitation")
	}
	if chromeDo(t, debug, `document.querySelector('[data-ssh-check-result] a').getAttribute('href')`) != "/devices/"+invite.DeviceID {
		t.Fatal("existing device management lost its stable identity")
	}
}
