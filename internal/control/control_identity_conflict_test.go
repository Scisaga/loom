package control

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestControlMemberLateIdentityConflictAndMajorityInvalidation(t *testing.T) {
	f := newSuccessorFixture(t, 3)
	keyID, _ := KeyID(f.base.Members[0].PublicKey)
	genesis, err := SignMaterial(Material{Schema: 3, NetworkID: f.base.NetworkID, IssuerControlID: f.base.Members[0].ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: Genesis{ControlConfig: f.base, NetworkIntent: EmptyNetworkIntent(), AdminCertificates: []AdminCertificate{}}}, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	authorities, configs := materialAuthorities(t, materialFixture{genesis: genesis, keys: f.keys, members: f.base.Members, configID: f.baseID})
	runtimes := make([]*Runtime, 3)
	for i := range runtimes {
		runtimes[i], err = OpenRuntime(authorities[i].root, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer runtimes[i].Close()
		authorities[i] = runtimes[i].Authority
	}
	server, invite, _, claim, _, _ := enrollmentFixtureWithRuntime(t, runtimes[0], func(invite *Invite) {
		invite.ID, invite.DeviceID, invite.Medium = "demo-first-transaction", "demo-collision-node", "sh"
		invite.Responsibilities, invite.PolicyIDs = []string{"control"}, []string{}
	})
	other, otherInvite, _, otherClaim, _, _ := enrollmentFixtureWithRuntime(t, runtimes[1], func(invite *Invite) {
		invite.ID, invite.DeviceID, invite.Medium = "demo-concurrent-transaction", "demo-collision-node", "sh"
		invite.Responsibilities, invite.PolicyIDs = []string{"control"}, []string{}
	})
	for _, value := range []struct {
		server *Server
		invite Invite
		claim  EnrollmentClaimRequest
	}{{server, invite, claim}, {other, otherInvite, otherClaim}} {
		if _, err = value.server.Runtime.Authority.CompleteEnrollment(context.Background(), value.claim, false, enrollmentTunnel(value.invite), value.server.now(), value.server.Config); err != nil {
			t.Fatal(err)
		}
	}
	copyFacts := func(from, to *Authority) {
		t.Helper()
		for _, material := range from.materials {
			body, _ := CanonicalEncode(material)
			if _, err := to.PutMaterial(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	copyFacts(authorities[0], authorities[2])
	decide := func(request ControlChangeRequest, voters []int) ControlCertificate {
		t.Helper()
		first, err := authorities[0].BeginControlRound(context.Background(), configs[0])
		if err != nil {
			t.Fatal(err)
		}
		promises := []ControlPromise{first}
		for _, i := range voters[1:] {
			reply, err := authorities[i].PrepareControl(context.Background(), request.BaseConfigID, first.Round, configs[i])
			if err != nil {
				t.Fatal(err)
			}
			promises = append(promises, reply)
		}
		proposal, err := authorities[0].controlChangeProposal(request, authorities[0].Snapshot().Config, promises)
		if err != nil {
			t.Fatal(err)
		}
		votes := []ControlVote{}
		for _, i := range voters {
			vote, err := authorities[i].VoteControl(context.Background(), proposal, first.Round, promises, configs[i], server.now())
			if err != nil {
				t.Fatal(err)
			}
			votes = append(votes, vote)
		}
		cert := ControlCertificate{Config: proposal, Round: first.Round, Promises: promises, Votes: votes}
		body, _ := CanonicalEncode(cert)
		for _, i := range voters {
			if err = authorities[i].AcceptControlCertificate(context.Background(), body, configs[i]); err != nil {
				t.Fatal(err)
			}
		}
		return cert
	}
	cert := decide(ControlChangeRequest{Schema: 3, BaseConfigID: f.baseID, Operation: "add", TargetNodeID: invite.DeviceID, TransactionID: invite.ID}, []int{0, 2})
	if _, ok := identityFor(authorities[0].Snapshot(), invite.DeviceID); !ok {
		t.Fatal("certified pure member lost its identity")
	}
	copyFacts(authorities[1], authorities[0])
	if _, ok := identityFor(authorities[0].Snapshot(), invite.DeviceID); ok {
		t.Fatal("late conflicting bound identity still authenticated")
	}
	if len(authorities[0].Snapshot().Config.Members) != 4 {
		t.Fatal("ordinary conflict rolled back the member chain")
	}
	readback := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/control/ui/invites/"+otherInvite.ID, nil)
	server.AdminHandler().ServeHTTP(readback, request)
	var inspected struct {
		State      string `json:"state"`
		Conflicted bool   `json:"identity_conflicted"`
		Member     bool   `json:"member_enrollment"`
		Invite     string `json:"invite"`
	}
	if json.Unmarshal(readback.Body.Bytes(), &inspected) != nil || readback.Code != 200 || inspected.State != "bound" || !inspected.Conflicted || !inspected.Member || inspected.Invite != "" {
		t.Fatal("administrator cannot review the conflicted bound transaction without reopening its invitation")
	}
	copyFacts(authorities[0], authorities[1])
	copyFacts(authorities[0], authorities[2])
	body, _ := CanonicalEncode(cert)
	if err = authorities[1].AcceptControlCertificate(context.Background(), body, configs[1]); err != nil {
		t.Fatal(err)
	}
	decide(ControlChangeRequest{Schema: 3, BaseConfigID: authorities[0].Snapshot().ControlConfigID, Operation: "invalidate_join", TargetNodeID: invite.DeviceID, TransactionID: otherInvite.ID, Reason: "cancelled"}, []int{0, 1, 2})
	for _, a := range authorities {
		if _, ok := identityFor(a.Snapshot(), invite.DeviceID); !ok {
			t.Fatal("majority-invalidated transaction left a stale identity conflict")
		}
		if len(a.Snapshot().Config.Members) != 4 {
			t.Fatal("cancelling a different transaction removed the established member")
		}
		if state, err := a.EnrollmentState(otherInvite.ID); err != nil || state != "cancelled" {
			t.Fatal("invalidation did not preserve exact transaction semantics", err)
		}
	}
}
