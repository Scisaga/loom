package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func membershipTLSPeers(t *testing.T, f materialFixture) []reportTestPeer {
	peers, _ := membershipTLSPeersWithCA(t, f, -1)
	return peers
}

func membershipTLSPeersWithCA(t *testing.T, f materialFixture, dropProofOn int) ([]reportTestPeer, transportCA) {
	return membershipTLSPeersWithHandler(t, f, dropProofOn, nil)
}

func membershipTLSPeersWithHandler(t *testing.T, f materialFixture, dropProofOn int, wrap func(int, http.Handler) http.Handler) ([]reportTestPeer, transportCA) {
	t.Helper()
	a, configs := materialAuthorities(t, f)
	parent := t.TempDir()
	ca := testTransportCA(t, parent)
	addresses := make([]string, len(f.members))
	for i := range addresses {
		addresses[i] = testLoopbackAddress(t)
	}
	peers := []reportTestPeer{}
	for i, member := range f.members {
		files, _, _ := testTransportIdentity(t, parent, member.ControlID, int64(i+10), f.keys[i], ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		browser, _, _ := testTransportIdentity(t, parent, member.ControlID+"-browser", int64(i+20), testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		configs[i].PeerTLS = &files
		configs[i].BrowserTLS = &browser
		body, _ := CanonicalEncode(configs[i])
		if err := atomicWrite(filepath.Join(a[i].root, "node.json"), body); err != nil {
			t.Fatal(err)
		}
		runtime, err := OpenRuntime(a[i].root, nil)
		if err != nil {
			t.Fatal(err)
		}
		privatePeers := []PrivatePeer{}
		for j, peer := range f.members {
			if i != j {
				privatePeers = append(privatePeers, PrivatePeer{Node: peer.NodeID, Addresses: []string{addresses[j]}})
			}
		}
		channel, err := OpenPrivateChannel(PrivateChannelConfig{Schema: 3, Node: member.NodeID, Listen: []string{addresses[i]}, Peers: privatePeers}, configs[i])
		if err != nil {
			t.Fatal(err)
		}
		channel.AttachAuthority(runtime.Authority)
		runtime.Channel = channel
		server := &Server{Runtime: runtime, Channel: channel, Config: configs[i]}
		handler := server.Handler()
		if i == dropProofOn {
			next := handler
			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut && r.URL.Path == "/internal/control-proof" {
					http.Error(w, "demo lost certificate delivery", http.StatusServiceUnavailable)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
		if wrap != nil {
			handler = wrap(i, handler)
		}
		httpServer := &http.Server{Handler: handler, ConnContext: controlConnContext, ReadHeaderTimeout: time.Second}
		go httpServer.Serve(channel.ControlListener())
		peers = append(peers, reportTestPeer{server, channel, httpServer})
	}
	t.Cleanup(func() {
		for _, peer := range peers {
			peer.close()
		}
	})
	return peers, ca
}

func memberAdminHTTP(t *testing.T, server *Server, request ControlChangeRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := CanonicalEncode(request)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/control/members", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), adminContextKey{}, true))
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	return w
}

func TestControlMemberCoordinatorRequiresOldMajorityAndTerminatesBoundJoin(t *testing.T) {
	f := newMaterialFixture(t)
	peers := membershipTLSPeers(t, f)
	server, invite, inviteID, claim, _, _ := enrollmentFixtureWithRuntime(t, peers[0].server.Runtime, func(invite *Invite) {
		invite.DeviceID, invite.Medium = "demo-new-control", "sh"
		invite.Responsibilities, invite.PolicyIDs = []string{"control"}, []string{}
	})
	server.Channel = peers[0].channel
	// N=2 has no one-member shortcut. The original bound claim survives a
	// failed collection and cannot terminate through an ordinary fact.
	peers[1].channel.Close()
	response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite))
	var result EnrollmentResponse
	if response.Code != http.StatusOK || DecodeCanonical(response.Body.Bytes(), &result, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 128, MaxItems: 1 << 16}) != nil || result.State != "bound" || result.DeviceView != nil {
		t.Fatal("one of two members manufactured completion")
	}
	binding, found, err := server.Runtime.Authority.Binding(invite.ID)
	if err != nil || !found {
		t.Fatal("failed majority lost its proven claim")
	}
	target, _ := server.Runtime.Authority.Snapshot().CurrentTarget("invite", invite.ID)
	cancel := Operation{Schema: 3, RequestID: "demo-ordinary-cancel", Operation: "invite.cancel", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(append(target.MaterialIDs, inviteID)), Payload: EnrollmentTermination{TransactionID: invite.ID, InviteMaterialID: inviteID}}
	if _, _, err = server.HandleOperation(context.Background(), cancel); err == nil {
		t.Fatal("ordinary cancellation bypassed member majority")
	}
	old := peers[1]
	channel, err := OpenPrivateChannel(old.channel.config, old.server.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	channel.AttachAuthority(old.server.Runtime.Authority)
	old.server.Runtime.Channel, old.server.Channel = channel, channel
	httpServer := &http.Server{Handler: old.server.Handler(), ConnContext: controlConnContext, ReadHeaderTimeout: time.Second}
	defer httpServer.Close()
	go httpServer.Serve(channel.ControlListener())
	change := ControlChangeRequest{Schema: 3, BaseConfigID: server.Runtime.Authority.Snapshot().ControlConfigID, Operation: "invalidate_join", TargetNodeID: invite.DeviceID, TransactionID: invite.ID, Reason: "cancelled"}
	response = memberAdminHTTP(t, server, change)
	if response.Code != http.StatusOK {
		t.Fatalf("majority cancellation failed: %s", response.Body.String())
	}
	var changed ControlChangeResult
	if err = DecodeCanonical(response.Body.Bytes(), &changed, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil || !changed.RequestedChangeApplied {
		t.Fatalf("cancellation result: %v", err)
	}
	for _, runtime := range []*Runtime{server.Runtime, old.server.Runtime} {
		state, err := runtime.Authority.EnrollmentState(invite.ID)
		if err != nil || state != "cancelled" || len(runtime.Authority.Snapshot().Config.Members) != 2 {
			t.Fatalf("termination was not consumed by both members: %s %v", state, err)
		}
	}
	if original, _, _ := server.Runtime.Authority.Binding(invite.ID); original != binding {
		t.Fatal("majority cancellation changed the bound identity")
	}
	if response = memberAdminHTTP(t, server, change); response.Code != http.StatusOK {
		t.Fatal("same reviewed base did not recover the original decision")
	}
}

func TestControlMemberInvalidRetirementDoesNotStopSigner(t *testing.T) {
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	base := server.Runtime.Authority.Snapshot().ControlConfigID
	for _, operation := range []string{"resign", "revoke", "delete"} {
		response := memberAdminHTTP(t, server, ControlChangeRequest{Schema: 3, BaseConfigID: base, Operation: operation, TargetNodeID: server.Config.NodeID})
		if response.Code == http.StatusOK || !server.Runtime.Writable() {
			t.Fatal("last-member failure stopped or removed the signer")
		}
	}
	public, _ := testKey(t).Public().(ed25519.PublicKey)
	response := memberAdminHTTP(t, server, ControlChangeRequest{Schema: 3, BaseConfigID: base, Operation: "rotate", TargetNodeID: server.Config.NodeID, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	if response.Code == http.StatusOK || !server.Runtime.Writable() {
		t.Fatal("unowned key or missing TLS materials stopped the original signer")
	}
}

func TestControlMemberTLSVotingAndLostRemovalNotification(t *testing.T) {
	f := newMaterialFixture(t)
	peers := membershipTLSPeers(t, f)
	a, b := peers[0].server.Runtime, peers[1].server.Runtime
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first, err := a.Authority.BeginControlRound(ctx, a.Config)
	if err != nil {
		t.Fatal(err)
	}
	request := ControlPrepareRequest{Schema: 3, BaseConfigID: f.configID, Round: first.Round}
	spoofed := request
	spoofed.Round.ProposerControlID = f.members[1].ControlID
	body, _ := CanonicalEncode(spoofed)
	if _, err = a.peerBody(ctx, f.members[1], http.MethodPost, "/internal/control-prepare", body); err == nil {
		t.Fatal("member TLS identity did not bind the round proposer")
	}
	body, _ = CanonicalEncode(request)
	var second ControlPromise
	if err = a.peerJSON(ctx, f.members[1], http.MethodPost, "/internal/control-prepare", body, &second); err != nil {
		t.Fatal(err)
	}
	promises := []ControlPromise{first, second}
	config := emptyRemoval(f, promises, 1)
	localVote, err := a.Authority.VoteControl(ctx, config, first.Round, promises, a.Config, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	vr := ControlVoteRequest{Schema: 3, Config: config, Round: first.Round, Promises: promises}
	body, _ = CanonicalEncode(vr)
	var remoteVote ControlVote
	if err = a.peerJSON(ctx, f.members[1], http.MethodPost, "/internal/control-vote", body, &remoteVote); err != nil {
		t.Fatal(err)
	}
	cert := ControlCertificate{Config: config, Round: first.Round, Promises: promises, Votes: []ControlVote{localVote, remoteVote}}
	body, _ = CanonicalEncode(cert)
	if err = a.Authority.AcceptControlCertificate(ctx, body, a.Config); err != nil {
		t.Fatal(err)
	}
	// The removal notification was lost. The old identity must be able to learn
	// its original stopping proof, while every privileged operation is denied.
	proofBody, err := b.peerBody(ctx, f.members[0], http.MethodGet, "/internal/control-proof", nil)
	if err != nil {
		t.Fatalf("removed member cannot retrieve its stopping proof: %v", err)
	}
	var proof ControlProof
	if err = DecodeCanonical(proofBody, &proof, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 128, MaxItems: 1 << 16}); err != nil || len(proof.Successors) != 1 {
		t.Fatalf("returned proof is incomplete: %v", err)
	}
	for _, path := range []string{"/internal/frontier", "/internal/material-conflicts", "/internal/materials?key_id=demo", "/internal/report-ranges", "/internal/control-proof?extra=1"} {
		if _, err = b.peerBody(ctx, f.members[0], http.MethodGet, path, nil); err == nil {
			t.Fatalf("historical identity acquired privileged read %s", path)
		}
	}
	for _, path := range []string{"/internal/control-prepare", "/internal/control-vote", "/internal/reports"} {
		if _, err = b.peerBody(ctx, f.members[0], http.MethodPost, path, []byte("{}")); err == nil {
			t.Fatalf("historical identity retained privileged write %s", path)
		}
	}
	if err = b.reconcileControlProof(ctx, f.members[0]); err != nil {
		t.Fatalf("lost-notification recovery did not apply its original proof: %v", err)
	}
	if b.Writable() || len(b.Authority.Snapshot().Config.Members) != 1 {
		t.Fatal("removed member did not stop ordinary authority after learning certificate")
	}
	if _, err = a.Submit(ctx, mustOperationBytes(t, authorityService("demo-retained-write", "demo-request"))); err != nil {
		t.Fatal(err)
	}
}

func mustOperationBytes(t *testing.T, op Operation) []byte {
	t.Helper()
	body, err := EncodeOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
