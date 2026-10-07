package control

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestControlMemberRunsFromTLSClaimAndOriginalFacts(t *testing.T) {
	f := newEndpointFixture(t)
	a := f.server.Runtime
	target, _ := a.Authority.Snapshot().CurrentTarget("endpoint", f.endpoint.ID)
	invite := Invite{ID: "demo-control-transaction", GenesisDigest: a.Config.GenesisID, IssuerControlID: a.Config.ControlID, DeviceID: "demo-joined-control", Name: "Demo joined control", Responsibilities: []string{"control"}, PolicyIDs: []string{}, Medium: "sh", Endpoint: f.endpoint, ExpiresAt: f.clock.Load() + 60000}
	issued, extra, err := f.server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-member-invite", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: target.MaterialIDs, Payload: invite})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := DecodeInvite(extra.Invite)
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	claim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 3, NetworkID: a.Config.NetworkID, GenesisDigest: a.Config.GenesisID, TransactionID: invite.ID, InviteMaterialID: issued.MaterialID, RequestID: "demo-control-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Platform: "linux"}, key)
	if err != nil {
		t.Fatal(err)
	}
	status, body := endpointPost(t, f.dialBootstrap(t, bootstrap), "/enrollment/claim", claim)
	if status != http.StatusOK {
		t.Fatalf("real TLS claim failed: %d %s", status, body)
	}
	var enrolled EnrollmentResponse
	if err = DecodeCanonical(body, &enrolled, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil || enrolled.State != "completed" || enrolled.DeviceView == nil {
		t.Fatalf("TLS claim did not complete: %v", err)
	}
	view := *enrolled.DeviceView
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func() *http.Client {
		conn, err := DialEndpoint(ctx, f.endpoint, TunnelHello{Schema: 3, Mode: "device", EndpointID: f.endpoint.ID, Generation: f.endpoint.Generation, DeviceID: invite.DeviceID}, key)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil }}}
	}
	fetch := func(ctx context.Context, path string) ([]byte, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://loom.private/device/control"+path, nil)
		if err != nil {
			return nil, err
		}
		response, err := dial().Do(r)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("member original read returned %d", response.StatusCode)
		}
		return io.ReadAll(io.LimitReader(response.Body, 8<<20))
	}
	originals, err := CollectMemberMaterials(ctx, view.ControlProof, fetch)
	if err != nil {
		t.Fatal("member did not receive original authenticated facts", err)
	}
	parent := t.TempDir()
	peer, _, _ := testTransportIdentity(t, parent, invite.DeviceID, 90, key, f.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	browser, _, _ := testTransportIdentity(t, parent, "demo-member-browser", 91, testKey(t), f.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	config := NodeConfig{Schema: 3, NetworkID: a.Config.NetworkID, ControlID: invite.DeviceID, NodeID: invite.DeviceID, GenesisID: a.Config.GenesisID, SigningKeyFile: peer.KeyFile, PeerTLS: &peer, BrowserTLS: &browser}
	root := filepath.Join(parent, "authority")
	if _, err = InitializeMemberAuthority(root, config, view.ControlProof, nil); err == nil {
		t.Fatal("new member initialized without original claim facts")
	}
	if _, err = InitializeMemberAuthority(root, config, view.ControlProof, originals); err != nil {
		t.Fatal(err)
	}
	b, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !b.Writable() {
		t.Fatal("certified member with originals cannot sign")
	}
	if _, err = InitializeMemberAuthority(root, config, view.ControlProof, originals); err == nil {
		t.Fatal("join overwrote existing authority")
	}
	addresses := []string{testLoopbackAddress(t), testLoopbackAddress(t)}
	aKey, _ := a.Config.PrivateKey()
	aPeer, _, _ := testTransportIdentity(t, t.TempDir(), a.Config.ControlID, 92, aKey, f.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	aConfig := a.Config
	aConfig.PeerTLS, aConfig.BrowserTLS = &aPeer, &browser
	servers := []*Server{f.server, {Runtime: b, Config: config}}
	configs := []NodeConfig{aConfig, config}
	for i, runtime := range []*Runtime{a, b} {
		channel, err := OpenPrivateChannel(PrivateChannelConfig{Schema: 3, Node: configs[i].NodeID, Listen: []string{addresses[i]}, Peers: []PrivatePeer{{Node: configs[1-i].NodeID, Addresses: []string{addresses[1-i]}}}}, configs[i])
		if err != nil {
			t.Fatal(err)
		}
		defer channel.Close()
		channel.AttachAuthority(runtime.Authority)
		runtime.Channel, servers[i].Channel = channel, channel
		h := &http.Server{Handler: servers[i].Handler(), ConnContext: controlConnContext, ReadHeaderTimeout: time.Second}
		defer h.Close()
		go h.Serve(channel.ControlListener())
	}
	// A newly admitted member signs through the same formal operation handler;
	// the previous member verifies and consumes it through real member TLS.
	op := authorityService("demo-new-member-service", "demo-new-member-write")
	accepted, _, err := servers[1].HandleOperation(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	bMember, _ := config.Member()
	if err = a.reconcilePeer(ctx, bMember); err != nil {
		t.Fatal("old member did not consume new member's signed fact", err)
	}
	if _, err = a.Authority.Material(accepted.MaterialID); err != nil {
		t.Fatal(err)
	}
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: config.NetworkID, DeviceID: config.NodeID, ReportSequence: 1, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: f.clock.Load(), Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := DialEndpoint(ctx, f.endpoint, TunnelHello{Schema: 3, Mode: "device", EndpointID: f.endpoint.ID, Generation: f.endpoint.Generation, DeviceID: config.NodeID}, key)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = endpointPost(t, conn, "/device/report", report)
	if status != http.StatusOK {
		t.Fatal("pure control report was rejected")
	}
	aMember, _ := a.Config.Member()
	if err = b.reconcilePeer(ctx, aMember); err != nil {
		t.Fatal("new member did not receive pure control report", err)
	}
	latest, err := b.Reports.Latest(ctx)
	if err != nil || len(latest) != 1 || latest[0].Signature != report.Signature {
		t.Fatal("pure control report lost its original authenticated history", err)
	}
	response := memberAdminHTTP(t, servers[0], ControlChangeRequest{Schema: 3, BaseConfigID: a.Authority.Snapshot().ControlConfigID, Operation: "delete", TargetNodeID: config.NodeID})
	if response.Code != http.StatusOK {
		t.Fatalf("member deletion: %s", response.Body.String())
	}
	if err = b.reconcileControlProof(ctx, aMember); err != nil {
		t.Fatal("removed member could not consume its stopping proof", err)
	}
	if b.Writable() {
		t.Fatal("deleted member retained ordinary signing authority")
	}
	if state, err := a.Authority.EnrollmentState(invite.ID); err != nil || state != "completed" {
		t.Fatal("deletion rewrote established enrollment history")
	}
	invite.ID = "demo-reused-node"
	if _, _, err = f.server.HandleOperation(ctx, Operation{Schema: 3, RequestID: "demo-reinvite-deleted", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: target.MaterialIDs, Payload: invite}); err == nil {
		t.Fatal("member deletion allowed node identity reuse")
	}
}
