package control

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type endpointFixture struct {
	server   *Server
	runtime  *EndpointRuntime
	endpoint EndpointGeneration
	ca       transportCA
	clock    *atomic.Int64
}

func newEndpointFixture(t *testing.T) endpointFixture {
	t.Helper()
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	clock := &atomic.Int64{}
	clock.Store(time.Now().UnixMilli())
	now := func() time.Time { return time.UnixMilli(clock.Load()) }
	ca := testTransportCA(t, filepath.Dir(root))
	files, _, leaf := testTransportIdentity(t, filepath.Dir(root), "demo-lifecycle", 81, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	address := testLoopbackAddress(t)
	host, port, _ := net.SplitHostPort(address)
	number, _ := strconv.Atoi(port)
	endpoint := EndpointGeneration{ID: "demo-lifecycle-entry", Generation: 1, OwnerControlID: config.ControlID, Host: host, Port: number, ServerName: "demo.example", SPKISHA256: endpointByteDigest(leaf.RawSubjectPublicKeyInfo), CertificateDigest: endpointByteDigest(leaf.Raw), Modes: []string{"bootstrap", "device"}, State: "prepared"}
	if err := InstallEndpointInputs(root, endpoint, EndpointLocalInputs{Listen: address, CertificateFile: files.CertificateFile, KeyFile: files.KeyFile}); err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: runtime, Config: config, Now: now}
	prepared, _, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-lifecycle-prepare", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: []string{}, Payload: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	endpoints, err := NewEndpointRuntime(runtime.Authority, config.ControlID, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { endpoints.Close() })
	server.Endpoints = endpoints
	service := &http.Server{Handler: server.DeviceHandler(), ConnContext: endpointConnContext, ReadHeaderTimeout: 10 * time.Second}
	t.Cleanup(func() { service.Close() })
	go service.Serve(endpoints)
	endpoint.State = "serving"
	if _, _, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-lifecycle-serve", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: []string{prepared.MaterialID}, Payload: endpoint}); err != nil {
		t.Fatal(err)
	}
	return endpointFixture{server, endpoints, endpoint, ca, clock}
}
func (fixture endpointFixture) invite(t *testing.T, suffix string) (BootstrapInvite, EnrollmentClaimRequest, ed25519.PrivateKey) {
	t.Helper()
	target, _ := fixture.server.Runtime.Authority.Snapshot().CurrentTarget("endpoint", fixture.endpoint.ID)
	invite := Invite{ID: "demo-transaction-" + suffix, GenesisDigest: fixture.server.Config.GenesisID, IssuerControlID: fixture.server.Config.ControlID, DeviceID: "demo-device-" + suffix, Name: "Demo lifecycle", Responsibilities: []string{"access"}, PolicyIDs: []string{}, Medium: "qr", Endpoint: fixture.endpoint, ExpiresAt: fixture.clock.Load() + 60000}
	issued, extra, err := fixture.server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-issue-" + suffix, Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: target.MaterialIDs, Payload: invite})
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := DecodeInvite(extra.Invite)
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	claim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 3, NetworkID: fixture.server.Config.NetworkID, GenesisDigest: fixture.server.Config.GenesisID, TransactionID: invite.ID, InviteMaterialID: issued.MaterialID, RequestID: "demo-claim-" + suffix, DevicePublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Platform: "linux"}, key)
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap, claim, key
}
func (fixture endpointFixture) dialBootstrap(t *testing.T, invite BootstrapInvite) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := DialEndpoint(ctx, fixture.endpoint, TunnelHello{Schema: 3, Mode: "bootstrap", EndpointID: fixture.endpoint.ID, Generation: fixture.endpoint.Generation, Invite: &invite}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	return connection
}
func (fixture endpointFixture) join(t *testing.T, suffix string) (BootstrapInvite, EnrollmentClaimRequest, ed25519.PrivateKey) {
	t.Helper()
	invite, claim, key := fixture.invite(t, suffix)
	status, body := endpointPost(t, fixture.dialBootstrap(t, invite), "/enrollment/claim", claim)
	if status != http.StatusOK {
		t.Fatalf("fixture claim failed: %s", body)
	}
	return invite, claim, key
}
func assertEndpointConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	_, err := connection.Read(b[:])
	if err == nil {
		t.Fatal("withdrawn session remained readable")
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		t.Fatal("withdrawn session remained open until the test deadline")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		if _, ok := err.(*net.OpError); !ok {
			t.Fatalf("unexpected connection closure: %v", err)
		}
	}
}
func TestEndpointClosesCancelledExpiredAndRevokedSessions(t *testing.T) {
	fixture := newEndpointFixture(t)
	cancelled, _, _ := fixture.invite(t, "cancel")
	connection := fixture.dialBootstrap(t, cancelled)
	inviteID, _ := MaterialID(cancelled.Material)
	if _, _, err := fixture.server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-cancel", Operation: "invite.cancel", TargetKind: "invite", TargetID: cancelled.Material.TargetID, Dependencies: []string{inviteID}, Payload: EnrollmentTermination{TransactionID: cancelled.Material.TargetID, InviteMaterialID: inviteID}}); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.reconcile()
	assertEndpointConnectionClosed(t, connection)
	expired, _, _ := fixture.invite(t, "expire")
	connection = fixture.dialBootstrap(t, expired)
	fixture.clock.Store(expired.Material.Payload.(Invite).ExpiresAt)
	fixture.runtime.reconcile()
	assertEndpointConnectionClosed(t, connection)
	// Runtime expiry closes a socket but never writes a terminal fact from a clock.
	if state, err := fixture.server.Runtime.Authority.EnrollmentState(expired.Material.TargetID); err != nil || state != "open" {
		t.Fatal("runtime clock rewrote enrollment authority")
	}
	completed, claim, key := fixture.join(t, "completed")
	fixture.clock.Store(completed.Material.Payload.(Invite).ExpiresAt + 1)
	connection = fixture.dialBootstrap(t, completed)
	resume := EnrollmentResumeRequest(claim)
	resume.Signature = ""
	resume, err := SignEnrollmentResume(resume, key)
	if err != nil {
		t.Fatal(err)
	}
	status, body := endpointPost(t, connection, "/enrollment/resume", resume)
	if status != http.StatusOK {
		t.Fatalf("completed binding could not recover after invite expiry: %s", body)
	}
	bootstrapSession := fixture.dialBootstrap(t, completed)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deviceID := completed.Material.Payload.(Invite).DeviceID
	deviceSession, err := DialEndpoint(ctx, fixture.endpoint, TunnelHello{Schema: 3, Mode: "device", EndpointID: fixture.endpoint.ID, Generation: fixture.endpoint.Generation, DeviceID: deviceID}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer deviceSession.Close()
	target, _ := fixture.server.Runtime.Authority.Snapshot().CurrentTarget("device", deviceID)
	submitAuthority(t, fixture.server.Runtime, Operation{Schema: 3, RequestID: "demo-lifecycle-revoke", Operation: "device.revoke", TargetKind: "device", TargetID: deviceID, Dependencies: target.MaterialIDs, Payload: DeleteTarget{ID: deviceID}})
	fixture.runtime.reconcile()
	assertEndpointConnectionClosed(t, bootstrapSession)
	assertEndpointConnectionClosed(t, deviceSession)
}
func TestEndpointDrainRetirementAndCertificateExpiry(t *testing.T) {
	fixture := newEndpointFixture(t)
	invite, _, key := fixture.join(t, "drain")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hello := TunnelHello{Schema: 3, Mode: "device", EndpointID: fixture.endpoint.ID, Generation: fixture.endpoint.Generation, DeviceID: invite.Material.Payload.(Invite).DeviceID}
	connection, err := DialEndpoint(ctx, fixture.endpoint, hello, key)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	draining := fixture.endpoint
	draining.State = "draining"
	draining.DrainUntil = fixture.clock.Load() + 1000
	target, _ := fixture.server.Runtime.Authority.Snapshot().CurrentTarget("endpoint", draining.ID)
	saved, _, err := fixture.server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-start-drain", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: draining.ID, Dependencies: target.MaterialIDs, Payload: draining})
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime.reconcile()
	if fixture.runtime.Active(draining) == 0 {
		t.Fatal("draining prematurely terminated an existing session")
	}
	if next, err := DialEndpoint(ctx, fixture.endpoint, hello, key); err == nil {
		next.Close()
		t.Fatal("draining endpoint accepted a new session")
	}
	retired := draining
	retired.State = "retired"
	retired.DrainUntil = 0
	retire := Operation{Schema: 3, RequestID: "demo-retire", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: retired.ID, Dependencies: []string{saved.MaterialID}, Payload: retired}
	if _, _, err := fixture.server.HandleOperation(context.Background(), retire); err == nil {
		t.Fatal("retirement ignored an active owned session")
	}
	fixture.clock.Store(draining.DrainUntil)
	fixture.runtime.reconcile()
	assertEndpointConnectionClosed(t, connection)
	if fixture.runtime.Active(draining) != 0 {
		t.Fatal("drain deadline left owned sessions active")
	}
	if _, _, err := fixture.server.HandleOperation(context.Background(), retire); err != nil {
		t.Fatal(err)
	}

	expired := newEndpointFixture(t)
	open, _, _ := expired.invite(t, "certificate")
	active := expired.dialBootstrap(t, open)
	expires, err := expired.runtime.ExpiresAt(expired.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	expired.clock.Store(expires.UnixMilli())
	expired.runtime.reconcile()
	assertEndpointConnectionClosed(t, active)
	if expired.runtime.Ready(expired.endpoint) {
		t.Fatal("expired certificate was still ready")
	}
	if expired.server.Runtime.Authority.Snapshot().EndpointGenerations[0].State != "serving" {
		t.Fatal("certificate clock changed signed endpoint state")
	}
}
func TestEndpointShutdownIncludesUnfinishedHandshakes(t *testing.T) {
	fixture := newEndpointFixture(t)
	raw, err := net.Dial("tcp", net.JoinHostPort(fixture.endpoint.Host, strconv.Itoa(fixture.endpoint.Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		fixture.runtime.mu.RLock()
		count := len(fixture.runtime.handshakes)
		fixture.runtime.mu.RUnlock()
		if count > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- fixture.runtime.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown left a TLS handshake running")
	}
	assertEndpointConnectionClosed(t, raw)
	fixture.runtime.mu.RLock()
	pending, active := len(fixture.runtime.handshakes), len(fixture.runtime.sessions)
	fixture.runtime.mu.RUnlock()
	if pending != 0 || active != 0 {
		t.Fatal("shutdown left untracked connections")
	}
}
func TestEndpointPreparedCertificateDoesNotDisplaceServing(t *testing.T) {
	fixture := newEndpointFixture(t)
	root := fixture.server.Runtime.Authority.root
	files, _, leaf := testTransportIdentity(t, filepath.Dir(root), "demo-next-certificate", 82, testKey(t), fixture.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	next := fixture.endpoint
	next.Generation = 2
	next.State = "prepared"
	next.SPKISHA256 = endpointByteDigest(leaf.RawSubjectPublicKeyInfo)
	next.CertificateDigest = endpointByteDigest(leaf.Raw)
	install := func(endpoint EndpointGeneration) {
		t.Helper()
		if err := InstallEndpointInputs(root, endpoint, EndpointLocalInputs{Listen: net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), CertificateFile: files.CertificateFile, KeyFile: files.KeyFile}); err != nil {
			t.Fatal(err)
		}
	}
	install(next)
	target, _ := fixture.server.Runtime.Authority.Snapshot().CurrentTarget("endpoint", next.ID)
	prepared := submitAuthority(t, fixture.server.Runtime, Operation{Schema: 3, RequestID: "demo-next-prepare", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: next.ID, Dependencies: target.MaterialIDs, Payload: next})
	fixture.runtime.reconcile()
	if !fixture.runtime.Ready(fixture.endpoint) || fixture.runtime.Ready(next) {
		t.Fatal("prepared incompatible certificate displaced the live serving listener")
	}
	next.State = "serving"
	if _, _, err := fixture.server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-next-serve", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: next.ID, Dependencies: []string{prepared.MaterialID}, Payload: next}); err == nil {
		t.Fatal("new certificate was marked serving without its actual TLS identity")
	}
	next.Generation = 3
	next.State = "prepared"
	_, port, _ := net.SplitHostPort(testLoopbackAddress(t))
	next.Port, _ = strconv.Atoi(port)
	install(next)
	prepared = submitAuthority(t, fixture.server.Runtime, Operation{Schema: 3, RequestID: "demo-other-listen-prepare", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: next.ID, Dependencies: []string{prepared.MaterialID}, Payload: next})
	fixture.runtime.reconcile()
	if !fixture.runtime.Ready(fixture.endpoint) || !fixture.runtime.Ready(next) {
		t.Fatal("separate explicit listener could not prove both certificates")
	}
	next.State = "serving"
	if _, _, err := fixture.server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-other-listen-serve", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: next.ID, Dependencies: []string{prepared.MaterialID}, Payload: next}); err != nil {
		t.Fatal(err)
	}
	if !fixture.runtime.Ready(fixture.endpoint) {
		t.Fatal("activating a verified new listener stopped the old serving generation")
	}
}

func TestEndpointRejectsProofCompletedAfterDeviceRevocation(t *testing.T) {
	fixture := newEndpointFixture(t)
	invite, _, key := fixture.join(t, "challenge")
	deviceID := invite.Material.Payload.(Invite).DeviceID
	hello := TunnelHello{Schema: 3, Mode: "device", EndpointID: fixture.endpoint.ID, Generation: fixture.endpoint.Generation, DeviceID: deviceID}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := connectEndpoint(ctx, fixture.endpoint, tunnelALPN)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeFrame(connection, hello); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	var challenge tunnelChallenge
	if err := readFrame(reader, &challenge); err != nil {
		t.Fatal(err)
	}
	target, _ := fixture.server.Runtime.Authority.Snapshot().CurrentTarget("device", deviceID)
	submitAuthority(t, fixture.server.Runtime, Operation{Schema: 3, RequestID: "demo-revoke-during-challenge", Operation: "device.revoke", TargetKind: "device", TargetID: deviceID, Dependencies: target.MaterialIDs, Payload: DeleteTarget{ID: deviceID}})
	message, err := tunnelProofBytes(hello, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(connection, TunnelProof{Schema: 3, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}); err != nil {
		t.Fatal(err)
	}
	var ready tunnelReady
	if err := readFrame(reader, &ready); err == nil {
		t.Fatal("device authenticated using authorization withdrawn during its challenge")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("withdrawn challenge was left pending instead of rejected")
	}
}

type endpointFailedClose struct {
	net.Conn
	err error
}

func (connection endpointFailedClose) Close() error { return connection.err }

func TestEndpointFailedCloseRetainsActiveHandle(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	want := errors.New("demo close failure")
	released := false
	connection := &authenticatedConn{Conn: endpointFailedClose{left, want}, closed: func() { released = true }}
	if err := connection.Close(); !errors.Is(err, want) || released {
		t.Fatal("failed connection close reported its handle released")
	}
	if err := connection.Close(); !errors.Is(err, want) || released {
		t.Fatal("repeated close discarded the original cleanup failure")
	}
	secure := &authenticatedConn{Conn: tls.Server(endpointFailedClose{left, want}, &tls.Config{}), closed: func() { released = true }}
	if err := secure.Close(); !errors.Is(err, want) || released {
		t.Fatal("TLS cleanup hid a real underlying close failure")
	}
}

func TestEndpointTLSCloseAfterPeerDisconnectReleasesHandle(t *testing.T) {
	f := newEndpointFixture(t)
	inputs, err := loadEndpointInputs(f.server.Runtime.Authority.root, f.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := LoadTLSCertificate(inputs.CertificateFile, inputs.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	server := tls.Server(left, &tls.Config{Certificates: []tls.Certificate{certificate}})
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.certificate)
	client := tls.Client(right, &tls.Config{RootCAs: roots, ServerName: f.endpoint.ServerName})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- server.HandshakeContext(ctx) }()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	_ = right.Close()
	released := false
	connection := &authenticatedConn{Conn: server, closed: func() { released = true }}
	if err := connection.Close(); err != nil || !released {
		t.Fatal("peer's missing TLS close notification retained an already closed TCP handle", err)
	}
}
