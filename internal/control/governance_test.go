package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func TestCanonicalMaterialAndDeterministicReducer(t *testing.T) {
	config, _ := testActivated(t)
	genesis := Material{Schema: MaterialSchema, Kind: "genesis", RequestID: "demo-genesis",
		Genesis: &Genesis{LegacyHead: "sha256:" + strings.Repeat("1", 64), ControlConfig: StableConfig([]Member{config.Member()}), Projection: testState().Projection}}
	body, id, err := EncodeMaterial(genesis)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMaterial(body)
	if err != nil || !reflect.DeepEqual(decoded, genesis) {
		t.Fatalf("round trip: %#v %v", decoded, err)
	}
	if _, err := DecodeMaterial(append([]byte(" "), body...)); err == nil {
		t.Fatal("non-canonical bytes accepted")
	}
	left, err := Reduce(Projection{}, genesis, id)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Reduce(Projection{}, decoded, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatal("reducer is not deterministic")
	}
}

func TestLegacyCommittedMaterialRemainsCanonical(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	legacy := Material{Schema: LegacyMaterialSchema, Kind: "genesis", RequestID: "demo-legacy-genesis",
		Genesis: &Genesis{LegacyHead: "sha256:" + strings.Repeat("1", 64), ControlConfig: StableConfig([]Member{{
			ID: "demo-control", LegacyRaftAddress: "192.0.2.10:7001", LegacyAPIAddress: "192.0.2.10:7002",
			PublicKey: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)),
		}}), Projection: testState().Projection}}
	body, _, err := EncodeMaterial(legacy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMaterial(body)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := EncodeMaterial(decoded)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("legacy committed material did not retain canonical bytes")
	}
}

func TestThreeMemberQuorumWritePartitionRecoveryAndMembership(t *testing.T) {
	roots, networks, runtimes, serverCancels, cancel := testCluster(t, 3)
	defer cancel()
	if len(networks[1].Peers[networks[2].Node]) != 0 || len(networks[2].Peers[networks[1].Node]) != 0 {
		t.Fatal("test topology unexpectedly has a leaf-to-leaf path")
	}
	leader := waitLeader(t, runtimes)
	_, _, initial := leader.Authority.Snapshot()
	members := []Member{runtimes[0].Config.Member(), runtimes[1].Config.Member(), runtimes[2].Config.Member()}
	joined, err := leader.ReplaceMembers(context.Background(), "demo-join", HeadID(initial.Head), members)
	if err != nil {
		t.Fatal(err)
	}
	if joined.Projection.Config.Mode != "stable" || len(joined.Projection.Config.Members) != 3 {
		t.Fatalf("join result: %#v", joined.Projection.Config)
	}
	// Put leadership on a leaf. Raft must use the authenticated private relay
	// through the center member to keep the other leaf in the same log.
	leafLeader := runtimes[1]
	if leader == leafLeader {
		leafLeader = runtimes[2]
	}
	if err := leader.Raft.LeadershipTransferToServer(raft.ServerID(leafLeader.Config.MemberID),
		raft.ServerAddress(leafLeader.Config.Node)).Error(); err != nil {
		t.Fatal(err)
	}
	leader = waitLeader(t, runtimes)
	if leader != leafLeader {
		t.Fatalf("leadership did not transfer to a leaf: got %s want %s", leader.Config.MemberID, leafLeader.Config.MemberID)
	}
	otherLeaf := runtimes[2]
	if leafLeader == otherLeaf {
		otherLeaf = runtimes[1]
	}
	relayConnection, err := leafLeader.Channel.RaftStream().Dial(raft.ServerAddress(otherLeaf.Config.Node), 3*time.Second)
	if err != nil {
		t.Fatalf("leaf-to-leaf private Raft relay: %v", err)
	}
	_ = relayConnection.Close()
	follower := runtimes[0]
	if follower == leader {
		follower = runtimes[1]
	}
	service := Service{ID: "demo-service", Name: "Demo", Matchers: []string{"demo.example"}, Policy: "direct"}
	material := Material{Schema: MaterialSchema, Kind: "service.put", RequestID: "demo-write", BaseHead: HeadID(joined.Head), Service: &service}
	body, _, _ := EncodeMaterial(material)
	written, err := follower.Submit(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if written.Head.Index != joined.Head.Index+1 {
		t.Fatalf("service write did not advance head: joined=%d written=%d", joined.Head.Index, written.Head.Index)
	}
	for _, runtime := range runtimes {
		waitHead(t, runtime.Authority, HeadID(written.Head))
	}

	minority := runtimes[2]
	minorityHead := HeadID(written.Head)
	serverCancels[2]()
	if err := minority.Close(); err != nil {
		t.Fatal(err)
	}
	_ = minority.Channel.Close()
	active := []*Runtime{runtimes[0], runtimes[1]}
	leader = waitLeader(t, active)
	service.Name = "Demo majority"
	material = Material{Schema: MaterialSchema, Kind: "service.put", RequestID: "demo-majority", BaseHead: minorityHead, Service: &service}
	body, _, _ = EncodeMaterial(material)
	majority, err := leader.Submit(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	_, _, stale := minority.Authority.Snapshot()
	if HeadID(stale.Head) != minorityHead {
		t.Fatal("minority did not retain its certified LKG")
	}

	channel, err := OpenPrivateChannel(networks[2], runtimes[2].Config)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenRuntime(roots[2], channel)
	if err != nil {
		t.Fatal(err)
	}
	runtimes[2] = restarted
	serverCancel := serveTestRuntime(t, restarted)
	defer serverCancel()
	waitHead(t, restarted.Authority, HeadID(majority.Head))

	kept := []Member{runtimes[0].Config.Member(), runtimes[1].Config.Member()}
	leader = waitLeader(t, runtimes)
	_, _, beforeRemove := leader.Authority.Snapshot()
	removed, err := leader.ReplaceMembers(context.Background(), "demo-remove", HeadID(beforeRemove.Head), kept)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.Projection.Config.Members) != 2 {
		t.Fatal("member removal did not converge")
	}
}

func TestEnrollmentApprovalRequiresControlQuorum(t *testing.T) {
	_, _, runtimes, serverCancels, cancel := testCluster(t, 3)
	defer cancel()
	leader := waitLeader(t, runtimes)
	_, _, initial := leader.Authority.Snapshot()
	members := []Member{runtimes[0].Config.Member(), runtimes[1].Config.Member(), runtimes[2].Config.Member()}
	joined, err := leader.ReplaceMembers(context.Background(), "enrollment-quorum-join", HeadID(initial.Head), members)
	if err != nil {
		t.Fatal(err)
	}

	submit := func(runtime *Runtime, material Material) CertifiedState {
		t.Helper()
		body, _, err := EncodeMaterial(material)
		if err != nil {
			t.Fatal(err)
		}
		result, err := runtime.Submit(context.Background(), body)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	digest := strings.Repeat("1", 64)
	generation := EndpointGeneration{Schema: 1, EndpointID: "demo-entry", Generation: 1, Node: leader.Config.Node,
		Transport: "tls_tunnel", Listen: "127.0.0.1:443", Address: "192.0.2.10:443", ServerName: "demo.example",
		TLSCertificateFile: "/etc/loom/demo.crt", TLSPrivateKeyFile: "/etc/loom/demo.key", SPKISHA256: digest,
		State: "prepared"}
	current := submit(leader, Material{Schema: MaterialSchema, Kind: "endpoint.put", RequestID: "quorum-endpoint-prepared",
		BaseHead: HeadID(joined.Head), EndpointGeneration: &generation})
	generation.State = "serving"
	current = submit(leader, Material{Schema: MaterialSchema, Kind: "endpoint.put", RequestID: "quorum-endpoint-serving",
		BaseHead: HeadID(current.Head), EndpointGeneration: &generation})
	intent := EnrollmentIntent{DeviceID: "demo-quorum-device", Name: "Demo quorum device", Platform: "linux", Roles: []string{"access"}, Routes: []RouteCandidate{}}
	constraint, _ := intentDigest(intent)
	capability, err := SignBootstrapCapability(BootstrapCapability{Schema: 1, TransactionID: "demo-quorum-transaction",
		IssuedHead: HeadID(current.Head), ConfigMaterial: current.Projection.ConfigMaterial, ControlConfig: current.Projection.Config,
		ExpiresAt: "2030-01-01T00:00:00Z", Actions: []string{"claim", "resume"}, Endpoints: []EndpointReference{generation.Reference()},
		ConstraintDigest: constraint, IssuerMemberID: leader.Config.MemberID}, leader.Config)
	if err != nil {
		t.Fatal(err)
	}
	open := EnrollmentOpen{TransactionID: capability.TransactionID, Intent: intent, Capability: capability}
	current = submit(leader, Material{Schema: MaterialSchema, Kind: "enrollment.open", RequestID: "quorum-enrollment-open",
		BaseHead: HeadID(current.Head), EnrollmentOpen: &open})
	devicePublic, _, _ := ed25519.GenerateKey(rand.Reader)
	bind := EnrollmentBind{TransactionID: capability.TransactionID, ClaimRequestID: "demo-quorum-claim",
		DevicePublicKey: base64.RawURLEncoding.EncodeToString(devicePublic), ClaimedAt: "2026-09-18T00:00:00Z"}
	current = submit(leader, Material{Schema: MaterialSchema, Kind: "enrollment.bind", RequestID: "quorum-enrollment-bind",
		BaseHead: HeadID(current.Head), EnrollmentBind: &bind})
	for _, runtime := range runtimes {
		waitHead(t, runtime.Authority, HeadID(current.Head))
	}

	minority := runtimes[2]
	for index := 0; index < 2; index++ {
		serverCancels[index]()
		if err := runtimes[index].Close(); err != nil {
			t.Fatal(err)
		}
		_ = runtimes[index].Channel.Close()
	}
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	server := &Server{Runtime: minority, Config: minority.Config, Now: func() time.Time {
		return time.Date(2026, 9, 18, 1, 0, 0, 0, time.UTC)
	}}
	if _, err := server.approveEnrollment(ctx, "quorum-approval", HeadID(current.Head), capability.TransactionID); err == nil {
		t.Fatal("minority approved a new device authorization")
	}
	_, projection, certified := minority.Authority.Snapshot()
	_, transaction := findEnrollment(&projection, capability.TransactionID)
	if transaction == nil || transaction.State != "bound" || HeadID(certified.Head) != HeadID(current.Head) {
		t.Fatalf("failed approval changed certified LKG: transaction=%+v", transaction)
	}
}

func TestMaterialDeltaIsIdempotentAndCommittedReferenceMustExist(t *testing.T) {
	_, root := testActivated(t)
	authority, err := OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	_, _, certified := authority.Snapshot()
	service := Service{ID: "demo", Name: "Demo", Matchers: []string{}, Policy: "direct"}
	material := Material{Schema: MaterialSchema, Kind: "service.put", RequestID: "demo-idempotent", BaseHead: HeadID(certified.Head), Service: &service}
	body, id, _ := EncodeMaterial(material)
	first, err := authority.PutMaterial(body)
	if err != nil {
		t.Fatal(err)
	}
	second, err := authority.PutMaterial(body)
	if err != nil || first != second || second != id {
		t.Fatal("duplicate material changed the set")
	}
	guard := guardedLogStore{LogStore: raftMemoryLogStore{}, authority: authority}
	if err := guard.StoreLog(&raft.Log{Type: raft.LogCommand, Data: []byte("sha256:" + strings.Repeat("f", 64))}); err == nil {
		t.Fatal("missing material log was acknowledged")
	}
}

func TestAuthenticatedOperationCommitsAndReadsBack(t *testing.T) {
	root := t.TempDir()
	state := testState()
	state.BrowserTLS = testTLS(t)
	address := freeAddress(t, "127.0.0.1")
	config, err := ActivateLegacy(root, state, "demo-control", "demo-node", []string{address})
	if err != nil {
		t.Fatal(err)
	}
	channel, err := OpenPrivateChannel(PrivateChannelConfig{Node: "demo-node", Listen: []string{address}, Peers: map[string][]string{}}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	runtime, err := OpenRuntime(root, channel)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	waitLeader(t, []*Runtime{runtime})
	server := &Server{Runtime: runtime, Channel: channel, Config: config, ReleaseRoot: t.TempDir(), ReleaseKey: filepath.Join(t.TempDir(), "missing")}
	_, _, before := runtime.Authority.Snapshot()
	payload, _ := json.Marshal(map[string]any{"kind": "service.put", "payload": map[string]any{"id": "demo-api", "name": "Demo API", "matchers": []string{"api.example"}, "policy": "direct"}, "request_id": "demo-api-write", "base_head": HeadID(before.Head)})
	request := httptest.NewRequest(http.MethodPost, "https://"+address+"/api/control/operations", strings.NewReader(string(payload)))
	request.Host = address
	request.Header.Set("Origin", "https://"+address)
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{Raw: testAdminCertificateDER}}}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("operation status=%d body=%s", response.Code, response.Body.String())
	}
	_, _, after := runtime.Authority.Snapshot()
	if after.Head.Index != before.Head.Index+1 || len(after.Projection.Web.Services) != len(before.Projection.Web.Services)+1 {
		t.Fatal("operation did not commit and read back")
	}

	request = httptest.NewRequest(http.MethodPost, "https://"+address+"/api/control/operations", strings.NewReader(string(payload)))
	request.Host = address
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{Raw: testReadCertificateDER}}}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("read credential write status=%d", response.Code)
	}
	_, _, localBefore := runtime.Authority.Snapshot()
	localPayload, _ := json.Marshal(map[string]any{"kind": "service.put", "payload": map[string]any{"id": "demo-local-api", "name": "Demo Local API", "matchers": []string{"local.example"}, "policy": "direct"}, "request_id": "demo-local-api-write", "base_head": HeadID(localBefore.Head)})
	request = httptest.NewRequest(http.MethodPost, "http://loom.local/api/control/operations", strings.NewReader(string(localPayload)))
	request.Header.Set("Origin", "http://loom.local")
	response = httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("local admin operation status=%d body=%s", response.Code, response.Body.String())
	}
}

type raftMemoryLogStore struct{}

func (raftMemoryLogStore) FirstIndex() (uint64, error)      { return 0, nil }
func (raftMemoryLogStore) LastIndex() (uint64, error)       { return 0, nil }
func (raftMemoryLogStore) GetLog(uint64, *raft.Log) error   { return raft.ErrLogNotFound }
func (raftMemoryLogStore) StoreLog(*raft.Log) error         { return nil }
func (raftMemoryLogStore) StoreLogs([]*raft.Log) error      { return nil }
func (raftMemoryLogStore) DeleteRange(uint64, uint64) error { return nil }

func testActivated(t *testing.T) (NodeConfig, string) {
	t.Helper()
	root := t.TempDir()
	state := testState()
	state.BrowserTLS = testTLS(t)
	address := freeAddress(t, "127.0.0.1")
	config, err := ActivateLegacy(root, state, "demo-control-1", "demo-node-1", []string{address})
	if err != nil {
		t.Fatal(err)
	}
	return config, root
}

func testCluster(t *testing.T, count int) ([]string, []PrivateChannelConfig, []*Runtime, []context.CancelFunc, context.CancelFunc) {
	t.Helper()
	addresses := make([]string, count)
	for index := range addresses {
		addresses[index] = freeAddress(t, "127.0.0.1")
	}
	first := t.TempDir()
	state := testState()
	state.BrowserTLS = testTLS(t)
	if _, err := ActivateLegacy(first, state, "demo-control-1", "demo-node-1", []string{addresses[0]}); err != nil {
		t.Fatal(err)
	}
	roots := []string{first}
	for index := 1; index < count; index++ {
		root := t.TempDir()
		_, err := PrepareMember(root, first, "demo-control-"+string(rune('1'+index)), "demo-node-"+string(rune('1'+index)), []string{addresses[index]})
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
	}
	networks := make([]PrivateChannelConfig, count)
	for index := range networks {
		peers := map[string][]string{}
		if index == 0 {
			for peer := 1; peer < count; peer++ {
				peers["demo-node-"+string(rune('1'+peer))] = []string{addresses[peer]}
			}
		} else {
			peers["demo-node-1"] = []string{addresses[0]}
		}
		networks[index] = PrivateChannelConfig{Node: "demo-node-" + string(rune('1'+index)), Listen: []string{addresses[index]}, Peers: peers}
	}
	runtimes := make([]*Runtime, 0, count)
	serverCancels := make([]context.CancelFunc, 0, count)
	allCtx, cancel := context.WithCancel(context.Background())
	for index, root := range roots {
		node, err := LoadNodeConfig(root)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		channel, err := OpenPrivateChannel(networks[index], node)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		runtime, err := OpenRuntime(root, channel)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		runtimes = append(runtimes, runtime)
		serverCtx, serverCancel := context.WithCancel(allCtx)
		serverCancels = append(serverCancels, serverCancel)
		go func(runtime *Runtime) {
			_ = (&Server{Runtime: runtime, Channel: runtime.Channel, Config: runtime.Config, ReleaseRoot: t.TempDir(),
				ReleaseKey: filepath.Join(t.TempDir(), "missing"), AdminSocket: filepath.Join(t.TempDir(), "admin.sock")}).Serve(serverCtx, http.NotFoundHandler())
		}(runtime)
	}
	t.Cleanup(func() {
		cancel()
		for _, runtime := range runtimes {
			_ = runtime.Close()
		}
	})
	return roots, networks, runtimes, serverCancels, cancel
}

func serveTestRuntime(t *testing.T, runtime *Runtime) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = (&Server{Runtime: runtime, Channel: runtime.Channel, Config: runtime.Config, ReleaseRoot: t.TempDir(),
			ReleaseKey: filepath.Join(t.TempDir(), "missing"), AdminSocket: filepath.Join(t.TempDir(), "admin.sock")}).Serve(ctx, http.NotFoundHandler())
	}()
	return cancel
}

func waitLeader(t *testing.T, runtimes []*Runtime) *Runtime {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, runtime := range runtimes {
			if runtime.Raft.State() == raft.Leader {
				return runtime
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("cluster did not elect a leader")
	return nil
}

func waitHead(t *testing.T, authority *Authority, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, _, certified := authority.Snapshot()
		if HeadID(certified.Head) == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("certified head did not converge to %s", want)
}

func freeAddress(t *testing.T, host string) string {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func testTLS(t *testing.T) BrowserTLS {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-control-ca"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "demo-control"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPKCS8, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	caPKCS8, _ := x509.MarshalPKCS8PrivateKey(caKey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return BrowserTLS{CertificateChainPEM: string(chain), PrivateKeyPKCS8PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafPKCS8})), RootPrivateKeyPKCS8PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caPKCS8}))}
}
