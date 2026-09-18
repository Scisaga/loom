package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	genesis := Material{Schema: 1, Kind: "genesis", RequestID: "demo-genesis",
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

func TestThreeMemberQuorumWritePartitionRecoveryAndMembership(t *testing.T) {
	roots, runtimes, serverCancels, cancel := testCluster(t, 3)
	defer cancel()
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

	follower := runtimes[0]
	if follower == leader {
		follower = runtimes[1]
	}
	service := Service{ID: "demo-service", Name: "Demo", Matchers: []string{"demo.example"}, Policy: "direct"}
	material := Material{Schema: 1, Kind: "service.put", RequestID: "demo-write", BaseHead: HeadID(joined.Head), Service: &service}
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
	active := []*Runtime{runtimes[0], runtimes[1]}
	leader = waitLeader(t, active)
	service.Name = "Demo majority"
	material = Material{Schema: 1, Kind: "service.put", RequestID: "demo-majority", BaseHead: minorityHead, Service: &service}
	body, _, _ = EncodeMaterial(material)
	majority, err := leader.Submit(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	_, _, stale := minority.Authority.Snapshot()
	if HeadID(stale.Head) != minorityHead {
		t.Fatal("minority did not retain its certified LKG")
	}

	restarted, err := OpenRuntime(roots[2])
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

func TestMaterialDeltaIsIdempotentAndCommittedReferenceMustExist(t *testing.T) {
	_, root := testActivated(t)
	authority, err := OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	_, _, certified := authority.Snapshot()
	service := Service{ID: "demo", Name: "Demo", Matchers: []string{}, Policy: "direct"}
	material := Material{Schema: 1, Kind: "service.put", RequestID: "demo-idempotent", BaseHead: HeadID(certified.Head), Service: &service}
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
	config, err := ActivateLegacy(root, state, "demo-control", freeAddress(t, "127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	waitLeader(t, []*Runtime{runtime})
	server := &Server{Runtime: runtime, Config: config, ReleaseRoot: t.TempDir(), ReleaseKey: filepath.Join(t.TempDir(), "missing")}
	_, _, before := runtime.Authority.Snapshot()
	payload, _ := json.Marshal(map[string]any{"kind": "service.put", "payload": map[string]any{"id": "demo-api", "name": "Demo API", "matchers": []string{"api.example"}, "policy": "direct"}, "request_id": "demo-api-write", "base_head": HeadID(before.Head)})
	request := httptest.NewRequest(http.MethodPost, "https://10.0.0.1:8443/api/control/operations", strings.NewReader(string(payload)))
	request.Host = "10.0.0.1:8443"
	request.Header.Set("Origin", "https://10.0.0.1:8443")
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{Raw: []byte("admin")}}}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("operation status=%d body=%s", response.Code, response.Body.String())
	}
	_, _, after := runtime.Authority.Snapshot()
	if after.Head.Index != before.Head.Index+1 || len(after.Projection.Web.Services) != len(before.Projection.Web.Services)+1 {
		t.Fatal("operation did not commit and read back")
	}

	request = httptest.NewRequest(http.MethodPost, "https://10.0.0.1:8443/api/control/operations", strings.NewReader(string(payload)))
	request.Host = "10.0.0.1:8443"
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{Raw: []byte("reader")}}}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("read credential write status=%d", response.Code)
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
	state.Listen = freeAddress(t, "127.0.0.2")
	state.BrowserTLS = testTLS(t)
	config, err := ActivateLegacy(root, state, "demo-control-1", freeAddress(t, "127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	return config, root
}

func testCluster(t *testing.T, count int) ([]string, []*Runtime, []context.CancelFunc, context.CancelFunc) {
	t.Helper()
	_, first := testActivated(t)
	roots := []string{first}
	for index := 1; index < count; index++ {
		root := t.TempDir()
		_, err := PrepareMember(root, first, "demo-control-"+string(rune('1'+index)), freeAddress(t, "127.0.0.2"), freeAddress(t, "127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
	}
	runtimes := make([]*Runtime, 0, count)
	serverCancels := make([]context.CancelFunc, 0, count)
	allCtx, cancel := context.WithCancel(context.Background())
	for _, root := range roots {
		runtime, err := OpenRuntime(root)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		runtimes = append(runtimes, runtime)
		serverCtx, serverCancel := context.WithCancel(allCtx)
		serverCancels = append(serverCancels, serverCancel)
		go func(runtime *Runtime) {
			_ = (&Server{Runtime: runtime, Config: runtime.Config, ReleaseRoot: t.TempDir(), ReleaseKey: filepath.Join(t.TempDir(), "missing")}).Serve(serverCtx)
		}(runtime)
	}
	t.Cleanup(func() {
		cancel()
		for _, runtime := range runtimes {
			_ = runtime.Close()
		}
	})
	return roots, runtimes, serverCancels, cancel
}

func serveTestRuntime(t *testing.T, runtime *Runtime) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = (&Server{Runtime: runtime, Config: runtime.Config, ReleaseRoot: t.TempDir(), ReleaseKey: filepath.Join(t.TempDir(), "missing")}).Serve(ctx)
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
