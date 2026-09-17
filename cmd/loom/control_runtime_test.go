package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/controlplane"
	"loom/internal/crdt"
	"loom/internal/publish"
	"loom/internal/wire"
)

func TestControlRuntimeN1AdminCommitAndRestart(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-test",
		"00000000000000000000000000", "device-test", "10.40.0.2", 17444, 17445, clock); err != nil {
		t.Fatal(err)
	}
	runtime, err := openControlRuntime(stateDir, clock)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.headCollector == nil || runtime.headPeers == nil || runtime.raftPeers == nil ||
		runtime.operationClients == nil || len(runtime.raftPeers) != 0 || len(runtime.operationClients) != 0 {
		t.Fatal("正式 control daemon 未初始化 Head QC peer/collector")
	}
	peer := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
	status := serveRuntimeStatus(t, runtime, peer)
	if status.Quorum != 1 || len(status.ControlSet.Members) != 1 ||
		status.Head.Body.Payload.HeadKind != "bootstrap" {
		t.Fatalf("unexpected bootstrap status: %#v", status)
	}
	var endpoint controlAdminEndpointV1
	if err := readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint); err != nil {
		t.Fatal(err)
	}
	browserRoot := readAdminTestCertificate(t, filepath.Join(adminDir, controlInternalRootName))
	encodedInternalRoot, err := base64.RawURLEncoding.DecodeString(endpoint.InternalRootDER)
	if err != nil || bytes.Equal(browserRoot.Raw, encodedInternalRoot) {
		t.Fatalf("browser compatibility root was not separated from native endpoint authority: %v", err)
	}
	_, _, browserStateRoot, err := loadControlBrowserTLS(filepath.Join(stateDir, controlBrowserTLSName),
		"runtime-test", "10.40.0.2", now)
	if err != nil || !bytes.Equal(browserRoot.Raw, browserStateRoot.Raw) {
		t.Fatalf("delivered browser trust root differs from browser TLS authority: %v", err)
	}
	submitted, err := newControlPingRequest(adminDir, endpoint, status, "runtime integration", now)
	if err != nil {
		t.Fatal(err)
	}
	result := serveRuntimeOperation(t, runtime, peer, submitted, http.StatusOK)
	if result.Status != "certified" || result.RequestID != submitted.RequestID ||
		result.Head.Body.Payload.HeadKind != "ordinary" || result.OperationTreeSize != 1 {
		t.Fatalf("unexpected certified result: %#v", result)
	}
	if err := wire.VerifyConfigQCAuthority(result.Head.HeadHash, result.ConfigQC, &result.Head,
		&status.ControlSet, nil); err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyControlOperationInclusion(&result.OperationLeaf, result.OperationLeafIndex,
		result.OperationTreeSize, result.OperationAuditPath, &result.Head); err != nil {
		t.Fatal(err)
	}
	if runtime.operationMaterials == nil || runtime.operationPeers == nil {
		t.Fatal("正式 control daemon 未初始化 operation material anti-entropy")
	}
	materials := runtime.operationMaterials.Snapshot()
	if len(materials) != 1 || bytes.Contains(materials[0].Payload, []byte(`"result"`)) ||
		bytes.Contains(materials[0].Payload, []byte(`"phases"`)) {
		t.Fatalf("operation material 混入本地执行进度: %#v", materials)
	}
	material, err := decodeControlOperationMaterialObject(materials[0])
	if err != nil || material.Candidate.EntryHash != result.Head.EntryHash ||
		material.Leaf.OperationID != submitted.Operation.Body.OperationID {
		t.Fatalf("operation material 未绑定 certified Head: %#v err=%v", material, err)
	}
	followerStorage, err := controlplane.OpenRaftStorage(filepath.Join(root, "follower-raft.json"),
		runtime.config.MemberID, runtime.config.ControlSet)
	if err != nil {
		t.Fatal(err)
	}
	followerVerifier := &controlRuntime{dir: stateDir, config: controlClone(runtime.config),
		storage: followerStorage, operationMaterials: runtime.operationMaterials, now: clock}
	if err := followerVerifier.verifyRaftHeadCandidate(context.Background(), result.Head,
		runtime.storage.SnapshotRaft().Log); err != nil {
		t.Fatalf("空 follower 未能用同批 Raft prefix 和复制材料重算 Head: %v", err)
	}
	t.Run("rejects tampered immutable material", func(t *testing.T) {
		tamperedObject := materials[0]
		tamperedObject.ObjectID = "sha256:" + strings.Repeat("0", 64)
		if _, err := decodeControlOperationMaterialObject(tamperedObject); err == nil {
			t.Fatal("接受了 object_id 与 exact bytes 不匹配的 operation material")
		}

		tamperedCandidate := controlClone(material)
		tamperedCandidate.Candidate.EntryHash = "sha256:" + strings.Repeat("1", 64)
		payload, err := wire.MarshalCanonical(tamperedCandidate)
		if err != nil {
			t.Fatal(err)
		}
		object, err := crdt.NewObject(tamperedCandidate.Candidate.EntryHash,
			controlOperationMaterialKind, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeControlOperationMaterialObject(object); err == nil {
			t.Fatal("接受了未绑定 body 的伪造 candidate entry hash")
		}

		duplicateLeaf := controlClone(material)
		duplicateLeaf.AdditionalLeaves = []wire.ControlOperationLeafV1{duplicateLeaf.Leaf}
		payload, err = wire.MarshalCanonical(duplicateLeaf)
		if err != nil {
			t.Fatal(err)
		}
		object, err = crdt.NewObject(duplicateLeaf.Candidate.EntryHash,
			controlOperationMaterialKind, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeControlOperationMaterialObject(object); err == nil {
			t.Fatal("接受了重复 operation ID 的 additional leaf")
		}
	})

	// Reopening must campaign again, commit/apply the barrier, and preserve the
	// exact certified operation head rather than synthesizing a second result.
	reopened, err := openControlRuntime(stateDir, clock)
	if err != nil {
		t.Fatal(err)
	}
	after := serveRuntimeStatus(t, reopened, peer)
	if after.Head.HeadHash != result.Head.HeadHash || after.Raft.Term <= status.Raft.Term ||
		after.Raft.CommitIndex != after.Raft.LastApplied {
		t.Fatalf("restart recovery changed authority or left prefix unapplied: %#v", after.Raft)
	}
	if got := reopened.operationMaterials.Snapshot(); len(got) != 1 ||
		got[0].ObjectID != materials[0].ObjectID {
		t.Fatalf("restart changed immutable operation material: %#v", got)
	}
}

type controlOperationMaterialPeerStub struct {
	err error
}

func (peer controlOperationMaterialPeerStub) Sync(context.Context) (controlplane.CRDTAntiEntropyResultV1, error) {
	return controlplane.CRDTAntiEntropyResultV1{}, peer.err
}

func TestControlOperationMaterialSyncRequiresCommittedQuorum(t *testing.T) {
	runtime := &controlRuntime{config: controlDiskConfigV1{ControlSet: wire.ControlSetV1{
		Members: []wire.ControlMemberV1{{MemberID: "member-a"}, {MemberID: "member-b"}, {MemberID: "member-c"}},
	}}, operationClients: map[string]controlOperationMaterialPeer{
		"member-b": controlOperationMaterialPeerStub{},
		"member-c": controlOperationMaterialPeerStub{err: errors.New("unreachable")},
	}}
	if err := runtime.syncOperationMaterialsToQuorum(context.Background()); err != nil {
		t.Fatalf("self + one durable remote 应达到 N=3 quorum: %v", err)
	}
	runtime.operationClients["member-b"] = controlOperationMaterialPeerStub{err: errors.New("unreachable")}
	if err := runtime.syncOperationMaterialsToQuorum(context.Background()); err == nil {
		t.Fatal("只在 leader 本机持有 operation material 时仍允许 Raft append")
	}
}

func TestConfiguredControlRuntimeDefersCampaignUntilPeerListenerCanStart(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-passive-test",
		"00000000000000000000000000", "device-test", "10.40.0.2", 21444, 21445, clock); err != nil {
		t.Fatal(err)
	}
	distribution, err := publish.ParseTarget(filepath.Join(root, "public"), "")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := openControlRuntimeConfigured(stateDir, clock, distribution)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.leader != nil {
		t.Fatal("configured serve open 在 peer listener 启动前提前 campaign")
	}
	if err := runtime.campaignAndRecover(context.Background()); err != nil || runtime.leader == nil {
		t.Fatalf("peer listener 就绪边界后的 N=1 campaign 失败: %v", err)
	}
}

func TestControlElectionTimeoutIsStaggeredAndContactGated(t *testing.T) {
	runtime := &controlRuntime{config: controlDiskConfigV1{MemberID: "member-b",
		ControlSet: wire.ControlSetV1{Members: []wire.ControlMemberV1{
			{MemberID: "member-a"}, {MemberID: "member-b"}, {MemberID: "member-c"},
		}}}}
	if got, want := runtime.electionTimeout(), controlElectionBase+controlElectionStep; got != want {
		t.Fatalf("member rank 未形成确定性错峰 election timeout: got=%s want=%s", got, want)
	}
	runtime.markRaftContact()
	if runtime.preVoteAllowed() {
		t.Fatal("刚收到合法 AppendEntries 仍允许 pre-vote")
	}
	runtime.lastRaftContact.Store(time.Now().Add(-runtime.electionTimeout() - time.Second).UnixNano())
	if !runtime.preVoteAllowed() {
		t.Fatal("超过 election timeout 后仍禁止 pre-vote")
	}
}

func TestControlRuntimeEnableLoopbackPreservesAuthorityAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-loopback-test",
		"00000000000000000000000000", "device-test", "10.40.0.2", 17944, 17945, clock); err != nil {
		t.Fatal(err)
	}
	var secrets controlDiskSecretsV1
	secretsPath := filepath.Join(stateDir, controlSecretsName)
	if err := readCanonicalFile(secretsPath, 8<<20, &secrets); err != nil {
		t.Fatal(err)
	}
	controlTLS, err := tls.X509KeyPair([]byte(secrets.ControlTLSCertificate),
		[]byte(secrets.ControlTLSPrivateKey))
	if err != nil || len(controlTLS.Certificate) != 2 {
		t.Fatalf("bootstrap control TLS: chain=%d err=%v", len(controlTLS.Certificate), err)
	}
	internalRoot, err := x509.ParseCertificate(controlTLS.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stateDir, controlBrowserTLSName)); err != nil {
		t.Fatal(err)
	}
	if err := writeBytesAtomic(filepath.Join(adminDir, controlInternalRootName),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: internalRoot.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	secretsBefore, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(filepath.Join(stateDir, controlStateName))
	if err != nil {
		t.Fatal(err)
	}
	if err := enableControlLoopback(stateDir, adminDir, clock); err != nil {
		t.Fatal(err)
	}
	stateAfter, err := os.ReadFile(filepath.Join(stateDir, controlStateName))
	if err != nil || !bytes.Equal(stateBefore, stateAfter) {
		t.Fatalf("certificate migration changed certified state: %v", err)
	}
	secretsAfter, err := os.ReadFile(secretsPath)
	if err != nil || !bytes.Equal(secretsBefore, secretsAfter) {
		t.Fatalf("browser migration changed native control secrets: %v", err)
	}
	_, browserTLS, browserRoot, err := loadControlBrowserTLS(filepath.Join(stateDir, controlBrowserTLSName),
		"runtime-loopback-test", "10.40.0.2", now)
	if err != nil {
		t.Fatal(err)
	}
	browserLeaf, err := x509.ParseCertificate(browserTLS.Certificate[0])
	if err != nil || browserLeaf.PublicKeyAlgorithm != x509.ECDSA ||
		browserLeaf.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		browserRoot.PublicKeyAlgorithm != x509.ECDSA ||
		browserRoot.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		browserLeaf.VerifyHostname(controlLoopbackIP) != nil {
		t.Fatalf("migrated browser leaf identity invalid: %v", err)
	}
	deliveredRoot := readAdminTestCertificate(t, filepath.Join(adminDir, controlInternalRootName))
	if !bytes.Equal(deliveredRoot.Raw, browserRoot.Raw) || bytes.Equal(deliveredRoot.Raw, internalRoot.Raw) {
		t.Fatal("browser migration did not replace only the delivered browser trust root")
	}
	firstMigration, err := os.ReadFile(filepath.Join(stateDir, controlBrowserTLSName))
	if err != nil {
		t.Fatal(err)
	}
	firstRoot, err := os.ReadFile(filepath.Join(adminDir, controlInternalRootName))
	if err != nil {
		t.Fatal(err)
	}
	if err := enableControlLoopback(stateDir, adminDir, clock); err != nil {
		t.Fatal(err)
	}
	secondMigration, err := os.ReadFile(filepath.Join(stateDir, controlBrowserTLSName))
	if err != nil || !bytes.Equal(firstMigration, secondMigration) {
		t.Fatalf("idempotent migration rewrote browser TLS state: %v", err)
	}
	secondRoot, err := os.ReadFile(filepath.Join(adminDir, controlInternalRootName))
	if err != nil || !bytes.Equal(firstRoot, secondRoot) {
		t.Fatalf("idempotent migration rewrote browser trust root: %v", err)
	}
}

func TestControlRuntimeEnableLoopbackRejectsUnrelatedAdminDelivery(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-loopback-a",
		"00000000000000000000000000", "device-a", "10.40.0.2", 17944, 17945, clock); err != nil {
		t.Fatal(err)
	}
	otherStateDir := filepath.Join(root, "other-state")
	otherAdminDir := filepath.Join(root, "other-admin")
	if err := bootstrapControlRuntime(otherStateDir, otherAdminDir, "runtime-loopback-b",
		"00000000000000000000000001", "device-b", "10.40.0.3", 18944, 18945, clock); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stateDir, controlBrowserTLSName)); err != nil {
		t.Fatal(err)
	}
	if err := enableControlLoopback(stateDir, otherAdminDir, clock); err == nil {
		t.Fatal("unrelated admin delivery unexpectedly authorized browser TLS migration")
	}
	if _, err := os.Lstat(filepath.Join(stateDir, controlBrowserTLSName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected migration wrote browser TLS state: %v", err)
	}
}

func TestControlRuntimeRejectsWrongAdminCertificate(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-test",
		"00000000000000000000000000", "device-test", "10.40.0.2", 18444, 18445, clock); err != nil {
		t.Fatal(err)
	}
	runtime, err := openControlRuntime(stateDir, clock)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongRoot, wrongRootKey, err := makeCertificateAuthority("wrong root",
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	wrongPEM, _, _, err := makeAdminCertificate("runtime-test", "wrong-admin",
		wrongRoot, wrongRootKey, now)
	if err != nil {
		t.Fatal(err)
	}
	wrong := certificateFromPEM(t, wrongPEM)
	request := httptest.NewRequest(http.MethodGet,
		"https://10.40.0.2:18444"+privateControlStatus, nil)
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress("10.40.0.2:18444")))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{wrong}}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong admin certificate status=%d body=%s", response.Code, response.Body.String())
	}
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedHead.Body.Payload.HeadKind != "bootstrap" {
		t.Fatal("wrong admin certificate changed certified state")
	}
}

func TestControlRuntimeBrowserUIUsesOptionalExactAdminCertificate(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-ui-test",
		"00000000000000000000000000", "device-test", "10.40.0.2", 19444, 19445, clock); err != nil {
		t.Fatal(err)
	}
	runtime, err := openControlRuntime(stateDir, clock)
	if err != nil {
		t.Fatal(err)
	}
	admin := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
	runtime.uiReadOnly = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Loom-Test-UI", "read-only")
		writer.WriteHeader(http.StatusOK)
	})
	runtime.uiAdmin = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Loom-Test-UI", "admin")
		writer.WriteHeader(http.StatusOK)
	})

	tlsConfig := runtime.controlServerTLSConfig(runtime.browserTLS)
	if tlsConfig.ClientAuth != tls.RequestClientCert || tlsConfig.MinVersion != tls.VersionTLS13 ||
		tlsConfig.MaxVersion != tls.VersionTLS13 || tlsConfig.ClientCAs == nil ||
		len(tlsConfig.ClientCAs.Subjects()) == 0 {
		t.Fatalf("control browser TLS policy = %#v", tlsConfig)
	}

	if response := serveRuntimeUI(t, runtime, http.MethodGet, "/", nil, "", ""); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "read-only" {
		t.Fatalf("no-certificate GET = %d headers=%v", response.Code, response.Header())
	}
	loopbackAddress := net.JoinHostPort(controlLoopbackIP, fmt.Sprint(runtime.config.ControlPort))
	if response := serveRuntimeUIAt(t, runtime, loopbackAddress, http.MethodGet, "/", nil, "", ""); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "read-only" {
		t.Fatalf("forwarded no-certificate GET = %d headers=%v", response.Code, response.Header())
	}
	if response := serveRuntimeUI(t, runtime, http.MethodGet, "/settings", admin, "", ""); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "admin" {
		t.Fatalf("admin-certificate GET = %d headers=%v", response.Code, response.Header())
	}

	_, wrongRoot, wrongRootKey, err := makeCertificateAuthority("wrong browser root",
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	wrongPEM, _, _, err := makeAdminCertificate("runtime-ui-test", "wrong-browser-admin",
		wrongRoot, wrongRootKey, now)
	if err != nil {
		t.Fatal(err)
	}
	wrong := certificateFromPEM(t, wrongPEM)
	if response := serveRuntimeUI(t, runtime, http.MethodGet, "/", wrong, "", ""); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "read-only" {
		t.Fatalf("wrong-certificate GET = %d headers=%v", response.Code, response.Header())
	}

	if response := serveRuntimeUI(t, runtime, http.MethodPost, "/devices/create", nil,
		"https://10.40.0.2:19444", "same-origin"); response.Code != http.StatusForbidden {
		t.Fatalf("no-certificate POST = %d body=%s", response.Code, response.Body.String())
	}
	if response := serveRuntimeUI(t, runtime, http.MethodPost, "/devices/create", admin,
		"", "same-origin"); response.Code != http.StatusForbidden {
		t.Fatalf("admin POST without Origin = %d body=%s", response.Code, response.Body.String())
	}
	if response := serveRuntimeUI(t, runtime, http.MethodPost, "/devices/create", admin,
		"https://10.40.0.2:19444", "cross-site"); response.Code != http.StatusForbidden {
		t.Fatalf("cross-site admin POST = %d body=%s", response.Code, response.Body.String())
	}
	if response := serveRuntimeUI(t, runtime, http.MethodPost, "/devices/create", admin,
		"https://10.40.0.2:19444", "same-origin"); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "admin" {
		t.Fatalf("same-origin admin POST = %d headers=%v body=%s",
			response.Code, response.Header(), response.Body.String())
	}
	if response := serveRuntimeUIAt(t, runtime, loopbackAddress, http.MethodPost, "/devices/create", admin,
		"https://"+loopbackAddress, "same-origin"); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "admin" {
		t.Fatalf("forwarded same-origin admin POST = %d headers=%v body=%s",
			response.Code, response.Header(), response.Body.String())
	}
	if response := serveRuntimeUIWebSocket(t, runtime, loopbackAddress, "", "same-origin"); response.Code != http.StatusForbidden {
		t.Fatalf("WebSocket without Origin = %d body=%s", response.Code, response.Body.String())
	}
	if response := serveRuntimeUIWebSocket(t, runtime, loopbackAddress, "https://cross-site.example", "cross-site"); response.Code != http.StatusForbidden {
		t.Fatalf("cross-site WebSocket = %d body=%s", response.Code, response.Body.String())
	}
	if response := serveRuntimeUIWebSocket(t, runtime, loopbackAddress, "https://"+loopbackAddress, "same-origin"); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "read-only" {
		t.Fatalf("same-origin WebSocket routing = %d headers=%v body=%s",
			response.Code, response.Header(), response.Body.String())
	}

	// Expiry is checked against the certified authorization on every request;
	// an exact but expired leaf degrades to read-only and can never write.
	runtime.now = func() time.Time { return now.Add(366 * 24 * time.Hour) }
	if response := serveRuntimeUI(t, runtime, http.MethodGet, "/", admin, "", ""); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "read-only" {
		t.Fatalf("expired admin GET = %d headers=%v", response.Code, response.Header())
	}
	if response := serveRuntimeUI(t, runtime, http.MethodPost, "/devices/create", admin,
		"https://10.40.0.2:19444", "same-origin"); response.Code != http.StatusForbidden {
		t.Fatalf("expired admin POST = %d body=%s", response.Code, response.Body.String())
	}

	runtime.now = clock
	runtime.config.Authorizations[0].Status = "revoked"
	if response := serveRuntimeUI(t, runtime, http.MethodGet, "/", admin, "", ""); response.Code != http.StatusOK || response.Header().Get("X-Loom-Test-UI") != "read-only" {
		t.Fatalf("revoked admin GET = %d headers=%v", response.Code, response.Header())
	}
	if response := serveRuntimeUI(t, runtime, http.MethodPost, "/devices/create", admin,
		"https://10.40.0.2:19444", "same-origin"); response.Code != http.StatusForbidden {
		t.Fatalf("revoked admin POST = %d body=%s", response.Code, response.Body.String())
	}
}

func TestControlRuntimeBrowserUIRejectsNonUIAndWrongListener(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	adminDir := filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	if err := bootstrapControlRuntime(stateDir, adminDir, "runtime-ui-boundary-test",
		"00000000000000000000000000", "device-test", "10.40.0.2", 20444, 20445,
		func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	runtime, err := openControlRuntime(stateDir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	runtime.uiReadOnly = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		t.Fatal("rejected path reached read-only UI")
	})
	runtime.uiAdmin = runtime.uiReadOnly

	for _, rejectedPath := range []string{"/api/client/enroll", "/api/control/../client/enroll",
		"/api/control/%2e%2e/client/enroll"} {
		if response := serveRuntimeUI(t, runtime, http.MethodGet, rejectedPath, nil, "", ""); response.Code != http.StatusNotFound {
			t.Fatalf("rejected path %q on control UI = %d", rejectedPath, response.Code)
		}
	}
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	request := httptest.NewRequest(http.MethodGet, "https://"+address+"/", nil)
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress("127.0.0.1:20444")))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("wrong listener address UI = %d", response.Code)
	}

	statusRequest := httptest.NewRequest(http.MethodGet, "https://"+address+privateControlStatus, nil)
	statusRequest = statusRequest.WithContext(context.WithValue(statusRequest.Context(),
		http.LocalAddrContextKey, controlTestAddress(address)))
	statusRequest.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	statusResponse := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusForbidden {
		t.Fatalf("private status without admin certificate = %d", statusResponse.Code)
	}

	admin := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
	loopbackAddress := net.JoinHostPort(controlLoopbackIP, fmt.Sprint(runtime.config.ControlPort))
	forwardedStatus := httptest.NewRequest(http.MethodGet,
		"https://"+loopbackAddress+privateControlStatus, nil)
	forwardedStatus = forwardedStatus.WithContext(context.WithValue(forwardedStatus.Context(),
		http.LocalAddrContextKey, controlTestAddress(loopbackAddress)))
	forwardedStatus.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{admin}}
	forwardedResponse := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(forwardedResponse, forwardedStatus)
	if forwardedResponse.Code != http.StatusForbidden {
		t.Fatalf("private status escaped onto browser loopback = %d", forwardedResponse.Code)
	}
}

func serveRuntimeUI(t *testing.T, runtime *controlRuntime, method, path string,
	peer *x509.Certificate, origin, fetchSite string) *httptest.ResponseRecorder {
	t.Helper()
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	return serveRuntimeUIAt(t, runtime, address, method, path, peer, origin, fetchSite)
}

func serveRuntimeUIAt(t *testing.T, runtime *controlRuntime, address, method, path string,
	peer *x509.Certificate, origin, fetchSite string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "https://"+address+path, nil)
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress(address)))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	if peer != nil {
		request.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if fetchSite != "" {
		request.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	return response
}

func serveRuntimeUIWebSocket(t *testing.T, runtime *controlRuntime, address, origin, fetchSite string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet,
		"https://"+address+"/api/control/device-inventory/live", nil)
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress(address)))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	request.Header.Set("Connection", "keep-alive, Upgrade")
	request.Header.Set("Upgrade", "websocket")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if fetchSite != "" {
		request.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	return response
}

func serveRuntimeStatus(t *testing.T, runtime *controlRuntime,
	peer *x509.Certificate) controlStatusResponseV1 {
	t.Helper()
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	request := httptest.NewRequest(http.MethodGet, "https://"+address+privateControlStatus, nil)
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress(address)))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{peer}}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var status controlStatusResponseV1
	canonical, err := wire.DecodeStrict(response.Body.Bytes(), controlMaxResponseSize, &status)
	if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) {
		t.Fatalf("status response not canonical: %v", err)
	}
	return status
}

func serveRuntimeOperation(t *testing.T, runtime *controlRuntime, peer *x509.Certificate,
	submitted controlOperationRequestV1, wantStatus int) controlCertifiedOperationResultV1 {
	t.Helper()
	body, err := wire.MarshalCanonical(submitted)
	if err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	request := httptest.NewRequest(http.MethodPost,
		"https://"+address+controlplane.PrivateControlOperationPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey,
		controlTestAddress(address)))
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{peer}}
	response := httptest.NewRecorder()
	runtime.controlHandler().ServeHTTP(response, request)
	if response.Code != wantStatus {
		t.Fatalf("operation status=%d body=%s", response.Code, response.Body.String())
	}
	var result controlCertifiedOperationResultV1
	if wantStatus == http.StatusOK {
		canonical, err := wire.DecodeStrict(response.Body.Bytes(), controlMaxResponseSize, &result)
		if err != nil || !bytes.Equal(canonical, response.Body.Bytes()) {
			t.Fatalf("operation response not canonical: %v", err)
		}
	}
	return result
}

func readAdminTestCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return certificateFromPEM(t, body)
}

func certificateFromPEM(t *testing.T, body []byte) *x509.Certificate {
	t.Helper()
	block, trailing := pem.Decode(body)
	if block == nil || len(bytes.TrimSpace(trailing)) != 0 {
		t.Fatal("invalid certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

type controlTestAddress string

func (address controlTestAddress) Network() string { return "tcp" }
func (address controlTestAddress) String() string  { return string(address) }

var _ net.Addr = controlTestAddress("")
