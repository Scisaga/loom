package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"loom/internal/clientrelease"
	"loom/internal/releasefloor"
)

var testAdminCertificateDER, testReadCertificateDER = testBrowserAuthorizationCertificates()

func testBrowserAuthorizationCertificates() ([]byte, []byte) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "demo-admin-ca"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		panic(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		panic(err)
	}
	issue := func(serial int64, name string) []byte {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			panic(keyErr)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, createErr := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
		if createErr != nil {
			panic(createErr)
		}
		return der
	}
	return issue(102, "demo-admin"), issue(103, "demo-reader")
}

func testState() State {
	digest := strings.Repeat("0", 64)
	return State{
		Schema: StateSchema, ClusterID: "demo-cluster", Listen: "10.0.0.1:8443",
		Head: CertifiedHead{Hash: "sha256:" + digest, Index: 7, Revision: 7},
		Recovery: RecoveryEvidence{ConfigSHA256: digest, CertifiedSHA256: digest, OperationsSHA256: digest,
			ReleaseFloorSHA256: digest, ReleaseFloor: releasefloor.Record{Schema: 1, Generation: 3,
				PayloadSHA256: digest, SelectedSnapshot: "000000000000"}, V2Latch: true},
		BrowserTLS: BrowserTLS{CertificateChainPEM: "present", PrivateKeyPKCS8PEM: "present",
			RootPrivateKeyPKCS8PEM: "present"},
		ReadCertDER:  []string{base64.RawURLEncoding.EncodeToString(testAdminCertificateDER)},
		AdminCertDER: []string{base64.RawURLEncoding.EncodeToString(testAdminCertificateDER)},
		Projection: WebProjection{Schema: 1, UIState: UIState{Head: "sha256:" + digest, Revision: 7,
			Writable: false, Warnings: []string{}}, Devices: []Device{}, Links: []Link{}, Paths: []Path{},
			Services: []Service{}, Releases: []Release{}, Events: []Event{}},
	}
}

func testRuntimeServer(t *testing.T, state State) *Server {
	t.Helper()
	root := t.TempDir()
	state.BrowserTLS = testTLS(t)
	address := state.Listen
	config, err := ActivateLegacy(root, state, "demo-control", "demo-node", []string{address})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	channel := &PrivateChannel{config: PrivateChannelConfig{Node: "demo-node", Listen: []string{address}}}
	return &Server{Runtime: &Runtime{Config: config, Authority: authority}, Channel: channel, Config: config}
}

func TestStateSurvivesRestartExactly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := testState()
	if err := SaveState(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restart changed state:\nwant %#v\ngot  %#v", want, got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}
}

func TestPrivateProjectionAndRetiredRoutes(t *testing.T) {
	state := testState()
	state.ReadCertDER = append(state.ReadCertDER, base64.RawURLEncoding.EncodeToString(testReadCertificateDER))
	server := testRuntimeServer(t, state)
	server.ReleaseRoot = t.TempDir()
	server.ReleaseKey = filepath.Join(t.TempDir(), "missing")
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/", http.StatusOK},
		{http.MethodGet, "/api/control/ui/snapshot", http.StatusOK},
		{http.MethodGet, "/api/client/report", http.StatusNotFound},
		{http.MethodPost, "/v2/enrollment/claim", http.StatusNotFound},
		{http.MethodPost, "/v2/enrollment/resume", http.StatusNotFound},
		{http.MethodPost, "/v2/device/config", http.StatusNotFound},
		{http.MethodPost, "/v2/device/report", http.StatusNotFound},
		{http.MethodGet, "/act/device", http.StatusNotFound},
		{http.MethodGet, "/device-dist/current", http.StatusNotFound},
		{http.MethodPost, "/", http.StatusNotFound},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://10.0.0.1:8443"+test.path, nil)
			request.Host = "10.0.0.1:8443"
			request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
				PeerCertificates: []*x509.Certificate{{Raw: testAdminCertificateDER}}}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
	request := httptest.NewRequest(http.MethodGet, "https://10.0.0.1:8443/", nil)
	request.Host = "10.0.0.1:8443"
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "https://10.0.0.1:8443/api/control/ui/snapshot", nil)
	request.Host = "10.0.0.1:8443"
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{Raw: testReadCertificateDER}}}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `"admin":true`) {
		t.Fatalf("read credential did not remain read-only: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestReleaseDownloadReturnsOnlyVerifiedExactBytes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "platform.pub")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifactBody := []byte("exact release bytes")
	checksumBody := []byte("checksum")
	signatureBody := []byte("signature")
	file := writeReleaseFile(t, root, "demo.bin", artifactBody)
	checksum := writeReleaseFile(t, root, "demo.sha256", checksumBody)
	signature := writeReleaseFile(t, root, "demo.sig", signatureBody)
	catalog := clientrelease.Catalog{Schema: 1, Artifacts: []clientrelease.Artifact{{File: file,
		Filename: file.Name, Title: "Demo", Platform: "linux-server", Arch: "amd64", Variant: "default",
		Version: "1", SourceCommit: strings.Repeat("a", 40), Signing: "ed25519", Checksum: checksum, Signature: signature}}}
	catalogBody, _ := json.Marshal(catalog)
	catalogHash := sha256.Sum256(catalogBody)
	catalogDigest := hex.EncodeToString(catalogHash[:])
	catalogDir := filepath.Join(root, "catalogs", catalogDigest)
	if err := os.MkdirAll(catalogDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(catalogDir, "catalog.json"), catalogBody, 0o600); err != nil {
		t.Fatal(err)
	}
	signed := ed25519.Sign(private, append([]byte("loom-client-releases-v1\n"), catalogBody...))
	if err := os.WriteFile(filepath.Join(catalogDir, "catalog.sig"), []byte(base64.StdEncoding.EncodeToString(signed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pointer, _ := json.Marshal(map[string]string{"catalog": "catalogs/" + catalogDigest + "/catalog.json"})
	if err := os.WriteFile(filepath.Join(root, "current.json"), pointer, 0o600); err != nil {
		t.Fatal(err)
	}

	server := testRuntimeServer(t, testState())
	server.ReleaseRoot = root
	server.ReleaseKey = keyPath
	request := httptest.NewRequest(http.MethodGet, "https://10.0.0.1:8443/api/control/ui/releases/files/"+file.Path, nil)
	request.Host = "10.0.0.1:8443"
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{Raw: testAdminCertificateDER}}}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !reflect.DeepEqual(response.Body.Bytes(), artifactBody) {
		t.Fatalf("download status=%d body=%q", response.Code, response.Body.Bytes())
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(file.Path)), []byte("tampered release"), 0o600); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("tampered release status=%d", response.Code)
	}
}

func writeReleaseFile(t *testing.T, root, name string, body []byte) clientrelease.File {
	t.Helper()
	digest := sha256.Sum256(body)
	hexDigest := hex.EncodeToString(digest[:])
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", hexDigest), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return clientrelease.File{Name: name, Path: "bin/" + hexDigest, SHA256: hexDigest, Size: int64(len(body))}
}

func TestPreservedWebUIShellUsesCurrentProjection(t *testing.T) {
	server := testRuntimeServer(t, testState())
	for _, test := range []struct {
		path       string
		contains   []string
		notContain []string
	}{
		{path: "/", contains: []string{"/assets/network.css", ">Topology<", ">Live paths<", ">Events<"}},
		{path: "/assets/app.js", contains: []string{"/api/control/ui/snapshot", "/api/control/ui/live", "Certified network"},
			notContain: []string{"device-inventory/live", "/api/control/ui/ssot"}},
	} {
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d", test.path, response.Code)
		}
		body := response.Body.String()
		for _, value := range test.contains {
			if !strings.Contains(body, value) {
				t.Fatalf("%s does not contain %q", test.path, value)
			}
		}
		for _, value := range test.notContain {
			if strings.Contains(body, value) {
				t.Fatalf("%s retained obsolete API %q", test.path, value)
			}
		}
	}
}

func TestWebSocketStartsWithCurrentSnapshot(t *testing.T) {
	server := testRuntimeServer(t, testState())
	server.ReleaseRoot = t.TempDir()
	server.ReleaseKey = filepath.Join(t.TempDir(), "missing")
	httpServer := httptest.NewServer(http.HandlerFunc(server.live))
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/api/control/ui/live", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	var snapshot struct {
		Projection WebProjection `json:"projection"`
	}
	if err := wsjson.Read(ctx, connection, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Projection.UIState.Head == "" || snapshot.Projection.UIState.Revision == 0 {
		t.Fatalf("live snapshot head=%q", snapshot.Projection.UIState.Head)
	}
}
