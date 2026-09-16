package distribution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/wire"
)

func TestRenderNginxHasOnlyFakeAndImmutableSurface(t *testing.T) {
	config, err := RenderNginx(NginxInput{
		FQDN: "demo-edge.example", ListenPort: 8443,
		Certificate: "/etc/loom/public-tls/cert.pem", CertificateKey: "/etc/loom/public-tls/key.pem",
		StaticRoot: "/var/www/loom-public",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "proxy_pass") || strings.Contains(string(config), "POST") {
		t.Fatalf("dynamic public surface leaked:\n%s", config)
	}
	if !strings.Contains(string(config), `location ~ "^/distribution/sha256/[0-9a-f]{64}$"`) {
		t.Fatalf("Nginx regex containing braces must be quoted:\n%s", config)
	}
	if strings.Count(string(config), `if ($args != "") { return 404; }`) != 2 {
		t.Fatalf("fake/static Nginx locations must reject query strings:\n%s", config)
	}
	if err := ValidatePublicNginx(append(append([]byte(nil), config...), config...)); err != nil {
		t.Fatalf("multiple generated public servers must remain valid: %v", err)
	}
	for _, malicious := range []string{
		string(config) + "\nproxy_pass http://127.0.0.1:9000;",
		string(config) + "\nlocation /claim { return 200; }",
		string(config) + "\nlocation /current.json { alias /tmp/current; }",
		strings.Replace(string(config), "limit_except GET HEAD", "", 1),
		strings.Replace(string(config), `if ($args != "") { return 404; }`, "", 1),
	} {
		if err := ValidatePublicNginx([]byte(malicious)); err == nil {
			t.Fatal("accepted dynamic handler in public Nginx")
		}
	}
}

func TestStaticHandlerRejectsPathFuzzAndWrites(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifactPath, err := PublishArtifact(root, []byte("artifact"))
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.TrimPrefix(artifactPath, "/distribution/sha256/")
	handler, err := StaticHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/", http.StatusOK},
		{http.MethodHead, "/distribution/sha256/" + digest, http.StatusOK},
		{http.MethodPost, "/distribution/sha256/" + digest, http.StatusMethodNotAllowed},
		{http.MethodGet, "/claim", http.StatusNotFound},
		{http.MethodGet, "/control_api", http.StatusNotFound},
		{http.MethodGet, "/distribution/sha256/../" + digest, http.StatusNotFound},
		{http.MethodGet, "/distribution/sha256/" + digest + "?token=x", http.StatusNotFound},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Errorf("%s %s = %d, want %d", test.method, test.path, response.Code, test.status)
		}
	}
}

func TestStaticHandlerIsTransportNotHashAuthority(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "distribution", "sha256")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(directory, digest), []byte("wrong bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := StaticHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/distribution/sha256/"+digest, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "wrong bytes" {
		t.Fatalf("静态镜像未按 opaque typed-hash 路径返回 bytes: status=%d body=%q",
			response.Code, response.Body.String())
	}
	if hash, err := wire.HashCanonical(wire.DomainDeviceConfigArtifact, []byte("wrong bytes")); err == nil && hash == "sha256:"+digest {
		t.Fatal("consumer-side canonical/typed hash rejection 未生效")
	}
}

func TestPublishDeviceConfigArtifactUsesTypedHashAndIsFetchable(t *testing.T) {
	root := t.TempDir()
	body := []byte(`{"files":{"sing-box/config.json":"{}"},"owner":"android-a"}`)
	ref, artifactPath, err := PublishDeviceConfigArtifact(root, "android-runtime", "android",
		"application/vnd.loom.config+json", "android-runtime-v1", 7, body)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, err := wire.DeviceConfigArtifactContentHash(body)
	if err != nil {
		t.Fatal(err)
	}
	raw := sha256.Sum256(body)
	if ref.ContentHash != wantHash || ref.ContentHash == "sha256:"+hex.EncodeToString(raw[:]) ||
		ref.SizeBytes != int64(len(body)) || ref.Generation != 7 {
		t.Fatalf("config ref 未使用 exact typed hash: %+v", ref)
	}
	digest, _ := wire.ParseHash(wantHash)
	if artifactPath != "/distribution/sha256/"+hex.EncodeToString(digest) {
		t.Fatalf("artifact path=%q", artifactPath)
	}
	handler, err := StaticHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, artifactPath, nil))
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), body) {
		t.Fatalf("typed artifact response status=%d body=%q", response.Code, response.Body.Bytes())
	}

	if _, _, err := PublishDeviceConfigArtifact(root, "android-runtime", "android",
		"application/vnd.loom.config+json", "android-runtime-v1", 8,
		[]byte("{\n  \"schema\": 1\n}\n")); err == nil {
		t.Fatal("接受了非 exact canonical config artifact")
	}
	if _, _, err := PublishDeviceConfigArtifact(root, "android-runtime", "ios",
		"application/vnd.loom.config+json", "android-runtime-v1", 8, body); err == nil {
		t.Fatal("接受了 artifact contract/platform 不一致")
	}
}
