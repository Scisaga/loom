package distribution

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderNginxHasOnlyFakeAndImmutableSurface(t *testing.T) {
	config, err := RenderNginx(NginxInput{
		FQDN: "demo-edge.example", PublicPort: 8443,
		Certificate: "/etc/loom/public-tls/cert.pem", CertificateKey: "/etc/loom/public-tls/key.pem",
		StaticRoot: "/var/www/loom-public",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "proxy_pass") || strings.Contains(string(config), "POST") {
		t.Fatalf("dynamic public surface leaked:\n%s", config)
	}
	for _, malicious := range []string{
		string(config) + "\nproxy_pass http://127.0.0.1:9000;",
		string(config) + "\nlocation /claim { return 200; }",
		string(config) + "\nlocation /current.json { alias /tmp/current; }",
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
	digest := strings.Repeat("a", 64)
	path := filepath.Join(root, "distribution", "sha256")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, digest), []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
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
