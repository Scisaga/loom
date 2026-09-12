package certmanager

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestRFC8555ClientKeepsAccountKeyLocalAndHardensHTTP(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "acme", "account.pem")
	proxyCalled := false
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = func(*http.Request) (*url.URL, error) {
		proxyCalled = true
		return url.Parse("https://proxy.example")
	}
	client, err := NewRFC8555Client(RFC8555Config{
		DirectoryURL: "https://acme.example/directory", AccountKeyPath: keyPath,
		ContactEmail: "operator@example.test", Timeout: 10 * time.Second, AcceptTerms: true,
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("account key 不是节点本地 0600 regular file: mode=%v", info.Mode())
	}
	hardened, ok := client.client.HTTPClient.Transport.(sameOriginTransport)
	if !ok || hardened.base.(*http.Transport).Proxy != nil {
		t.Fatal("ACME HTTP client 没有禁用环境/调用方 proxy")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://other.example/account", nil)
	if _, err := hardened.RoundTrip(request); err == nil || proxyCalled {
		t.Fatal("跨 origin ACME request 未失败关闭或错误调用了 proxy")
	}
	redirect, _ := http.NewRequest(http.MethodGet, "https://other.example/redirect", nil)
	if err := client.client.HTTPClient.CheckRedirect(redirect, nil); err != http.ErrUseLastResponse {
		t.Fatal("ACME redirect 未被拒绝")
	}
	if _, err := NewRFC8555Client(RFC8555Config{
		DirectoryURL: "http://acme.example/directory", AccountKeyPath: filepath.Join(t.TempDir(), "key.pem"),
		ContactEmail: "operator@example.test", Timeout: 10 * time.Second,
	}); err == nil {
		t.Fatal("明文 ACME directory 被接受")
	}
}

func TestRFC8555ClientRejectsProviderResourceOriginExpansion(t *testing.T) {
	origin, _ := url.Parse("https://acme.example/directory")
	client := &RFC8555Client{origin: origin}
	order := &acme.Order{
		URI: "https://acme.example/order/1", Status: acme.StatusPending,
		Identifiers: []acme.AuthzID{{Type: "dns", Value: "demo-edge.example"}},
		AuthzURLs:   []string{"https://evil.example/authz/1"}, FinalizeURL: "https://acme.example/finalize/1",
	}
	if err := client.validateOrder(order, []string{"demo-edge.example"}); err == nil {
		t.Fatal("CA 返回的跨 origin authorization URL 被接受")
	}
	order.AuthzURLs[0] = "https://acme.example/authz/1"
	if err := client.validateOrder(order, []string{"demo-edge.example"}); err != nil {
		t.Fatal(err)
	}
}

func TestLoadP256RejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	realPath := filepath.Join(directory, "real.pem")
	client, err := NewRFC8555Client(RFC8555Config{
		DirectoryURL: "https://acme.example/directory", AccountKeyPath: realPath,
		ContactEmail: "operator@example.test", Timeout: 10 * time.Second,
	})
	if err != nil || client == nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "link.pem")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRFC8555Client(RFC8555Config{
		DirectoryURL: "https://acme.example/directory", AccountKeyPath: linkPath,
		ContactEmail: "operator@example.test", Timeout: 10 * time.Second,
	}); err == nil {
		t.Fatal("symlink account private key 被接受")
	}
}
