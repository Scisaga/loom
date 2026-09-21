package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type chromeClientIdentity struct {
	name    string
	certDER []byte
	certPEM []byte
	keyPEM  []byte
}

type chromeTLSFixture struct {
	browser BrowserTLS
	rootPEM []byte
	admin   chromeClientIdentity
	reader  chromeClientIdentity
}

// TestWebTLSClientCertificatesChrome verifies the product handler through a
// real TLS 1.3 socket and Chrome's NSS client-certificate selection. It is
// opt-in because it requires Chrome and the libnss3-tools test utilities.
func TestWebTLSClientCertificatesChrome(t *testing.T) {
	if os.Getenv("LOOM_WEB_TLS_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_TLS_CHROME_TEST=1 to run the Chrome mTLS acceptance")
	}
	chrome := requireExecutable(t, "google-chrome")
	requireExecutable(t, "certutil")
	requireExecutable(t, "pk12util")
	requireExecutable(t, "openssl")
	installChromeClientCertificatePolicy(t)

	fixture := newChromeTLSFixture(t)
	state := testState()
	state.Projection = visualWebProjection()
	state.BrowserTLS = fixture.browser
	state.ReadCertDER = []string{
		base64.RawURLEncoding.EncodeToString(fixture.admin.certDER),
		base64.RawURLEncoding.EncodeToString(fixture.reader.certDER),
	}
	state.AdminCertDER = []string{base64.RawURLEncoding.EncodeToString(fixture.admin.certDER)}
	server := testWritableRuntimeServer(t, state)
	server.Config.BrowserTLS = fixture.browser
	server.Config.ReadCertDER = append([]string(nil), state.ReadCertDER...)
	server.Config.AdminCertDER = append([]string(nil), state.AdminCertDER...)
	intent := testNetworkIntent(t)
	server.Runtime.Authority.mu.Lock()
	server.Runtime.Authority.projection.NetworkIntent = &intent
	server.Runtime.Authority.certified.Projection.NetworkIntent = &intent
	server.Runtime.Authority.mu.Unlock()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	server.Channel.config.Listen = []string{address}
	tlsConfig, err := browserTLSConfig(server.Config)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	tlsConfig.NextProtos = []string{"http/1.1"}
	httpServer := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second}
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(tls.NewListener(listener, tlsConfig)) }()
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
		<-served
	})
	target := "https://" + address + "/devices"

	// RequireAnyClientCert must reject a normal TLS client before HTTP. This
	// guards against accidentally testing only the handler's DER comparison.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(fixture.rootPEM)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool,
	}}}
	if response, requestErr := client.Get(target); requestErr == nil {
		response.Body.Close()
		t.Fatal("TLS listener accepted a browser request without a client certificate")
	}

	adminDOM := chromeDOM(t, chrome, fixture.rootPEM, fixture.admin, target)
	if !strings.Contains(adminDOM, "Admin ·") || !strings.Contains(adminDOM, "Add Device") {
		t.Fatalf("admin Chrome profile did not receive the writable SPA capability: %s", boundedText(adminDOM))
	}
	readerDOM := chromeDOM(t, chrome, fixture.rootPEM, fixture.reader, target)
	if !strings.Contains(readerDOM, "Read only ·") || strings.Contains(readerDOM, ">＋ Add Device<") {
		t.Fatalf("reader Chrome profile received the wrong SPA capability: %s", boundedText(readerDOM))
	}
}

func installChromeClientCertificatePolicy(t *testing.T) {
	t.Helper()
	// Packaged Google Chrome only accepts client-certificate auto-selection as
	// managed policy. This opt-in acceptance therefore installs one bounded,
	// test-only policy and removes it before returning; it never carries a
	// certificate, key or production address.
	directory := "/etc/opt/chrome/policies/managed"
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("create Chrome test policy directory: %v", err)
	}
	path := filepath.Join(directory, "loom-web-tls-test.json")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("refusing to replace an existing Chrome policy at %s", path)
	}
	body := []byte(`{"AutoSelectCertificateForUrls":["{\"pattern\":\"https://127.0.0.1:*\",\"filter\":{}}"]}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("install Chrome test policy: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove Chrome test policy: %v", err)
		}
	})
}

func requireExecutable(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s is required: %v", name, err)
	}
	return path
}

func newChromeTLSFixture(t *testing.T) chromeTLSFixture {
	t.Helper()
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(700), Subject: pkix.Name{CommonName: "demo-browser-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	issue := func(serial int64, name string, usages []x509.ExtKeyUsage, addresses []net.IP) chromeClientIdentity {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: usages, IPAddresses: addresses}
		der, createErr := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		keyDER, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return chromeClientIdentity{name: name, certDER: der,
			certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
	}
	server := issue(701, "demo-control", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")})
	rootKeyDER, err := x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return chromeTLSFixture{
		browser: BrowserTLS{
			CertificateChainPEM:    string(append(append([]byte(nil), server.certPEM...), rootPEM...)),
			PrivateKeyPKCS8PEM:     string(server.keyPEM),
			RootPrivateKeyPKCS8PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rootKeyDER})),
		},
		rootPEM: rootPEM,
		admin:   issue(702, "demo-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil),
		reader:  issue(703, "demo-reader", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil),
	}
}

func chromeDOM(t *testing.T, chrome string, rootPEM []byte, identity chromeClientIdentity, target string) string {
	t.Helper()
	home, profile, autoSelect := chromeIdentityProfile(t, rootPEM, identity)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
		"--user-data-dir="+profile, "--auto-select-certificate-for-urls="+autoSelect,
		"--virtual-time-budget=3000", "--dump-dom", target)
	command.Env = append(os.Environ(), "HOME="+home)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		t.Fatalf("Chrome mTLS request failed: %v: %s", err, boundedText(output.String()))
	}
	return output.String()
}

func chromeIdentityProfile(t *testing.T, rootPEM []byte, identity chromeClientIdentity) (string, string, string) {
	t.Helper()
	home := t.TempDir()
	database := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(database, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(command string, arguments ...string) {
		result := exec.Command(command, arguments...)
		if output, err := result.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v: %s", filepath.Base(command), err, output)
		}
	}
	run("certutil", "-N", "--empty-password", "-d", "sql:"+database)
	rootPath := filepath.Join(home, "root.pem")
	certPath := filepath.Join(home, "client.pem")
	keyPath := filepath.Join(home, "client.key")
	bundlePath := filepath.Join(home, "client.p12")
	for path, body := range map[string][]byte{rootPath: rootPEM, certPath: identity.certPEM, keyPath: identity.keyPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run("certutil", "-A", "-d", "sql:"+database, "-n", "loom-test-root", "-t", "C,,", "-i", rootPath)
	const password = "loom-test-only"
	run("openssl", "pkcs12", "-export", "-out", bundlePath, "-inkey", keyPath, "-in", certPath,
		"-certfile", rootPath, "-name", identity.name, "-passout", "pass:"+password)
	run("pk12util", "-i", bundlePath, "-d", "sql:"+database, "-W", password)

	profile := filepath.Join(home, "chrome-profile")
	if err := os.MkdirAll(filepath.Join(profile, "Default"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Chrome maps the Linux AutoSelectCertificateForUrls policy to this
	// per-profile preference. Keep the command-line setting as well because the
	// browser test must work with both the packaged stable and test Chrome.
	preference := `{"profile":{"managed_auto_select_certificate_for_urls":["{\"pattern\":\"https://127.0.0.1:*\",\"filter\":{}}"]}}`
	if err := os.WriteFile(filepath.Join(profile, "Default", "Preferences"), []byte(preference), 0o600); err != nil {
		t.Fatal(err)
	}
	autoSelect := `["{\"pattern\":\"https://127.0.0.1:*\",\"filter\":{}}"]`
	return home, profile, autoSelect
}

func boundedText(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1024 {
		return fmt.Sprintf("%s…", value[:1024])
	}
	return value
}
