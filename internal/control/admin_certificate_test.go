package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func adminTestLeaf(t *testing.T, root string, ca transportCA, name string, usages []x509.ExtKeyUsage) (AdminCertificate, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, pair, leaf := testTransportIdentity(t, root, name, 50, key, ca, usages)
	return AdminCertificate{ID: AdminCertificateID(leaf.Raw), CertificateDER: base64.RawURLEncoding.EncodeToString(leaf.Raw)}, pair
}

func TestAdminCertificateCanonicalIdentityAndConcurrentRevocation(t *testing.T) {
	f := newMaterialFixture(t)
	parent := t.TempDir()
	ca := testTransportCA(t, parent)
	value, _ := adminTestLeaf(t, parent, ca, "demo-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	// The original genesis identity is deliberately not the new derived ID.
	value.ID = "demo-existing-admin"
	g := f.genesis.Payload.(Genesis)
	g.AdminCertificates = []AdminCertificate{value}
	f.genesis.Payload = g
	f.genesis.Signature = ""
	var err error
	f.genesis, err = SignMaterial(f.genesis, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	original, genesisID, err := EncodeMaterial(f.genesis)
	if err != nil {
		t.Fatal(err)
	}
	deleted := f.sign(t, 0, 1, nil, "demo-revoke-admin", "admin_certificate.delete", "admin_certificate", value.ID, DeleteTarget{ID: value.ID}, genesisID)
	concurrent := f.sign(t, 1, 1, nil, "demo-refresh-admin", "admin_certificate.put", "admin_certificate", value.ID, value, genesisID)
	for _, facts := range [][]Material{{deleted, concurrent}, {concurrent, deleted}} {
		p, err := Project(f.genesis, nil, facts)
		if err != nil || len(p.AdminCertificates) != 0 || len(p.InvalidMaterials) != 0 {
			t.Fatalf("revocation did not win: %v", err)
		}
	}
	newValue, _ := adminTestLeaf(t, parent, ca, "demo-admin-new", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	newValue.ID = value.ID
	replaced := f.sign(t, 0, 2, &deleted, "demo-rebind-admin", "admin_certificate.put", "admin_certificate", value.ID, newValue, materialTestID(t, deleted))
	if err := ValidateAdmission(replaced, f.genesis, nil, []Material{deleted}); err == nil {
		t.Fatal("certificate ID rebound after withdrawal")
	}
	alias := value
	der, _ := base64.RawURLEncoding.DecodeString(alias.CertificateDER)
	alias.ID = AdminCertificateID(der)
	duplicate := f.sign(t, 0, 2, &deleted, "demo-alias-admin", "admin_certificate.put", "admin_certificate", alias.ID, alias)
	if err := ValidateAdmission(duplicate, f.genesis, nil, []Material{deleted}); err == nil {
		t.Fatal("revoked leaf returned under a new ID")
	}
	regrant := f.sign(t, 0, 2, &deleted, "demo-regrant-admin", "admin_certificate.put", "admin_certificate", value.ID, value, materialTestID(t, deleted), materialTestID(t, concurrent))
	for _, facts := range [][]Material{{deleted, concurrent, regrant}, {regrant, concurrent, deleted}} {
		p, err := Project(f.genesis, nil, facts)
		if err != nil || !reflect.DeepEqual(p.AdminCertificates, []AdminCertificate{value}) {
			t.Fatalf("explicit regrant did not recover original leaf: %v", err)
		}
	}
	for _, material := range []Material{f.genesis, deleted, concurrent, regrant} {
		body, id, err := EncodeMaterial(material)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeMaterial(body)
		if err != nil {
			t.Fatal(err)
		}
		again, againID, err := EncodeMaterial(decoded)
		if err != nil || id != againID || !bytes.Equal(body, again) || !reflect.DeepEqual(material, decoded) {
			t.Fatal("administrator fact round trip changed")
		}
	}
	after, _, _ := EncodeMaterial(f.genesis)
	if !bytes.Equal(original, after) {
		t.Fatal("genesis was rewritten")
	}
}

func adminServerFixture(t *testing.T) (*Server, string, transportCA) {
	t.Helper()
	root, config, genesis := authorityFixture(t)
	ca := testTransportCA(t, filepath.Dir(root))
	files, _, _ := testTransportIdentity(t, filepath.Dir(root), "demo-admin-browser", 40, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	config.BrowserTLS = &files
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	return &Server{Runtime: runtime, Config: config}, root, ca
}

func adminPut(value AdminCertificate, request string, deps ...string) Operation {
	return Operation{Schema: 3, RequestID: request, Operation: "admin_certificate.put", TargetKind: "admin_certificate", TargetID: value.ID, Dependencies: append([]string{}, deps...), Payload: value}
}

func TestAdminGrantVerifiedTLSWriteRevocationAndRestart(t *testing.T) {
	server, root, ca := adminServerFixture(t)
	value, pair := adminTestLeaf(t, filepath.Dir(root), ca, "demo-issued-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	wrongCA := testTransportCA(t, t.TempDir())
	wrong, _ := adminTestLeaf(t, t.TempDir(), wrongCA, "demo-wrong-issuer", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	wrongPurpose, _ := adminTestLeaf(t, t.TempDir(), ca, "demo-wrong-purpose", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	for _, bad := range []AdminCertificate{wrong, wrongPurpose} {
		if _, _, err := server.HandleOperation(context.Background(), adminPut(bad, "demo-rejected-admin")); err == nil {
			t.Fatal("invalid admin grant accepted")
		}
	}
	var clock atomic.Int64
	clock.Store(time.Now().UnixMilli())
	server.Now = func() time.Time { return time.UnixMilli(clock.Load()) }
	clock.Store(time.Now().Add(24 * time.Hour).UnixMilli())
	if _, _, err := server.HandleOperation(context.Background(), adminPut(value, "demo-expired-admin")); err == nil {
		t.Fatal("expired grant accepted")
	}
	clock.Store(time.Now().UnixMilli())
	tlsConfig, err := browserTLSConfig(server.Config)
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewUnstartedServer(server.Handler())
	server.Channel = &PrivateChannel{config: PrivateChannelConfig{Listen: []string{h.Listener.Addr().String()}}}
	h.TLS = tlsConfig
	h.StartTLS()
	defer h.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ca.certificate)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	read := func(want int) {
		t.Helper()
		r, e := client.Get(h.URL + "/api/control/ui/snapshot")
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("got HTTP %d, want %d", r.StatusCode, want)
		}
	}
	read(http.StatusForbidden)
	op := adminPut(value, "demo-grant-admin")
	accepted, _, err := server.HandleOperation(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	read(http.StatusOK)
	requestBody, err := EncodeOperation(authorityService("demo-admin-service", "demo-admin-service-write"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := client.Post(h.URL+"/api/control/operations", "application/json", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatal("new certificate could not perform an ordinary operation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(h.URL, "https")+"/api/control/ui/live", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if _, _, err = ws.Read(ctx); err != nil {
		t.Fatal(err)
	}
	clock.Store(time.Now().Add(24 * time.Hour).UnixMilli())
	read(http.StatusForbidden) // Also checks a reused TLS connection.
	if retry, _, err := server.HandleOperation(context.Background(), op); err != nil || retry.MaterialID != accepted.MaterialID {
		t.Fatal("accepted request retry must retain original bytes after expiration", err)
	}
	for {
		_, _, err = ws.Read(ctx)
		if err != nil {
			break
		}
	}
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatal("expired administrator WebSocket remained authorized", err)
	}
	clock.Store(time.Now().UnixMilli())
	ws2, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(h.URL, "https")+"/api/control/ui/live", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer ws2.CloseNow()
	if _, _, err = ws2.Read(ctx); err != nil {
		t.Fatal(err)
	}
	withdraw := Operation{Schema: 3, RequestID: "demo-withdraw-admin", Operation: "admin_certificate.delete", TargetKind: "admin_certificate", TargetID: value.ID, Dependencies: []string{accepted.MaterialID}, Payload: DeleteTarget{ID: value.ID}}
	removed, _, err := server.HandleOperation(context.Background(), withdraw)
	if err != nil {
		t.Fatal(err)
	}
	read(http.StatusForbidden)
	for {
		_, _, err = ws2.Read(ctx)
		if err != nil {
			break
		}
	}
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatal("withdrawn administrator WebSocket remained authorized", err)
	}
	original, _ := server.Runtime.Authority.Material(removed.MaterialID)
	reopened, err := OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := reopened.Material(removed.MaterialID)
	if len(reopened.Snapshot().AdminCertificates) != 0 || !bytes.Equal(original, again) {
		t.Fatal("restart lost exact administrator withdrawal")
	}
	if _, _, err := server.HandleOperation(context.Background(), adminPut(value, "demo-stale-admin")); err == nil {
		t.Fatal("stale regrant resurrected revoked certificate")
	}
}

func TestWebChromeAdministratorPublicFileAndRevocation(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires real Chrome")
	}
	server, root, ca := adminServerFixture(t)
	value, _ := adminTestLeaf(t, filepath.Dir(root), ca, "demo-web-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	h := httptest.NewServer(server.AdminHandler())
	defer h.Close()
	d := openCommandChrome(t, h.URL+"/ssot")
	waitChromeEvaluation(t, d, `document.querySelector('#admin-certificate-form')`)
	public, _ := CanonicalEncode(value)
	literal, _ := json.Marshal(string(public))
	chromeDo(t, d, `(()=>{const f=document.querySelector('#admin-certificate-form'),dt=new DataTransfer;dt.items.add(new File([`+string(literal)+`],'admin.json',{type:'application/json'}));f.elements.certificate.files=dt.files;f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, d, `document.querySelector('#administrators tbody').textContent.includes('demo-web-admin')`)
	if len(server.Runtime.Authority.Snapshot().AdminCertificates) != 1 {
		t.Fatal("browser grant did not persist")
	}
	chromeDo(t, d, `(()=>{window.confirm=()=>true;document.querySelector('[data-delete-kind=admin_certificate]').click();return true})()`)
	waitChromeEvaluation(t, d, `!document.querySelector('[data-delete-kind=admin_certificate]')`)
	reopened, err := OpenAuthority(root)
	if err != nil || len(reopened.Snapshot().AdminCertificates) != 0 {
		t.Fatal("browser revocation did not survive reload", err)
	}
}
