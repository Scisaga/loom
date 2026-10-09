package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func websiteManagementFixture(t *testing.T) (endpointFixture, PublicTrust, *ecdsa.PrivateKey, tls.Certificate) {
	t.Helper()
	f := newEndpointFixture(t)
	root := f.server.Runtime.Authority.root
	files, _, _ := testTransportIdentity(t, filepath.Dir(root), "demo-website-browser", 101, testKey(t), f.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	f.server.Config.BrowserTLS = &files
	body, _ := CanonicalEncode(f.server.Config)
	if err := os.WriteFile(filepath.Join(root, "node.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	trust, key := testWebsiteTrustKey(t, f.server.now())
	submitAuthority(t, f.server.Runtime, Operation{Schema: 3, RequestID: "demo-website-root", Operation: "public_trust.put", TargetKind: "public_trust", TargetID: trust.ID, Dependencies: []string{}, Payload: trust})
	admin, pair := adminTestLeaf(t, filepath.Dir(root), f.ca, "demo-website-admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if _, _, err := f.server.HandleOperation(context.Background(), adminPut(admin, "demo-website-admin-grant")); err != nil {
		t.Fatal(err)
	}
	web := &http.Server{Handler: f.server.Handler(), ConnContext: endpointConnContext, ReadHeaderTimeout: 5 * time.Second}
	go web.Serve(f.runtime.WebListener())
	t.Cleanup(func() { web.Close() })
	return f, trust, key, pair
}

func signManagementRequest(t *testing.T, server *Server, request WebsiteRequest, trust PublicTrust, key *ecdsa.PrivateKey) string {
	t.Helper()
	csr, err := VerifyWebsiteRequest(request, localWebsiteExpectation(server.Config, server.Runtime.Authority.Snapshot(), request.EndpointID, request.Generation))
	if err != nil {
		t.Fatal(err)
	}
	root, _ := trust.certificate()
	now := server.now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(request.Generation) + 200), Subject: pkix.Name{CommonName: "demo-website"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"control.loom"}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, csr.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func websiteHTTP(t *testing.T, handler http.Handler, method, path string, value any, want int) []byte {
	t.Helper()
	var body []byte
	if value != nil {
		var err error
		body, err = CanonicalEncode(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s returned %d, want %d: %s", method, path, w.Code, want, w.Body.String())
	}
	return w.Body.Bytes()
}

func websiteOperation(t *testing.T, server *Server, endpoint EndpointGeneration, name string) Operation {
	t.Helper()
	projection := server.Runtime.Authority.Snapshot()
	deps := []string{}
	if target, ok := projection.CurrentTarget("endpoint", endpoint.ID); ok {
		deps = append(deps, target.MaterialIDs...)
	}
	if endpoint.State == "prepared" || endpoint.State == "serving" {
		target, _ := projection.CurrentTarget("public_trust", endpoint.WebsiteTrustID)
		deps = append(deps, target.MaterialIDs...)
	}
	return Operation{Schema: 3, RequestID: name, Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: sortedUniqueDependencies(deps), Payload: endpoint}
}

func TestWebsiteManagementHTTPMaterialRestartAndVerifiedRetirement(t *testing.T) {
	f, trust, key, pair := websiteManagementFixture(t)
	server, root := f.server, f.server.Runtime.Authority.root
	handler := server.AdminHandler()
	requestPath := "/api/control/website/demo-web/1/request"
	body := websiteHTTP(t, handler, "POST", requestPath, nil, 200)
	if retry := websiteHTTP(t, handler, "POST", requestPath, nil, 200); !bytes.Equal(body, retry) {
		t.Fatal("retry regenerated signing request")
	}
	var request WebsiteRequest
	if err := DecodeCanonical(body, &request, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	pemLeaf := signManagementRequest(t, server, request, trust, key)
	input := websiteInstallInput{EndpointID: request.EndpointID, Generation: 1, WebsiteTrustID: trust.ID, Host: f.endpoint.Host, Port: f.endpoint.Port, Listen: net.JoinHostPort(f.endpoint.Host, strconv.Itoa(f.endpoint.Port)), CertificatePEM: pemLeaf}
	bad := input
	bad.CertificatePEM = pemLeaf + "private material"
	websiteHTTP(t, handler, "POST", "/api/control/website/certificate", bad, 422)
	if _, err := os.Stat(endpointInputPath(root, input.EndpointID, 1)); !os.IsNotExist(err) {
		t.Fatal("bad certificate installed inputs")
	}
	body = websiteHTTP(t, handler, "POST", "/api/control/website/certificate", input, 200)
	var first EndpointGeneration
	if err := json.Unmarshal(body, &first); err != nil {
		t.Fatal(err)
	}
	if _, ok := server.Runtime.Authority.Snapshot().CurrentTarget("endpoint", first.ID); ok {
		t.Fatal("certificate adapter manufactured an endpoint fact")
	}
	websiteHTTP(t, handler, "POST", "/api/control/operations", websiteOperation(t, server, first, "demo-web-prepare"), 200)
	f.runtime.reconcile()
	first.State = "serving"
	websiteHTTP(t, handler, "POST", "/api/control/operations", websiteOperation(t, server, first, "demo-web-serve"), 200)
	if got := websiteHTTP(t, handler, "GET", "/api/control/website/demo-web/1/leaf", nil, 200); string(got) != pemLeaf {
		t.Fatal("public leaf export differs")
	}
	reopened, err := OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	requests, err := localWebsiteRequests(root, server.Config, reopened.Snapshot())
	if err != nil || len(requests) != 1 || !requests[0].Available {
		t.Fatal("request did not survive authority reopen", err)
	}
	// Independently trusted root, actual advertised TLS and real admin client authentication.
	ca, _ := trust.certificate()
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	client := func(host string) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}, ServerName: "control.loom"}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(first.Port)))
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	base := "https://control.loom:" + strconv.Itoa(first.Port)
	oldClient := client(first.Host)
	read := func(client *http.Client, generation U64) {
		t.Helper()
		response, err := client.Get(base + "/api/control/ui/snapshot")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var snapshot WebSnapshot
		if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&snapshot) != nil || snapshot.WebsiteConnection == nil || snapshot.WebsiteConnection.Generation != generation {
			t.Fatal("actual authenticated connection did not identify its exact generation")
		}
	}
	read(oldClient, 1)
	// Cross-origin writes are rejected even with a valid administrator certificate.
	cross, _ := http.NewRequest("POST", base+"/api/control/website/demo-other/1/request", nil)
	cross.Header.Set("Origin", "https://other.example")
	response, err := oldClient.Do(cross)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("cross-origin request accepted")
	}
	body = websiteHTTP(t, handler, "POST", "/api/control/website/demo-web/2/request", nil, 200)
	if DecodeCanonical(body, &request, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}) != nil {
		t.Fatal("invalid second request")
	}
	input.Generation = 2
	input.CertificatePEM = signManagementRequest(t, server, request, trust, key)
	websiteHTTP(t, handler, "POST", "/api/control/website/certificate", input, 422)
	if !f.runtime.Ready(first) {
		t.Fatal("failed candidate replaced the serving certificate")
	}
	input.Host = "127.0.0.2"
	input.Listen = net.JoinHostPort(input.Host, strconv.Itoa(input.Port))
	body = websiteHTTP(t, handler, "POST", "/api/control/website/certificate", input, 200)
	var second EndpointGeneration
	if json.Unmarshal(body, &second) != nil {
		t.Fatal("invalid second endpoint")
	}
	websiteHTTP(t, handler, "POST", "/api/control/operations", websiteOperation(t, server, second, "demo-web-prepare-second"), 200)
	f.runtime.reconcile()
	second.State = "serving"
	websiteHTTP(t, handler, "POST", "/api/control/operations", websiteOperation(t, server, second, "demo-web-serve-second"), 200)
	newClient := client(second.Host)
	read(newClient, 2)
	read(oldClient, 1)
	first.State = "draining"
	first.DrainUntil = server.now().Add(time.Minute).UnixMilli()
	op := websiteOperation(t, server, first, "demo-web-drain-first")
	websiteHTTP(t, handler, "POST", "/api/control/website/retire-previous", op, 409)
	post := func(client *http.Client, operation Operation, want int) {
		t.Helper()
		body, _ := EncodeOperation(operation)
		response, err := client.Post(base+"/api/control/website/retire-previous", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		message, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("retirement returned %d: %s", response.StatusCode, message)
		}
	}
	post(oldClient, op, 409)
	post(newClient, op, 200)
	first.State = "retired"
	first.DrainUntil = 0
	post(newClient, websiteOperation(t, server, first, "demo-web-retire-first"), 422)
	oldClient.CloseIdleConnections()
	f.clock.Add(61000)
	f.runtime.reconcile()
	post(newClient, websiteOperation(t, server, first, "demo-web-retire-first"), 200)
	reopened, err = OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range reopened.Snapshot().EndpointGenerations {
		if endpoint.ID == first.ID && endpoint.Generation == 1 && endpoint.State != "retired" {
			t.Fatal("retirement did not persist")
		}
	}
}

func TestWebChromeWebsiteRequestImportAndActivation(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires real Chrome")
	}
	f, trust, key, _ := websiteManagementFixture(t)
	h := httptest.NewServer(f.server.AdminHandler())
	defer h.Close()
	browser := openCommandChrome(t, h.URL+"/settings")
	waitChromeEvaluation(t, browser, `document.querySelector('[data-website-form=request]')`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('[data-website-form=request]');f.elements.endpoint_id.value='demo-web';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-website-request="demo-web"]')`)
	request, err := localWebsiteRequest(f.server.Runtime.Authority.root, f.server.Config, f.server.Runtime.Authority.Snapshot(), "demo-web", 1)
	if err != nil {
		t.Fatal(err)
	}
	leaf := signManagementRequest(t, f.server, request, trust, key)
	certificate, _ := json.Marshal(leaf)
	id, _ := json.Marshal(trust.ID)
	chromeDo(t, browser, fmt.Sprintf(`(()=>{const f=document.querySelector('[data-website-form=import]');f.elements.website_trust_id.value=%s;f.elements.host.value='127.0.0.1';f.elements.port.value='%d';f.elements.listen.value='127.0.0.1:%d';const dt=new DataTransfer();dt.items.add(new File([%s],'demo-leaf.pem'));f.elements.certificate.files=dt.files;f.requestSubmit();return true})()`, id, f.endpoint.Port, f.endpoint.Port, certificate))
	waitChromeEvaluation(t, browser, `document.querySelector('[data-website-entry="demo-web"]')?.dataset.state==='prepared'`)
	f.runtime.reconcile()
	chromeDo(t, browser, `document.querySelector('[data-website-action=serve]').click();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-website-entry="demo-web"]')?.dataset.state==='serving'`)
	chromeDo(t, browser, `document.querySelector('[data-website-action=request]').click();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-website-request="demo-web"][data-generation="2"]')`)
	chromeDo(t, browser, `location.reload();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-website-entry="demo-web"]')?.dataset.state==='serving'&&document.querySelector('[data-website-request="demo-web"][data-generation="2"]')`)
}
