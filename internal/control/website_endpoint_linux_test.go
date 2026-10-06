package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"
)

func TestWebsiteEndpointCSRRootWithdrawalAndSharedSNI(t *testing.T) {
	f := newEndpointFixture(t)
	root := f.server.Runtime.Authority.root
	now := f.server.now()
	files, _, _ := testTransportIdentity(t, filepath.Dir(root), "demo-browser-admin", 91, testKey(t), f.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	node := f.server.Config
	node.BrowserTLS = &files
	body, _ := CanonicalEncode(node)
	if err := os.WriteFile(filepath.Join(root, "node.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	trust, signingKey := testWebsiteTrustKey(t, now)
	grant := submitAuthority(t, f.server.Runtime, Operation{Schema: 3, RequestID: "demo-grant-website", Operation: "public_trust.put", TargetKind: "public_trust", TargetID: trust.ID, Dependencies: []string{}, Payload: trust})
	request, err := PrepareWebsiteRequest(root, "demo-website", 1)
	if err != nil {
		t.Fatal(err)
	}
	expected := WebsiteRequestExpectation{node.NetworkID, node.GenesisID, f.server.Runtime.Authority.Snapshot().ControlConfigID, node.ControlID, node.NodeID, request.EndpointID, 1}
	csr, err := VerifyWebsiteRequest(request, expected)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := trust.certificate()
	template := &x509.Certificate{SerialNumber: big.NewInt(92), Subject: pkix.Name{CommonName: "demo-website"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"control.loom"}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	certificateFile := filepath.Join(root, "demo-returned-leaf.pem")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := EndpointGeneration{ID: request.EndpointID, Generation: 1, OwnerControlID: node.ControlID,
		Host: f.endpoint.Host, Port: f.endpoint.Port, ServerName: "control.loom", SPKISHA256: endpointByteDigest(leaf.RawSubjectPublicKeyInfo),
		CertificateDigest: endpointByteDigest(der), WebsiteTrustID: trust.ID, Modes: []string{"web"}, State: "prepared"}
	inputs := EndpointLocalInputs{Listen: net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), CertificateFile: certificateFile,
		KeyFile: filepath.Join(websiteRequestDirectory(root, endpoint.ID, 1), "key.pem")}
	wrong := inputs
	wrong.KeyFile = files.KeyFile
	if InstallEndpointInputs(root, endpoint, wrong) == nil {
		t.Fatal("another local key replaced the original website CSR key")
	}
	if err := InstallEndpointInputs(root, endpoint, inputs); err != nil {
		t.Fatal(err)
	}
	operation := Operation{Schema: 3, RequestID: "demo-prepare-website", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: []string{grant.MaterialID}, Payload: endpoint}
	prepared, _, err := f.server.HandleOperation(context.Background(), operation)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.reconcile()
	if !f.runtime.Ready(endpoint) || !f.runtime.Ready(f.endpoint) {
		t.Fatal("distinct SNI identities could not share the original advertised listener")
	}
	endpoint.State = "serving"
	operation.RequestID = "demo-serve-website"
	operation.Dependencies = []string{prepared.MaterialID}
	operation.Payload = endpoint
	served, _, err := f.server.HandleOperation(context.Background(), operation)
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("demo website")) })}
	t.Cleanup(func() { web.Close() })
	go web.Serve(f.runtime.WebListener())
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	connection, err := tls.Dial("tcp", inputs.Listen, &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "control.loom", RootCAs: roots, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal("website chain did not verify through the real listener", err)
	}
	defer connection.Close()
	if _, err := fmt.Fprint(connection, "GET / HTTP/1.1\r\nHost: control.loom\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("website HTTP did not consume the prepared certificate", err)
	}
	page, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(page) != "demo website" || f.runtime.Active(endpoint) < 1 {
		t.Fatal("website response did not leave a tracked live session", err)
	}
	if got := connection.ConnectionState().PeerCertificates[0]; !bytes.Equal(got.Raw, der) {
		t.Fatal("website handshake selected the original device certificate")
	}
	// This call performs the original authenticated claim, not only TLS.
	f.join(t, "while-website-serving")
	other := testWebsiteTrust(t, now)
	otherGrant := submitAuthority(t, f.server.Runtime, Operation{Schema: 3, RequestID: "demo-other-website-root", Operation: "public_trust.put", TargetKind: "public_trust", TargetID: other.ID, Dependencies: []string{}, Payload: other})
	rebound := endpoint
	rebound.WebsiteTrustID = other.ID
	dependencies := []string{served.MaterialID, otherGrant.MaterialID}
	sort.Strings(dependencies)
	if _, err := f.server.Runtime.Authority.Submit(context.Background(), Operation{Schema: 3, RequestID: "demo-rebind-website", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: dependencies, Payload: rebound}, node); err == nil {
		t.Fatal("same-generation root substitution was accepted")
	}
	removed := submitAuthority(t, f.server.Runtime, Operation{Schema: 3, RequestID: "demo-withdraw-website", Operation: "public_trust.delete", TargetKind: "public_trust", TargetID: trust.ID, Dependencies: []string{grant.MaterialID}, Payload: DeleteTarget{ID: trust.ID}})
	f.runtime.reconcile()
	assertEndpointConnectionClosed(t, connection)
	if f.runtime.Ready(endpoint) || !f.runtime.Ready(f.endpoint) {
		t.Fatal("root withdrawal retained website readiness or stopped the other SNI")
	}
	f.join(t, "after-website-withdrawal")
	endpoint.State, endpoint.DrainUntil = "draining", now.Add(time.Minute).UnixMilli()
	operation.RequestID, operation.Payload = "demo-drain-website", endpoint
	operation.Dependencies = []string{served.MaterialID, removed.MaterialID}
	sort.Strings(operation.Dependencies)
	draining, _, err := f.server.HandleOperation(context.Background(), operation)
	if err != nil {
		t.Fatal("withdrawn root prevented endpoint drainage", err)
	}
	endpoint.State, endpoint.DrainUntil = "retired", 0
	operation.RequestID, operation.Payload, operation.Dependencies = "demo-retire-website", endpoint, []string{draining.MaterialID}
	if _, _, err := f.server.HandleOperation(context.Background(), operation); err != nil {
		t.Fatal("withdrawn root prevented endpoint retirement", err)
	}
	reopened, err := OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range reopened.Snapshot().EndpointGenerations {
		if value.ID == endpoint.ID && (value.State != "retired" || value.WebsiteTrustID != trust.ID) {
			t.Fatal("restart lost original root binding or retirement")
		}
	}
	old, _ := CanonicalEncode(f.endpoint)
	if bytes.Contains(old, []byte("website_trust_id")) {
		t.Fatal("ordinary endpoint acquired a website field")
	}
}
