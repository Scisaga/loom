package control

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestEndpointCertificateReadbackCoversDeviceModesWithoutLoadingKey(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	key := testKey(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-endpoint"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"demo.example"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificateFile := filepath.Join(root, "demo-certificate.pem")
	certificateBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certificateFile, certificateBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := EndpointGeneration{ID: "demo-endpoint", Generation: 1, OwnerControlID: "demo-owner", Host: "192.0.2.1", Port: 443,
		ServerName: "demo.example", SPKISHA256: endpointByteDigest(leaf.RawSubjectPublicKeyInfo), CertificateDigest: endpointByteDigest(der), Modes: []string{"bootstrap", "device"}, State: "serving"}
	inputs := EndpointLocalInputs{Listen: "127.0.0.1:443", CertificateFile: certificateFile, KeyFile: filepath.Join(root, "demo-key-not-present.pem")}
	inputBytes, _ := CanonicalEncode(inputs)
	if err := os.Mkdir(filepath.Join(root, "endpoint-inputs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(endpointInputPath(root, endpoint.ID, endpoint.Generation), inputBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	projection := Projection{EndpointGenerations: []EndpointGeneration{endpoint}}
	before, _ := CanonicalEncode(projection)
	for _, test := range []struct {
		name, owner, status, reason string
		at                          time.Time
		change                      func(*EndpointGeneration)
	}{
		{name: "valid", owner: endpoint.OwnerControlID, status: "valid", at: now},
		{name: "renewal-boundary", owner: endpoint.OwnerControlID, status: "renewal_due", at: leaf.NotAfter.Add(-30 * 24 * time.Hour)},
		{name: "expired", owner: endpoint.OwnerControlID, status: "expired", at: leaf.NotAfter},
		{name: "not-yet-valid", owner: endpoint.OwnerControlID, status: "not_yet_valid", at: leaf.NotBefore.Add(-time.Second)},
		{name: "remote-owner", owner: "demo-other-owner", status: "unknown", reason: "inspect_owning_control", at: now},
		{name: "wrong-digest", owner: endpoint.OwnerControlID, status: "unknown", reason: "certificate_invalid", at: now, change: func(e *EndpointGeneration) { e.CertificateDigest = endpointByteDigest([]byte("demo-other-leaf")) }},
		{name: "wrong-name", owner: endpoint.OwnerControlID, status: "unknown", reason: "certificate_invalid", at: now, change: func(e *EndpointGeneration) { e.ServerName = "demo-other.example" }},
		{name: "wrong-spki", owner: endpoint.OwnerControlID, status: "unknown", reason: "certificate_invalid", at: now, change: func(e *EndpointGeneration) { e.SPKISHA256 = endpointByteDigest([]byte("demo-other-public-key")) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := endpoint
			if test.change != nil {
				test.change(&current)
			}
			rows := EndpointCertificateReadbacks(root, test.owner, Projection{EndpointGenerations: []EndpointGeneration{current}}, test.at)
			if len(rows) != 1 || rows[0].Status != test.status || rows[0].Reason != test.reason || !reflect.DeepEqual(rows[0].Modes, endpoint.Modes) {
				t.Fatalf("certificate readback = %+v", rows)
			}
			if test.reason == "" && (rows[0].LeafNotBefore != leaf.NotBefore.UTC().Format(time.RFC3339) || rows[0].LeafNotAfter != leaf.NotAfter.UTC().Format(time.RFC3339) || rows[0].RootNotAfter != "" || rows[0].RemainingSeconds == nil || *rows[0].RemainingSeconds != int64(leaf.NotAfter.Sub(test.at)/time.Second)) {
				t.Fatal("certificate dates did not follow the authenticated leaf and injected clock")
			}
			if test.reason != "" && (rows[0].LeafNotAfter != "" || rows[0].RemainingSeconds != nil) {
				t.Fatal("unverified material supplied certificate dates")
			}
		})
	}
	for _, state := range []string{"prepared", "draining", "retired"} {
		current := endpoint
		current.State = state
		if rows := EndpointCertificateReadbacks(root, endpoint.OwnerControlID, Projection{EndpointGenerations: []EndpointGeneration{current}}, now); len(rows) != 0 {
			t.Fatal("non-serving endpoint appeared in certificate diagnostics", state)
		}
	}
	if rows := EndpointCertificateReadbacks(t.TempDir(), endpoint.OwnerControlID, projection, now); len(rows) != 1 || rows[0].Reason != "material_unavailable" {
		t.Fatal("missing material did not remain unknown", rows)
	}
	if err := os.WriteFile(certificateFile, []byte("demo-invalid-public-certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rows := EndpointCertificateReadbacks(root, endpoint.OwnerControlID, projection, now); len(rows) != 1 || rows[0].Reason != "certificate_invalid" {
		t.Fatal("invalid public certificate did not remain unknown", rows)
	}
	after, _ := CanonicalEncode(projection)
	if !bytes.Equal(before, after) {
		t.Fatal("diagnosis modified the endpoint projection")
	}
	if _, err := os.Stat(inputs.KeyFile); !os.IsNotExist(err) {
		t.Fatal("certificate diagnosis introduced a private key requirement")
	}
}

func TestEndpointCertificateSnapshotUsesOnlyUnifiedProjection(t *testing.T) {
	f := newEndpointFixture(t)
	response := httptest.NewRecorder()
	f.server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
	if response.Code != http.StatusOK {
		t.Fatal("normal administration snapshot failed", response.Code)
	}
	var snapshot map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if _, exists := snapshot["website_certificates"]; exists {
		t.Fatal("replaced website-only certificate projection remains active")
	}
	var rows []EndpointCertificateReadback
	if err := json.Unmarshal(snapshot["endpoint_certificates"], &rows); err != nil || len(rows) != 1 || rows[0].EndpointID != f.endpoint.ID || rows[0].Status != "renewal_due" || rows[0].LeafNotAfter == "" || !reflect.DeepEqual(rows[0].Modes, []string{"bootstrap", "device"}) {
		t.Fatal("normal snapshot omitted the device certificate", rows, err)
	}
}
