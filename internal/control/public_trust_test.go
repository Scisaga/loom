package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func testWebsiteTrust(t *testing.T, now time.Time) PublicTrust {
	t.Helper()
	trust, _ := testWebsiteTrustKey(t, now)
	return trust
}

func testWebsiteTrustKey(t *testing.T, now time.Time) (PublicTrust, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, v4, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6, _ := net.ParseCIDR("::/0")
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-website-root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{".loom"}, ExcludedIPRanges: []*net.IPNet{v4, v6}}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return PublicTrust{ID: WebsiteTrustID(der), Purpose: "website", CertificateDER: base64.RawURLEncoding.EncodeToString(der)}, key
}

func TestPublicTrustCanonicalFactsAndConcurrentWithdrawal(t *testing.T) {
	f := newMaterialFixture(t)
	value := testWebsiteTrust(t, time.Now())
	original, _, _ := EncodeMaterial(f.genesis)
	put := f.sign(t, 0, 1, nil, "demo-grant-website-root", "public_trust.put", "public_trust", value.ID, value)
	deleted := f.sign(t, 0, 2, &put, "demo-withdraw-website-root", "public_trust.delete", "public_trust", value.ID, DeleteTarget{ID: value.ID}, materialTestID(t, put))
	concurrent := f.sign(t, 1, 1, nil, "demo-concurrent-website-root", "public_trust.put", "public_trust", value.ID, value, materialTestID(t, put))
	for _, facts := range [][]Material{{put, deleted, concurrent}, {concurrent, deleted, put}} {
		projection, err := Project(f.genesis, nil, facts)
		if err != nil || len(projection.NetworkIntent.PublicTrust) != 0 || len(projection.InvalidMaterials) != 0 {
			t.Fatal("concurrent root refresh defeated withdrawal", err)
		}
	}
	regrant := f.sign(t, 0, 3, &deleted, "demo-regrant-website-root", "public_trust.put", "public_trust", value.ID, value, materialTestID(t, deleted), materialTestID(t, concurrent))
	projection, err := Project(f.genesis, nil, []Material{regrant, concurrent, deleted, put})
	if err != nil || !reflect.DeepEqual(projection.NetworkIntent.PublicTrust, []PublicTrust{value}) {
		t.Fatal("explicit same-root regrant failed", err)
	}
	for _, fact := range []Material{put, deleted, concurrent, regrant} {
		body, id, err := EncodeMaterial(fact)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeMaterial(body)
		if err != nil {
			t.Fatal(err)
		}
		again, againID, err := EncodeMaterial(decoded)
		if err != nil || !bytes.Equal(body, again) || id != againID || !reflect.DeepEqual(fact, decoded) {
			t.Fatal("public trust fact changed during canonical round trip", err)
		}
	}
	after, _, _ := EncodeMaterial(f.genesis)
	if !bytes.Equal(original, after) {
		t.Fatal("empty public trust rewrote the original genesis")
	}
	intent := EmptyNetworkIntent()
	intent.PublicTrust = []PublicTrust{value}
	if err := intent.Validate(); err != nil {
		t.Fatal("valid initial website trust rejected", err)
	}
	for _, change := range []func(*PublicTrust){
		func(v *PublicTrust) { v.ID = "demo-alias-root" },
		func(v *PublicTrust) { v.Purpose = "transport" },
		func(v *PublicTrust) { v.CertificateDER += "=" },
	} {
		wrong := value
		change(&wrong)
		if wrong.Validate() == nil {
			t.Fatal("noncanonical identity, encoding or unknown purpose accepted")
		}
	}
}

func TestPublicTrustAuthenticatedViewRestartExportAndRemoval(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	trusted, err := server.bootstrapInvite(invite.ID)
	if err != nil {
		t.Fatal(err)
	}
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("fixture join failed")
	}
	before, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := CanonicalEncode(before)
	originalView, _ := CanonicalEncode(before.View)
	if bytes.Contains(originalView, []byte(`"public_trust"`)) {
		t.Fatal("unconfigured View acquired an empty public trust field")
	}
	value := testWebsiteTrust(t, server.now())
	operation := Operation{Schema: 3, RequestID: "demo-public-root", Operation: "public_trust.put", TargetKind: "public_trust", TargetID: value.ID, Dependencies: []string{}, Payload: value}
	result, _, err := server.HandleOperation(context.Background(), operation)
	if err != nil {
		t.Fatal(err)
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Runtime.Close()
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || !reflect.DeepEqual(view.View.PublicTrust, []PublicTrust{value}) {
		t.Fatal("certified website root lost on restart", err)
	}
	if err := VerifyDeviceViewEnvelope(view, trusted); err != nil {
		t.Fatal("root projection is not authenticated", err)
	}
	if !reflect.DeepEqual(view.View.Routes, before.View.Routes) || !reflect.DeepEqual(view.View.RuntimeProfile, before.View.RuntimeProfile) || view.View.DevicePublicKey != before.View.DevicePublicKey {
		t.Fatal("website root changed business permissions or device identity")
	}
	web := buildWebSnapshot(server.Runtime.Authority.Snapshot(), true, true, true)
	if !reflect.DeepEqual(web.PublicTrust, []PublicTrust{value}) {
		t.Fatal("normal UI omitted the persisted root")
	}
	url := "/api/control/public-trust/" + value.ID + "/certificate"
	read := func(handler http.Handler) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, url, nil))
		return response
	}
	if response := read(server.Handler()); response.Code == http.StatusOK {
		t.Fatal("unauthenticated transport obtained private root delivery")
	}
	response := read(server.AdminHandler())
	block, rest := pem.Decode(response.Body.Bytes())
	der, _ := base64.RawURLEncoding.DecodeString(value.CertificateDER)
	if response.Code != http.StatusOK || block == nil || !bytes.Equal(block.Bytes, der) || len(rest) != 0 {
		t.Fatal("formal root download did not preserve the original certificate")
	}
	now := server.now()
	server.Now = func() time.Time { return now.Add(25 * time.Hour) }
	if response := read(server.AdminHandler()); response.Code != http.StatusConflict {
		t.Fatal("expired root was exportable")
	}
	operation.RequestID = "demo-expired-root-grant"
	operation.Dependencies = []string{result.MaterialID}
	if _, _, err := server.HandleOperation(context.Background(), operation); err == nil {
		t.Fatal("formal entry granted expired root")
	}
	server.Now = func() time.Time { return now }
	operation = Operation{Schema: 3, RequestID: "demo-remove-root", Operation: "public_trust.delete", TargetKind: "public_trust", TargetID: value.ID, Dependencies: []string{result.MaterialID}, Payload: DeleteTarget{ID: value.ID}}
	if _, _, err := server.HandleOperation(context.Background(), operation); err != nil {
		t.Fatal(err)
	}
	view, err = server.deviceEnvelope(invite.DeviceID)
	if err != nil || view.View.PublicTrust != nil || read(server.AdminHandler()).Code != http.StatusNotFound {
		t.Fatal("withdrawn root remained in a current View or download", err)
	}
	after, _ := CanonicalEncode(before)
	if !bytes.Equal(original, after) {
		t.Fatal("original authenticated View bytes changed")
	}
}
