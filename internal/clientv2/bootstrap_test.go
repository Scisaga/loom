package clientv2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func mirrorTLSTestFixture(t *testing.T, handler http.Handler) (*httptest.Server, *x509.CertPool, string) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mirror test CA"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafPublic, leafPrivate, _ := ed25519.GenerateKey(rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "a.example.test"}, DNSNames: []string{"a.example.test", "b.example.test"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:  x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafPrivate}}}
	server.StartTLS()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return server, roots, "sha256:" + hex.EncodeToString(digest[:])
}

func TestMirrorFetcherSendsNoSecretAndRequiresCanonicalTypedObject(t *testing.T) {
	body := []byte(`{"schema":1,"value":"catalog"}`)
	expectedHash, _ := wire.HashCanonical("test-bootstrap-object-v1", body)
	digest := strings.TrimPrefix(expectedHash, "sha256:")
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/distribution/sha256/"+digest || request.URL.RawQuery != "" ||
			request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Errorf("unsafe mirror request: %s headers=%v", request.URL.String(), request.Header)
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(body)
	})
	server, roots, pin := mirrorTLSTestFixture(t, handler)
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	baseURLA := "https://a.example.test:" + parsed.Port() + "/distribution/sha256/"
	baseURLB := "https://b.example.test:" + parsed.Port() + "/distribution/sha256/"
	hash := func(value string) string { return wire.HashRaw("mirror-fetch-test-v1", []byte(value)) }
	mirrors := []wire.DistributionMirrorRefV1{
		{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: hash("set-1"), ListenerGeneration: 1, BaseURL: baseURLA, ServerName: "a.example.test", WebPKIProfileRef: "webpki-v1", SPKIPins: []string{pin}, HintRank: 0},
		{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: hash("set-2"), ListenerGeneration: 1, BaseURL: baseURLB, ServerName: "b.example.test", WebPKIProfileRef: "webpki-v1", SPKIPins: []string{pin}, HintRank: 1},
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, parsed.Host)
	}
	fetcher := MirrorFetcher{RootCAs: roots, Timeout: 5 * time.Second, DialContext: dial}
	got, err := fetcher.FetchCanonicalObject(context.Background(), mirrors, expectedHash, "test-bootstrap-object-v1", 4096)
	if err != nil || string(got) != string(body) {
		t.Fatalf("got=%q err=%v", got, err)
	}

	badBody := append([]byte(" "), body...)
	badServer, badRoots, badPin := mirrorTLSTestFixture(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write(badBody)
	}))
	defer badServer.Close()
	badParsed, _ := url.Parse(badServer.URL)
	badBaseURLA := "https://a.example.test:" + badParsed.Port() + "/distribution/sha256/"
	badBaseURLB := "https://b.example.test:" + badParsed.Port() + "/distribution/sha256/"
	badMirrors := []wire.DistributionMirrorRefV1{
		{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: hash("bad-set-1"), ListenerGeneration: 1, BaseURL: badBaseURLA, ServerName: "a.example.test", WebPKIProfileRef: "webpki-v1", SPKIPins: []string{badPin}},
		{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: hash("bad-set-2"), ListenerGeneration: 1, BaseURL: badBaseURLB, ServerName: "b.example.test", WebPKIProfileRef: "webpki-v1", SPKIPins: []string{badPin}},
	}
	badDial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, badParsed.Host)
	}
	if _, err := (MirrorFetcher{RootCAs: badRoots, DialContext: badDial}).FetchCanonicalObject(context.Background(), badMirrors, expectedHash, "test-bootstrap-object-v1", 4096); err == nil {
		t.Fatal("accepted non-canonical bytes for an immutable object")
	}
}

func TestInviteURICarrierRejectsPaddingAndWhitespace(t *testing.T) {
	descriptor := &wire.InviteBootstrapDescriptorV2{Schema: 2, ClusterID: "cluster", InviteID: "invite"}
	uri, err := EncodeInviteURI(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInviteURI(uri)
	if err != nil || decoded.ClusterID != descriptor.ClusterID {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	if _, err := DecodeInviteURI(uri + "="); err == nil {
		t.Fatal("accepted padded base64url descriptor")
	}
	if _, err := DecodeInviteURI(uri + "\n"); err == nil {
		t.Fatal("accepted whitespace in descriptor carrier")
	}
}
