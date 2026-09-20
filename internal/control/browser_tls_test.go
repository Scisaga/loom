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
	"math/big"
	"net/http"
	"testing"
	"time"
)

func TestBrowserTLSUsesP256AndAdvertisesAuthorizedIssuer(t *testing.T) {
	state := testState()
	state.BrowserTLS = testTLS(t)
	admin, adminLeaf := browserTestClient(t)
	encoded := base64.RawURLEncoding.EncodeToString(adminLeaf.Raw)
	state.ReadCertDER = []string{encoded}
	state.AdminCertDER = []string{encoded}

	root := t.TempDir()
	address := freeAddress(t, "127.0.0.1")
	config, err := ActivateLegacy(root, state, "demo-browser-control", "demo-browser-node", []string{address})
	if err != nil {
		t.Fatal(err)
	}
	channel, err := OpenPrivateChannel(PrivateChannelConfig{Node: config.Node, Listen: []string{address}, Peers: map[string][]string{}}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()

	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 ||
			!bytes.Equal(request.TLS.PeerCertificates[0].Raw, adminLeaf.Raw) {
			http.Error(writer, "missing exact client leaf", http.StatusForbidden)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(channel.ControlListener()) }()
	defer func() {
		_ = server.Shutdown(context.Background())
		<-serverDone
	}()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(config.BrowserTLS.CertificateChainPEM)) {
		t.Fatal("browser root is invalid")
	}
	selected := false
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1",
		GetClientCertificate: func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			for _, acceptable := range request.AcceptableCAs {
				if bytes.Equal(acceptable, adminLeaf.RawIssuer) {
					selected = true
					return &admin, nil
				}
			}
			return &tls.Certificate{}, nil
		},
	}}}
	response, err := client.Get("https://" + address + "/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || !selected {
		t.Fatalf("browser-style certificate selection: status=%d selected=%t", response.StatusCode, selected)
	}
	serverLeaf := response.TLS.PeerCertificates[0]
	public, ok := serverLeaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		t.Fatalf("browser server leaf algorithm = %T", serverLeaf.PublicKey)
	}
}

func browserTestClient(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(201), Subject: pkix.Name{CommonName: "demo-browser-admin-ca"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(202), Subject: pkix.Name{CommonName: "demo-browser-admin"},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey, Leaf: leaf}, leaf
}
