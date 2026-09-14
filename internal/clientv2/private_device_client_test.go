package clientv2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/wire"
)

type privateDeviceInvalidSigner struct{ public crypto.PublicKey }

func (signer privateDeviceInvalidSigner) Public() crypto.PublicKey { return signer.public }
func (privateDeviceInvalidSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestPrivateDeviceClientUsesExactTupleTLS13PinAndDeviceSigner(t *testing.T) {
	now := time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)
	serverCertificate, roots, serverPin, clientChain, clientKey := privateDeviceTestPKI(t, now)
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/private/v2/device/config" ||
			request.Host != "10.50.0.2:7445" || request.TLS == nil ||
			request.TLS.Version != tls.VersionTLS13 || len(request.TLS.PeerCertificates) == 0 {
			t.Errorf("private Device 请求未使用 exact route/TLS/mTLS")
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		body, err := wire.MarshalCanonical(wire.DeviceConfigDeliveryV1{Schema: 1})
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", wire.DeviceConfigDeliveryMediaTypeV1)
		_, _ = writer.Write(body)
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAnyClientCert,
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	service := wire.PrivateControlServiceV1{
		ServiceID: "device-config-primary", Role: "device_config", OverlayIP: "10.50.0.2", Port: 7445,
		CertificateProfileRef: "internal-device-config-server", SPKIPins: []string{serverPin},
		AuthorizedSubjectProfiles: []string{"device-profile"},
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "10.50.0.2:7445" {
			t.Fatalf("private Device dial 逃离 certified tuple: %s %s", network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client, err := NewPrivateDeviceHTTPClient(service, "device_config", "device-profile",
		clientChain, clientKey, roots, dial, func() time.Time { return now }, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	delivery, err := client.FetchDeviceConfigDelivery(context.Background())
	if err != nil || delivery.Schema != 1 || requests != 1 {
		t.Fatalf("private Device delivery=%+v requests=%d err=%v", delivery, requests, err)
	}

	wrongPin := service
	wrongPin.SPKIPins = []string{wire.HashRaw("private-device-test", []byte("wrong"))}
	rejected, err := NewPrivateDeviceHTTPClient(wrongPin, "device_config", "device-profile",
		clientChain, clientKey, roots, dial, func() time.Time { return now }, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rejected.CloseIdleConnections()
	if _, err := rejected.FetchDeviceConfigDelivery(context.Background()); err == nil {
		t.Fatal("错误 private service SPKI pin 通过了 inner TLS")
	}
}

func TestPrivateDeviceClientRejectsIncompletePlatformPublicKey(t *testing.T) {
	service := wire.PrivateControlServiceV1{
		ServiceID: "device-config-primary", Role: "device_config", OverlayIP: "10.50.0.2", Port: 7445,
		CertificateProfileRef: "internal-device-config-server", SPKIPins: []string{wire.EmptyHashV1},
		AuthorizedSubjectProfiles: []string{"device-profile"},
	}
	var nilP256 *ecdsa.PublicKey
	for _, public := range []crypto.PublicKey{nilP256, &ecdsa.PublicKey{Curve: elliptic.P256()}} {
		if _, err := NewPrivateDeviceHTTPClient(service, "device_config", "device-profile",
			[][]byte{{1}}, privateDeviceInvalidSigner{public: public}, x509.NewCertPool(), nil,
			time.Now, 5*time.Second); err == nil {
			t.Fatal("接受了不完整的 Device platform public key")
		}
	}
}

func privateDeviceTestPKI(t *testing.T, now time.Time) (tls.Certificate, *x509.CertPool,
	string, [][]byte, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "Loom private Device test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate,
		&rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, commonName string, usages []x509.ExtKeyUsage,
		addresses []net.IP) ([]byte, *ecdsa.PrivateKey) {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial),
			Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: usages, IPAddresses: addresses}
		der, issueErr := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return der, key
	}
	serverDER, serverKey := issue(2, "private device config", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]net.IP{net.ParseIP("10.50.0.2")})
	clientDER, clientKey := issue(3, "private device client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	serverLeaf, err := x509.ParseCertificate(serverDER)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(serverLeaf.RawSubjectPublicKeyInfo)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return tls.Certificate{Certificate: [][]byte{serverDER, rootDER}, PrivateKey: serverKey,
			Leaf: serverLeaf}, roots, "sha256:" + hex.EncodeToString(digest[:]),
		[][]byte{clientDER, rootDER}, clientKey
}
