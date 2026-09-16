package loomcore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/devicehttp"
	"loom/internal/wire"
)

type androidTestMessageSigner struct {
	key   *ecdsa.PrivateKey
	calls int
}

func (s *androidTestMessageSigner) SignP256(message []byte) ([]byte, error) {
	s.calls++
	digest := sha256.Sum256(message)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

func TestAndroidKeystoreMessageCallbackWithEd25519PrivateTLS(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	_, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issue := func(id int64, public crypto.PublicKey, usage x509.ExtKeyUsage) []byte {
		t.Helper()
		template := &x509.Certificate{SerialNumber: big.NewInt(id), NotBefore: root.NotBefore,
			NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			template.IPAddresses = []net.IP{net.ParseIP("10.50.0.2")}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, root, public, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	serverDER := issue(2, serverKey.Public(), x509.ExtKeyUsageServerAuth)
	clientDER := issue(3, &clientKey.PublicKey, x509.ExtKeyUsageClientAuth)
	leaf, _ := x509.ParseCertificate(serverDER)
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/private/v2/device/config" || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) != 1 {
			t.Error("私有请求没有通过完整 mTLS")
		}
		body, _ := wire.MarshalCanonical(wire.DeviceConfigDeliveryV1{Schema: 1})
		w.Header().Set("Content-Type", wire.DeviceConfigDeliveryMediaTypeV1)
		_, _ = w.Write(body)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER, rootDER}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: roots, Time: func() time.Time { return now }}
	server.StartTLS()
	defer server.Close()
	service := wire.PrivateControlServiceV1{ServiceID: "demo-private-config", Role: "device_config",
		OverlayIP: "10.50.0.2", Port: 7445, CertificateProfileRef: "demo-internal",
		SPKIPins: []string{"sha256:" + hex.EncodeToString(pin[:])}, AuthorizedSubjectProfiles: []string{"demo-device"}}
	callback := &androidTestMessageSigner{key: clientKey}
	signer := androidMessageSigner{public: &clientKey.PublicKey, callback: callback}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "10.50.0.2:7445" || network != "tcp" {
			t.Fatal("拨号离开认证私有 tuple")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client, err := devicehttp.NewPrivateDeviceHTTPClient(service, service.Role, "demo-device",
		[][]byte{clientDER, rootDER}, signer, roots, dial, func() time.Time { return now }, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.FetchDeviceConfigDelivery(context.Background()); err != nil || requests != 1 || callback.calls != 1 {
		t.Fatalf("完整消息签名未通过私有 TLS：requests=%d callbacks=%d error=%v", requests, callback.calls, err)
	}
	if _, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("错误地接受预哈希签名")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer.callback = &androidTestMessageSigner{key: other}
	if _, err := signer.SignMessage(rand.Reader, []byte("demo-message"), crypto.SHA256); err == nil {
		t.Fatal("接受了另一身份的回调签名")
	}
}
