package loomcore

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestVersion(t *testing.T) {
	if got, want := Version(), "android-stage3-v1"; got != want {
		t.Fatalf("Version() = %q, want %q", got, want)
	}
}

func TestVerifySignedConfig(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"stage":1}`)
	signature := ed25519.Sign(privateKey, config)
	if err := VerifySignedConfig(config, signature, publicKey); err != nil {
		t.Fatal(err)
	}
	config[1] ^= 1
	if err := VerifySignedConfig(config, signature, publicKey); err == nil {
		t.Fatal("被篡改的配置验签成功")
	}
}

func TestKeystoreStyleSignatureAndCSR(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("keystore proof")
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyP256Signature(publicKey, message, signature); err != nil {
		t.Fatal(err)
	}

	infoDER, err := PrepareCSR("demo-request", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest = sha256.Sum256(infoDER)
	signature, err = ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := AssembleCSR(infoDER, signature)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("组装结果不是单个 PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "demo-request" {
		t.Fatalf("组装的 CSR 无效: csr=%+v err=%v", csr, err)
	}
}

func TestCSRRejectsWrongExternalKeyAndTamper(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	infoDER, err := PrepareCSR("demo-request", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(infoDER)
	signature, _ := ecdsa.SignASN1(rand.Reader, other, digest[:])
	if _, err := AssembleCSR(infoDER, signature); err == nil {
		t.Fatal("错误 Keystore 密钥的 CSR 被接受")
	}
	if _, err := PrepareCSR(" bad\n", publicKey); err == nil {
		t.Fatal("无效 request_id 被接受")
	}
}
