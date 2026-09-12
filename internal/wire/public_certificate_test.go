package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"testing"
)

func TestCertificateIntentSeparatesStableIdentityFromIssuance(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "demo-edge.example"}, DNSNames: []string{"demo-edge.example"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	digest := sha256.Sum256(spki)
	projection := CertificateIdentityProjectionV1{
		Schema: 1, ClusterID: "demo-cluster", IntentID: "public-edge", IdentityGeneration: 3,
		EndpointIDs: []string{"bootstrap-edge", "distribution-edge"}, DNSNames: []string{"demo-edge.example"},
		IssuerProfileRef: "public-webpki", KeyOwnerDeviceID: "demo-edge",
		KeyArtifactHash: HashRaw("test-key-artifact-v1", []byte("edge-key-3")),
		SPKIHash:        "sha256:" + hex.EncodeToString(digest[:]),
	}
	first, err := NewCertificateIntentV1(projection, 8, csrDER, 30*24*60*60, 7*24*60*60)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.IssuanceGeneration++
	firstIdentityHash, _ := CertificateIdentityProjectionHash(&first.IdentityProjection)
	secondIdentityHash, _ := CertificateIdentityProjectionHash(&second.IdentityProjection)
	firstIntentHash, _ := CertificateIntentHash(&first)
	secondIntentHash, _ := CertificateIntentHash(&second)
	if firstIdentityHash != secondIdentityHash || firstIntentHash == secondIntentHash {
		t.Fatal("例行签发 generation 错误改变稳定 identity，或没有改变签发 intent")
	}
	listener := ListenerGenerationV2{
		Schema: 2, ListenerGeneration: 1, PublishedState: "preferred", DialTargetFQDN: "demo-edge.example",
		PublicPort: 443, AddressFamilies: []string{"ipv4"}, TransportIdentityRefs: []string{"spki:" + projection.SPKIHash},
		CredentialGeneration: 1, CertificateIdentityProjectionHash: firstIdentityHash, PublicProfileGeneration: 1,
		IntroducedRevision: 1, ValidFrom: "2026-09-12T00:00:00Z", ValidUntil: "2026-10-12T00:00:00Z",
		RotationOperationHash: HashRaw("test-rotation-v1", []byte("rotation")),
	}
	if err := ValidateListenerGeneration(&listener, "trojan_tls"); err != nil {
		t.Fatal(err)
	}
	listener.CertificateIdentityProjectionHash = ""
	if err := ValidateListenerGeneration(&listener, "trojan_tls"); err == nil {
		t.Fatal("TLS listener 未绑定稳定 identity projection 却通过")
	}
}

func TestCertificateIntentRejectsCSRIdentityExpansion(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "demo-edge.example"},
		DNSNames: []string{"demo-edge.example", "unexpected.example"}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, privateKey)
	spki, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	digest := sha256.Sum256(spki)
	projection := CertificateIdentityProjectionV1{
		Schema: 1, ClusterID: "demo-cluster", IntentID: "public-edge", IdentityGeneration: 1,
		EndpointIDs: []string{"bootstrap-edge"}, DNSNames: []string{"demo-edge.example"},
		IssuerProfileRef: "public-webpki", KeyOwnerDeviceID: "demo-edge",
		KeyArtifactHash: HashRaw("test-key-artifact-v1", []byte("edge-key")),
		SPKIHash:        "sha256:" + hex.EncodeToString(digest[:]),
	}
	if _, err := NewCertificateIntentV1(projection, 1, csrDER, 30*24*60*60, 7*24*60*60); err == nil {
		t.Fatal("CSR 额外 DNS identity 未被拒绝")
	}
}
