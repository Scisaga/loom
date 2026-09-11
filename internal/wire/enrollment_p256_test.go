package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestClaimCoreBindsP256IdentityCSRAndIndependentWrappingKey(t *testing.T) {
	identity, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "request"}, SignatureAlgorithm: x509.ECDSAWithSHA256}, identity)
	hash := HashRaw("p256-test", []byte("hash"))
	core := EnrollmentClaimCoreV2{
		Schema: 2, ClusterID: "cluster", InviteID: "invite", RequestID: "request", CertifiedInviteRecordHash: hash,
		DeviceEnrollmentIntentCommitmentHash: hash, DeviceEnrollmentIntentOpeningHash: hash, AcceptedDeviceEnrollmentIntentHash: hash,
		ClientPlatform: "android", BaseRecoveryEpoch: 0, BaseControlEpoch: 0, BaseControlSetHash: hash, BaseHeadHash: hash,
		DeviceIdentityPublicKey: base64.RawURLEncoding.EncodeToString(identitySPKI), DeviceIdentityKeyProfile: "p256-android-keystore-sha256-v1",
		WrappingPublicKey: base64.RawURLEncoding.EncodeToString(wrappingSPKI), WrappingKeyProfile: "p256-keystore-ecdh-v1",
		CSRDER: base64.RawURLEncoding.EncodeToString(csr), ClientNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	if _, err := EnrollmentClaimCoreHash(&core); err != nil {
		t.Fatal(err)
	}
	core.WrappingPublicKey = core.DeviceIdentityPublicKey
	if _, err := EnrollmentClaimCoreHash(&core); err == nil {
		t.Fatal("identity key was accepted as wrapping key")
	}
}

func TestP256PoPRequiresCanonicalLowS(t *testing.T) {
	identity, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := HashRaw("p256-test", []byte("hash"))
	body := EnrollmentPoPBodyV2{Schema: 2, ClusterID: "cluster", InviteID: "invite", RequestID: "request", ClaimCoreHash: hash, TokenCommitment: hash, ChallengeHash: hash}
	canonical, _ := MarshalCanonical(body)
	message, _ := Frame(DomainEnrollmentPoPSignature, canonical)
	digest := sha256.Sum256(message)
	r, s, _ := ecdsa.Sign(rand.Reader, identity, digest[:])
	half := new(big.Int).Rsh(new(big.Int).Set(identity.Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(identity.Params().N, s)
	}
	lowDER, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err := VerifyEnrollmentPoPP256(&body, &identity.PublicKey, base64.RawURLEncoding.EncodeToString(lowDER)); err != nil {
		t.Fatal(err)
	}
	highS := new(big.Int).Sub(identity.Params().N, s)
	highDER, _ := asn1.Marshal(struct{ R, S *big.Int }{r, highS})
	if err := VerifyEnrollmentPoPP256(&body, &identity.PublicKey, base64.RawURLEncoding.EncodeToString(highDER)); err == nil {
		t.Fatal("high-S malleable signature accepted")
	}
}
