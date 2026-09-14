package wire

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"io"
	"math/big"
	"testing"
	"time"
)

type recordingP256Signer struct {
	key       *ecdsa.PrivateKey
	digest    []byte
	algorithm crypto.Hash
	badDER    bool
}

type invalidPublicSigner struct{ public crypto.PublicKey }

func (signer invalidPublicSigner) Public() crypto.PublicKey { return signer.public }

func (invalidPublicSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (signer *recordingP256Signer) Public() crypto.PublicKey {
	return &signer.key.PublicKey
}

func (signer *recordingP256Signer) Sign(_ io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	signer.digest = append([]byte(nil), digest...)
	signer.algorithm = options.HashFunc()
	if signer.badDER {
		return []byte{0x30, 0x01, 0x00}, nil
	}
	r, s, err := ecdsa.Sign(rand.Reader, signer.key, digest)
	if err != nil {
		return nil, err
	}
	// 强制制造 high-S，验证共享边界会归一化宿主返回值。
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(signer.key.Params().N), 1)) <= 0 {
		s.Sub(signer.key.Params().N, s)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
}

func TestPlatformSignerEnrollmentPoPUsesDigestAndNormalizesLowS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "demo-invite", RequestID: "demo-request",
		ClaimCoreHash: EmptyHashV1, TokenCommitment: EmptyHashV1, ChallengeHash: EmptyHashV1,
	}
	signer := &recordingP256Signer{key: key}
	signature, err := SignEnrollmentPoPWithSigner(&body, signer)
	if err != nil {
		t.Fatal(err)
	}
	message, _ := EnrollmentPoPMessage(&body)
	digest := sha256.Sum256(message)
	if signer.algorithm != crypto.SHA256 || string(signer.digest) != string(digest[:]) {
		t.Fatal("平台 signer 未收到 exact SHA-256 digest")
	}
	if err := VerifyEnrollmentPoPP256(&body, &key.PublicKey, signature); err != nil {
		t.Fatalf("归一化后的 PoP 未通过共享 verifier: %v", err)
	}
}

func TestPlatformSignerDeviceReportAndMalformedDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"state":"ready"}`)
	payloadHash, _ := DeviceReportPayloadHash(payload)
	body := DeviceReportBodyV2{
		Schema: 2, ClusterID: "demo-cluster", DeviceID: "demo-device", ReportID: "demo-report",
		ReportSequence: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		AcceptedFloors: reportTestFloors(),
		Kind:           "health", PayloadSchema: 1, PayloadHash: payloadHash,
	}
	body.AcceptedFloors.ClusterID = body.ClusterID
	schemas := DeviceReportSchemaRegistry{"health": 1}
	signer := &recordingP256Signer{key: key}
	envelope, err := SignDeviceReportWithSigner(body, payload, signer, schemas)
	if err != nil {
		t.Fatal(err)
	}
	identityDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	identityHash, _ := HashBytes(DomainEnrollmentIdentitySPKI, identityDER)
	if err := VerifyDeviceReport(&envelope, &key.PublicKey, body.DeviceID, identityHash,
		time.Now().UTC(), time.Hour, time.Minute, schemas); err != nil {
		t.Fatalf("平台 signer report 未通过共享 verifier: %v", err)
	}
	signer.badDER = true
	if _, err := SignEnrollmentPoPWithSigner(&EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "demo-invite", RequestID: "demo-request",
		ClaimCoreHash: EmptyHashV1, TokenCommitment: EmptyHashV1, ChallengeHash: EmptyHashV1,
	}, signer); err == nil {
		t.Fatal("接受了平台 signer 的非规范 DER")
	}
}

func TestPlatformSignerRejectsIncompleteP256PublicKey(t *testing.T) {
	body := &EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "demo-invite", RequestID: "demo-request",
		ClaimCoreHash: EmptyHashV1, TokenCommitment: EmptyHashV1, ChallengeHash: EmptyHashV1,
	}
	var nilP256 *ecdsa.PublicKey
	for _, public := range []crypto.PublicKey{
		nilP256,
		&ecdsa.PublicKey{Curve: elliptic.P256()},
	} {
		if _, err := SignEnrollmentPoPWithSigner(body, invalidPublicSigner{public: public}); err == nil {
			t.Fatal("接受了不完整的 P-256 public key")
		}
	}
}
