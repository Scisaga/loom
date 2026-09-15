package enrollmentv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"loom/internal/wire"
)

func TestDeviceIssuerUsesAdmittedPublicKeyAndCurrentCertifiedProfile(t *testing.T) {
	input, key := deviceIssuerFixture(t)
	signer := &deviceIssuerHandle{public: key.Public(), sign: key.Sign}
	der, err := IssueReservedDeviceCertificate(input, signer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	intent := input.Reservation.ClaimEvidence.Opening.DeviceEnrollmentIntent
	issuedAt, _ := wire.ParseTimeZ(input.Coordinate.CommittedLogicalTime)
	coordinate := wire.IssuanceLogCoordinateV1{RecoveryEpoch: input.Coordinate.RecoveryEpoch, RaftIndex: input.Coordinate.RaftIndex}
	if _, err := wire.VerifyDeviceCertificateAt(der, &input.Profile, intent.DeviceID, input.Reservation.State.IdentityKeyHash,
		intent.Platform, intent.Responsibilities.Values, coordinate, issuedAt, issuedAt); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, input.IdentitySPKIDER) || leaf.IsCA ||
		leaf.SignatureAlgorithm != x509.PureEd25519 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("签发器改变了客户端持有的 identity 或 certificate role")
	}
	if signer.calls != 1 {
		t.Fatalf("opaque signing handle calls=%d", signer.calls)
	}
}

// Only the provider retains the private key; issuance receives a signing handle.
type deviceIssuerHandle struct {
	public crypto.PublicKey
	sign   func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
	calls  int
}

func (handle *deviceIssuerHandle) Public() crypto.PublicKey { return handle.public }

func (handle *deviceIssuerHandle) Sign(random io.Reader, message []byte, options crypto.SignerOpts) ([]byte, error) {
	handle.calls++
	if options.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("provider requires pure Ed25519")
	}
	return handle.sign(random, message, options)
}

func TestDeviceIssuerPreservesProviderFailureWithoutCertificate(t *testing.T) {
	input, key := deviceIssuerFixture(t)
	unavailable := errors.New("demo-exact-key-version-unavailable")
	signer := &deviceIssuerHandle{public: key.Public(), sign: func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
		return nil, unavailable
	}}
	der, err := IssueReservedDeviceCertificate(input, signer, rand.Reader)
	if len(der) != 0 || !errors.Is(err, unavailable) || signer.calls != 1 {
		t.Fatalf("provider failure bypassed: bytes=%d calls=%d err=%v", len(der), signer.calls, err)
	}
}

func TestDeviceIssuerRejectsUncertifiedAndConflictingInputsBeforeSigning(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DeviceIssuanceContext, *ed25519.PrivateKey)
	}{
		{"identity-key", func(input *DeviceIssuanceContext, _ *ed25519.PrivateKey) {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			input.IdentitySPKIDER, _ = x509.MarshalPKIXPublicKey(&key.PublicKey)
		}},
		{"issuer-key", func(_ *DeviceIssuanceContext, key *ed25519.PrivateKey) { _, *key, _ = ed25519.GenerateKey(rand.Reader) }},
		{"missing-registry", func(input *DeviceIssuanceContext, _ *ed25519.PrivateKey) { input.CARegistry.DeviceProfiles = nil }},
		{"missing-qc", func(input *DeviceIssuanceContext, _ *ed25519.PrivateKey) { input.ConfigQC = nil }},
		{"wrong-parent", func(input *DeviceIssuanceContext, _ *ed25519.PrivateKey) {
			input.Coordinate.ParentHeadHash = wire.EmptyHashV1
		}},
		{"retry-expired", func(input *DeviceIssuanceContext, _ *ed25519.PrivateKey) {
			input.Coordinate.CommittedLogicalTime = input.Reservation.ClaimOperation.RetryNotAfter
		}},
		{"token-binding", func(input *DeviceIssuanceContext, _ *ed25519.PrivateKey) {
			input.Reservation.ClaimOperation.TokenCommitment = wire.EmptyHashV1
		}},
		{"second-issuance", func(input *DeviceIssuanceContext, _ *ed25519.PrivateKey) {
			input.Reservation.State.Status = "issued_provisional"
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input, key := deviceIssuerFixture(t)
			test.mutate(&input, &key)
			random := &issuerRandomGuard{t: t}
			if _, err := IssueReservedDeviceCertificate(input, key, random); err == nil {
				t.Fatal("无效输入仍生成 Device leaf")
			}
		})
	}
}

type issuerRandomGuard struct{ t *testing.T }

func (random *issuerRandomGuard) Read([]byte) (int, error) {
	random.t.Fatal("未拒绝无效请求就进入签发/随机数边界")
	return 0, nil
}

func deviceIssuerFixture(t *testing.T) (DeviceIssuanceContext, ed25519.PrivateKey) {
	t.Helper()
	fixture := newApprovalEvidenceFixture(t)
	record := durableRecordForApprovalFixture(t, fixture)
	record.State, _ = Reserve(record.Invite, record.ClaimOperation, &record.AdmissionQC, &record.AdmissionControlSet, record.ClaimOperation.ReservedAt)
	record.ProvisionalOperation, record.ProvisionalIssuance, record.DeviceCertificateProfile = nil, nil, nil
	record.ResultArtifact, record.ProvisionalCertification = nil, nil
	record.ReservationToIssuanceHeads, record.ReservationToIssuanceTransitions = nil, nil
	der, err := wire.EnrollmentResultCertificateDER(&fixture.evidence.ResultArtifact)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return DeviceIssuanceContext{Reservation: record, Head: fixture.evidence.Reservation.Head,
		ConfigQC: fixture.evidence.Reservation.ConfigQC, ControlSet: fixture.set,
		CARegistry: fixture.evidence.ReservationCARegistry, Profile: fixture.evidence.DeviceCertificateProfile,
		Coordinate: coordinateForCertifiedHead(&fixture.evidence.Issuance.Head), IdentitySPKIDER: leaf.RawSubjectPublicKeyInfo,
	}, fixture.issuerKey
}
