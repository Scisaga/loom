package wire

import (
	"crypto"
	"errors"
	"io"
	"testing"
)

func TestProvisionalIssuanceBindsActiveProfileKeyAndFence(t *testing.T) {
	fixture := newDeviceCertificateFixture(t)
	member, _ := deterministicMember(t, 1)
	set := ControlSetV1{Schema: 1, ClusterID: member.ClusterID, Members: []ControlMemberV1{member}}
	stagedHead := testHead(t, &set)
	staged, err := ReduceDeviceCertificateProfile(nil, fixture.intent, &stagedHead, false)
	if err != nil {
		t.Fatal(err)
	}
	stagedHash, _ := DeviceCertificateProfileStateHash(&staged)
	activeIntent := fixture.intent
	activeIntent.Generation = 2
	activeIntent.ExpectedPreviousProfileStateHash = stagedHash
	activeIntent.TargetStatus = "active"
	activeIntent.IssuerFencingEpoch = 2
	activeHead := nextDeviceProfileHead(t, stagedHead, "2026-09-11T12:01:00Z")
	active, err := ReduceDeviceCertificateProfile(&staged, activeIntent, &activeHead, false)
	if err != nil {
		t.Fatal(err)
	}
	profileHash, _ := DeviceCertificateProfileStateHash(&active)
	body := EnrollmentProvisionalIssuanceBodyV1{
		Schema: 1, ClusterID: active.ClusterID, InviteID: "invite-1", RequestID: "request-1",
		ClaimOperationHash:                HashRaw("issuance-test", []byte("claim")),
		ReservationHeadHash:               HashRaw("issuance-test", []byte("reservation-head")),
		ReservationHeadQCHash:             HashRaw("issuance-test", []byte("reservation-qc")),
		DeviceCertificateHash:             HashRaw("issuance-test", []byte("device-certificate")),
		InitialDeviceViewHash:             HashRaw("issuance-test", []byte("device-view")),
		SecretArtifactRefsRoot:            HashRaw("issuance-test", []byte("secret-refs")),
		ResultArtifactHash:                HashRaw("issuance-test", []byte("result")),
		DeviceCertificateProfileStateHash: profileHash,
		IssuanceLogCoordinate:             IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: 3},
	}
	issuance, err := SignEnrollmentProvisionalIssuance(body, &active, fixture.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnrollmentProvisionalIssuance(&issuance, &active); err != nil {
		t.Fatal(err)
	}
	tampered := issuance
	tampered.CASignature.IssuerFencingEpoch++
	if err := VerifyEnrollmentProvisionalIssuance(&tampered, &active); err == nil {
		t.Fatal("接受了改写 fencing epoch 的 provisional issuance")
	}
	if _, err := SignEnrollmentProvisionalIssuance(body, &staged, fixture.issuerKey); err == nil {
		t.Fatal("staged profile 签发了 provisional issuance")
	}
	providerError := errors.New("demo-provider-unavailable")
	for _, test := range []struct {
		name      string
		signature []byte
		failure   error
	}{
		{"provider-error", nil, providerError},
		{"empty-signature", nil, nil},
		{"invalid-signature", make([]byte, 64), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer := failingIssuanceSigner{public: fixture.issuerKey.Public(), signature: test.signature, failure: test.failure}
			result, err := SignEnrollmentProvisionalIssuance(body, &active, signer)
			if err == nil || result.CASignature.Signature != "" {
				t.Fatal("provider failure produced issuance result")
			}
			if test.failure != nil && !errors.Is(err, test.failure) {
				t.Fatalf("provider error lost: %v", err)
			}
		})
	}
}

type failingIssuanceSigner struct {
	public    crypto.PublicKey
	signature []byte
	failure   error
}

func (signer failingIssuanceSigner) Public() crypto.PublicKey { return signer.public }
func (signer failingIssuanceSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return signer.signature, signer.failure
}

func TestEnrollmentIssuanceRegistryIsOrderIndependentAndFirstResultOnly(t *testing.T) {
	first := EnrollmentIssuanceRegistryLeafV1{Schema: 1,
		ClaimOperationHash:      HashRaw("issuance-registry-test", []byte("claim-b")),
		ProvisionalIssuanceHash: HashRaw("issuance-registry-test", []byte("result-b"))}
	second := EnrollmentIssuanceRegistryLeafV1{Schema: 1,
		ClaimOperationHash:      HashRaw("issuance-registry-test", []byte("claim-a")),
		ProvisionalIssuanceHash: HashRaw("issuance-registry-test", []byte("result-a"))}
	one, err := EnrollmentIssuanceRegistryRoot([]EnrollmentIssuanceRegistryLeafV1{first, second})
	if err != nil {
		t.Fatal(err)
	}
	two, err := EnrollmentIssuanceRegistryRoot([]EnrollmentIssuanceRegistryLeafV1{second, first})
	if err != nil || one != two {
		t.Fatalf("issuance registry root 依赖输入顺序: one=%s two=%s err=%v", one, two, err)
	}
	competing := first
	competing.ProvisionalIssuanceHash = HashRaw("issuance-registry-test", []byte("competing"))
	if _, err := EnrollmentIssuanceRegistryRoot([]EnrollmentIssuanceRegistryLeafV1{first, competing}); err == nil {
		t.Fatal("同一 claim 接受了两个 issuance first-result")
	}
}
