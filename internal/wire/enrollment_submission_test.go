package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"testing"
	"time"
)

func TestEnrollmentSubmissionBindsTokenOpeningCoreChallengeAndP256PoP(t *testing.T) {
	policy := testInvitePolicy()
	policyHash, _ := InviteIssuancePolicyHash(&policy)
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tokenCommitment, _ := TokenCommitment(policy.ClusterID, "invite-1", token)
	hash := func(value string) string { return HashRaw("submission-test-v1", []byte(value)) }
	intent := DeviceEnrollmentIntentV1{
		Schema: 1, ClusterID: policy.ClusterID, InviteID: "invite-1", DeviceID: "linux-device-1", Platform: "linux-server",
		DeviceCertificateProfileRef: DeviceCertificateProfileRefV1{
			ProfileID: "device-profile-1", Generation: 1,
			DeviceCertificateProfileIntentHash: hash("profile-intent"), DeviceCertificateProfileStateHash: hash("profile-state"),
		},
		WrappingKeyProfiles: []string{"p256-root-only-pkcs8-ecdh-v1"},
		Membership:          EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities:    EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}},
		Grants:              EnrollmentDestinationGrantsV1{Schema: 1, Values: []EnrollmentDestinationGrantV1{}},
	}
	intentHash, _ := EnrollmentIntentHash(&intent)
	opening := DeviceEnrollmentIntentOpeningV1{
		Schema: 1, ClusterID: policy.ClusterID, InviteID: "invite-1", DeviceEnrollmentIntent: intent,
		DeviceEnrollmentIntentHash: intentHash, HidingNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	_, commitmentHash, err := IntentCommitment(&opening)
	if err != nil {
		t.Fatal(err)
	}
	record := CertifiedInviteRecordV2{
		Schema: 2, ClusterID: policy.ClusterID, InviteID: "invite-1", Generation: 1,
		IssuedAt: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:20:00Z",
		DeviceEnrollmentIntentCommitmentHash: commitmentHash, TokenCommitment: tokenCommitment,
		TokenArtifactBindingHash: hash("token-artifact"), InviteIssuancePolicyHash: policyHash,
		BootstrapIssuerAuthorizationHash: hash("authorization"), BootstrapIssuerRegistryRoot: hash("registry"),
		BootstrapCatalogHash: hash("catalog"), EnrollmentServiceRefHash: hash("service"),
		OperationID: "operation-1", ParentHeadHash: hash("parent-head"),
	}
	recordHash, _ := CertifiedInviteRecordHash(&record, &policy)
	identityKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrappingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "request-1"}}, identityKey)
	core := EnrollmentClaimCoreV2{
		Schema: 2, ClusterID: policy.ClusterID, InviteID: "invite-1", RequestID: "request-1",
		CertifiedInviteRecordHash: recordHash, DeviceEnrollmentIntentCommitmentHash: commitmentHash,
		DeviceEnrollmentIntentOpeningHash: openingHashForTest(t, &opening), AcceptedDeviceEnrollmentIntentHash: intentHash,
		ClientPlatform: "linux-server", BaseRecoveryEpoch: 0, BaseControlEpoch: 0,
		BaseControlSetHash: hash("control-set"), BaseHeadHash: hash("head"),
		DeviceIdentityPublicKey: base64.RawURLEncoding.EncodeToString(identitySPKI), DeviceIdentityKeyProfile: "p256-root-only-pkcs8-sha256-v1",
		WrappingPublicKey: base64.RawURLEncoding.EncodeToString(wrappingSPKI), WrappingKeyProfile: "p256-root-only-pkcs8-ecdh-v1",
		CSRDER: base64.RawURLEncoding.EncodeToString(csrDER), ClientNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	coreHash, err := EnrollmentClaimCoreHash(&core)
	if err != nil {
		t.Fatal(err)
	}
	challenge := EnrollmentPoPChallengeV1{
		Schema: 1, ClusterID: policy.ClusterID, InviteID: "invite-1", RequestID: "request-1",
		EnrollmentServiceID: "enrollment-service-1", ClaimCoreHash: coreHash,
		ServerNonce: base64.RawURLEncoding.EncodeToString(bytesOf(32, 1)),
		IssuedAt:    "2026-09-11T11:05:00Z", ExpiresAt: "2026-09-11T11:06:00Z",
	}
	now := time.Date(2026, 9, 11, 11, 5, 30, 0, time.UTC)
	challengeHash, _ := EnrollmentChallengeHash(&challenge, coreHash, now)
	pop := EnrollmentPoPBodyV2{Schema: 2, ClusterID: policy.ClusterID, InviteID: "invite-1", RequestID: "request-1", ClaimCoreHash: coreHash, TokenCommitment: tokenCommitment, ChallengeHash: challengeHash}
	signature, _ := SignEnrollmentPoPP256(&pop, identityKey)
	submission := &EnrollmentClaimSubmissionV2{Schema: 2, Token: token, ClaimCore: core, Challenge: challenge, PoPBody: pop, ProofSignature: signature}
	verified, err := VerifyEnrollmentClaimSubmission(submission, &record, &policy, &opening, "enrollment-service-1", now)
	if err != nil || verified.ClaimCoreHash != coreHash {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
	submission.PoPBody.TokenCommitment = hash("other-token")
	if _, err := VerifyEnrollmentClaimSubmission(submission, &record, &policy, &opening, "enrollment-service-1", now); err == nil {
		t.Fatal("accepted PoP body detached from the token")
	}
}

func openingHashForTest(t *testing.T, opening *DeviceEnrollmentIntentOpeningV1) string {
	t.Helper()
	hash, err := IntentOpeningHash(opening)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func bytesOf(size int, value byte) []byte {
	result := make([]byte, size)
	for i := range result {
		result[i] = value
	}
	return result
}
