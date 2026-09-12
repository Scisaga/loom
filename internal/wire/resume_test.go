package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

func TestEnrollmentResumeDescriptorBindsPendingTransactionAndHasNoToken(t *testing.T) {
	catalog, _, _ := testBootstrapCatalog(t)
	catalogHash, _ := BootstrapEndpointCatalogHash(catalog)
	policy := testInvitePolicy()
	policyHash, _ := InviteIssuancePolicyHash(&policy)
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-1] = 77
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, _ := ControlKeyID(publicKey)
	service := PrivateEnrollmentServiceRefV1{
		Schema: 1, ServiceID: "enrollment-service-1", OverlayIP: "10.30.0.1", TCPPort: 7444,
		InternalCAProfileRef: "internal-enrollment-ca-v1", ServiceGeneration: 1,
		ServerIdentitySPKIPins: []string{HashRaw("resume-test-pin-v1", []byte("service"))},
	}
	serviceHash, _ := PrivateEnrollmentServiceRefHash(&service)
	authorization := BootstrapIssuerAuthorizationV1{
		Schema: 1, ClusterID: policy.ClusterID, AuthorizationID: "bootstrap-issuer-1", Generation: 1, Status: "active",
		Active: &BootstrapIssuerAuthorizationActiveV1{
			IssuerEpoch: 1, IssuerKeyID: keyID, IssuerPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
			InviteIssuancePolicyHash: policyHash, ValidFrom: "2026-09-11T00:00:00Z", ValidUntil: "2026-09-12T00:00:00Z",
			MaximumCapabilityTTLSeconds: 900, MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1,
			MaximumSessionSeconds: 180, MaximumTotalBytes: 8 << 20,
			PermittedIngressSetHashes: []string{catalog.BootstrapIngressSetHash}, PermittedServiceIDs: []string{service.ServiceID},
			PermittedModes: []string{"initial_claim", "resume_committed_claim"},
		},
		ParentHeadHash: HashRaw("resume-test-head-v1", []byte("head")),
	}
	authorizationHash, _ := BootstrapIssuerAuthorizationHash(&authorization)
	leaf := BootstrapIssuerAuthorizationLeafV1{Schema: 1, AuthorizationID: authorization.AuthorizationID, Generation: 1, AuthorizationHash: authorizationHash}
	leafBytes, _ := MarshalCanonical(leaf)
	registryRoot := "sha256:" + hex.EncodeToString(MerkleRoot([][]byte{leafBytes}))
	proof := BootstrapIssuerAuthorizationProofV1{
		Schema: 1, ClusterID: policy.ClusterID, Authorization: authorization, AuthorizationHash: authorizationHash,
		Leaf: leaf, LeafIndex: 0, RegistryTreeSize: 1, RegistryAuditPath: []string{}, RegistryRoot: registryRoot,
	}
	hash := func(name string) string { return HashRaw("resume-test-v1", []byte(name)) }
	binding := BootstrapCapabilityResumeBindingV1{
		RequestID: "request-1", ClaimOperationHash: hash("claim-operation"), AdmissionQCHash: hash("admission-qc"),
		ClaimCoreHash: hash("claim-core"), CSRHash: hash("csr"), IdentityKeyHash: hash("identity"),
		WrappingKeyHash: hash("wrapping"), EnrollmentTransactionStateHash: hash("transaction"),
	}
	body := BootstrapTunnelCapabilityBodyV1{
		Schema: 1, ClusterID: policy.ClusterID, InviteID: "invite-1", CommittedInviteRecordHash: hash("invite-record"),
		InviteIssuancePolicyHash: policyHash, BootstrapIssuerAuthorizationHash: authorizationHash,
		BootstrapIssuerRegistryRoot: registryRoot, EnrollmentServiceRefHash: serviceHash,
		Mode: "resume_committed_claim", ResumeBinding: &binding,
		IssuedAt: "2026-09-11T11:00:00Z", NotBefore: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:15:00Z",
		AllowedIngressSetHash: catalog.BootstrapIngressSetHash, AllowedServiceID: service.ServiceID,
		AllowedDestinationIP: service.OverlayIP, AllowedDestinationPrefixLength: 32, AllowedDestinationPort: service.TCPPort,
		AllowedInsideTransport: "tcp", MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1,
		MaximumSessionSeconds: 180, MaximumTotalBytes: 8 << 20, IssuerEpoch: 1, IssuerKeyID: keyID,
	}
	capability, err := SignBootstrapCapability(body, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := EnrollmentResumeDescriptorV1{
		Schema: 1, ClusterID: policy.ClusterID, InviteID: "invite-1", RequestID: binding.RequestID,
		ExpiresAt: "2026-09-11T11:14:00Z", ResumeTunnelCapability: capability,
		ClaimCoreHash: binding.ClaimCoreHash, ClaimOperationHash: binding.ClaimOperationHash,
		AdmissionQCHash: binding.AdmissionQCHash, EnrollmentTransactionStateHash: binding.EnrollmentTransactionStateHash,
		BootstrapCatalogHash: catalogHash, ProofBundleHash: hash("proof-bundle"), EnrollmentServiceRef: service,
		DistributionMirrors: []DistributionMirrorRefV1{
			{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: hash("mirror-set-1"), ListenerGeneration: 1, BaseURL: "https://a.example.test:443/distribution/sha256/", ServerName: "a.example.test", WebPKIProfileRef: "webpki-v1", SPKIPins: []string{hash("mirror-pin-1")}, HintRank: 0},
			{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: hash("mirror-set-2"), ListenerGeneration: 1, BaseURL: "https://b.example.test:8443/distribution/sha256/", ServerName: "b.example.test", WebPKIProfileRef: "webpki-v1", SPKIPins: []string{hash("mirror-pin-2")}, HintRank: 1},
		},
	}
	expected := EnrollmentResumeExpectedV1{
		ClusterID: descriptor.ClusterID, InviteID: descriptor.InviteID, RequestID: descriptor.RequestID,
		ClaimCoreHash: binding.ClaimCoreHash, ClaimOperationHash: binding.ClaimOperationHash,
		AdmissionQCHash: binding.AdmissionQCHash, CSRHash: binding.CSRHash, IdentityKeyHash: binding.IdentityKeyHash,
		WrappingKeyHash: binding.WrappingKeyHash, EnrollmentTransactionStateHash: binding.EnrollmentTransactionStateHash,
		RetryNotAfter: "2026-09-11T11:20:00Z",
	}
	trustedTime := time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC)
	if err := VerifyEnrollmentResumeDescriptorBindings(&descriptor, expected, catalog, &proof, &policy, trustedTime, 2); err != nil {
		t.Fatal(err)
	}
	olderFloor := expected
	olderFloor.EnrollmentTransactionStateHash = hash("earlier-reserved-floor")
	if err := VerifyEnrollmentResumeDescriptorBindings(&descriptor, olderFloor, catalog,
		&proof, &policy, trustedTime, 2); err != nil {
		t.Fatalf("服务端已前进后的 signed resume target 未被接受: %v", err)
	}
	tooFewMirrors := descriptor
	tooFewMirrors.DistributionMirrors = tooFewMirrors.DistributionMirrors[:1]
	if err := VerifyEnrollmentResumeDescriptorBindings(&tooFewMirrors, expected, catalog,
		&proof, &policy, trustedTime, 2); err == nil {
		t.Fatal("resume descriptor 绕过了 certified mirror count")
	}
	expected.WrappingKeyHash = hash("another-wrapping-key")
	if err := VerifyEnrollmentResumeDescriptorBindings(&descriptor, expected, catalog, &proof, &policy, trustedTime, 2); err == nil {
		t.Fatal("resume descriptor 接受了另一把本机 wrapping key")
	}

	wireBytes, _ := MarshalCanonical(descriptor)
	withToken := append(append([]byte(nil), wireBytes[:len(wireBytes)-1]...), []byte(`,"token":"forbidden"}`)...)
	var decoded EnrollmentResumeDescriptorV1
	if _, err := DecodeStrict(withToken, 1<<20, &decoded); err == nil {
		t.Fatal("resume descriptor 接受了被禁止的 token 字段")
	}
}
