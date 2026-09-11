package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func testInvitePolicy() InviteIssuancePolicyV2 {
	return InviteIssuancePolicyV2{
		Schema: 2, ClusterID: "demo-cluster", PolicyID: "default-invite-policy", Generation: 1,
		MinimumTTLSeconds: 300, MaximumTTLSeconds: 1800,
		MaximumDescriptorBytes: 65536, MaximumIntentOpeningBytes: 65536,
		MinimumDistributionMirrors: 2, MaximumDistributionMirrors: 3,
		AllowedBootstrapTransports:         []string{"hysteria2", "trojan_tls"},
		MaximumInitialCapabilityTTLSeconds: 900, MaximumResumeCapabilityTTLSeconds: 900,
		MaximumReservationRetrySeconds: 1800, BootstrapSessionSeconds: 180,
		BootstrapTotalBytes: 8 << 20, BootstrapConnectionAttempts: 3, BootstrapMaxConcurrentSessions: 1,
	}
}

func testBootstrapCatalog(t *testing.T) (*BootstrapEndpointCatalogV1, *ControlSetV1, *HeadEntryV2) {
	t.Helper()
	member, key := deterministicMember(t, 1)
	set := &ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: []ControlMemberV1{member}}
	head := testHead(t, set)
	signature, _ := SignHeadAttestation(AttestationForHead(&head), member, key)
	qc := StableQC(&head, []ControlConfigSignatureV1{signature})
	qcRaw, _ := json.Marshal(qc)
	listener := ListenerGenerationV2{
		Schema: 2, ListenerGeneration: 1, PublishedState: "preferred", DialTargetFQDN: "edge.example.test",
		PublicPort: 8443, AddressFamilies: []string{"ipv4"},
		TransportIdentityRefs: []string{"profile:webpki-v1", "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		CredentialGeneration:  1, CertificateIntentHash: HashRaw("test-certificate-v1", []byte("cert")),
		PublicProfileGeneration: 1, IntroducedRevision: 1,
		ValidFrom: "2026-09-11T00:00:00Z", ValidUntil: "2026-09-12T00:00:00Z",
		RotationOperationHash: HashRaw("test-rotation-v1", []byte("rotation")),
	}
	ingressSet := BootstrapIngressEndpointSetV1{
		Schema: 1, ClusterID: set.ClusterID, EndpointSetID: "bootstrap-ingress", Generation: 1,
		ValidFrom: "2026-09-11T00:00:00Z", ValidUntil: "2026-09-12T00:00:00Z",
		Endpoints: []BootstrapIngressEndpointV1{{
			EndpointID: "bootstrap-edge-1", LogicalServerID: "edge-server-1", Transport: "hysteria2", HintRank: 0,
			ListenerGenerations: []ListenerGenerationV2{listener}, ListenerTombstones: []ListenerGenerationTombstoneV1{},
		}},
		ParentHeadHash: head.HeadHash, ConfigQC: qcRaw,
	}
	ingressHash, err := BootstrapIngressSetHash(&ingressSet)
	if err != nil {
		t.Fatal(err)
	}
	qcCanonical, _ := CanonicalizeStrict(qcRaw)
	qcHash, _ := HashCanonical(DomainQuorumCertificate, qcCanonical)
	catalog := &BootstrapEndpointCatalogV1{
		Schema: 1, ClusterID: set.ClusterID, CatalogGeneration: 1,
		ValidFrom: "2026-09-11T00:00:00Z", ValidUntil: "2026-09-12T00:00:00Z",
		BootstrapIngressSet: ingressSet, BootstrapIngressSetHash: ingressHash,
		RequiredClientProtocol: 2, ParentHeadHash: head.HeadHash, ConfigQCHash: qcHash,
	}
	return catalog, set, &head
}

func TestBootstrapCatalogBindsSetHeadAndQC(t *testing.T) {
	catalog, set, head := testBootstrapCatalog(t)
	if err := ValidateBootstrapEndpointCatalogAt(catalog, time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC), 2); err != nil {
		t.Fatal(err)
	}
	if err := VerifyConfigQCAuthority(catalog.ParentHeadHash, catalog.BootstrapIngressSet.ConfigQC, head, set, nil); err != nil {
		t.Fatal(err)
	}
	catalog.ConfigQCHash = HashRaw("wrong-qc-v1", []byte("wrong"))
	if err := ValidateBootstrapEndpointCatalog(catalog); err == nil {
		t.Fatal("accepted a catalog with substituted QC hash")
	}
}

func TestBootstrapIssuerProofAndCapabilityLimits(t *testing.T) {
	policy := testInvitePolicy()
	policyHash, _ := InviteIssuancePolicyHash(&policy)
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-1] = 44
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, _ := ControlKeyID(publicKey)
	ingressHash := HashRaw("test-ingress-v1", []byte("ingress"))
	authorization := BootstrapIssuerAuthorizationV1{
		Schema: 1, ClusterID: policy.ClusterID, AuthorizationID: "bootstrap-issuer-1", Generation: 1, Status: "active",
		Active: &BootstrapIssuerAuthorizationActiveV1{
			IssuerEpoch: 1, IssuerKeyID: keyID, IssuerPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
			InviteIssuancePolicyHash: policyHash, ValidFrom: "2026-09-11T00:00:00Z", ValidUntil: "2026-09-12T00:00:00Z",
			MaximumCapabilityTTLSeconds: 900, MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1,
			MaximumSessionSeconds: 180, MaximumTotalBytes: 8 << 20,
			PermittedIngressSetHashes: []string{ingressHash}, PermittedServiceIDs: []string{"enrollment-service-1"},
			PermittedModes: []string{"initial_claim", "resume_committed_claim"},
		},
		ParentHeadHash: HashRaw("test-head-v1", []byte("head")),
	}
	authorizationHash, err := BootstrapIssuerAuthorizationHash(&authorization)
	if err != nil {
		t.Fatal(err)
	}
	leaf := BootstrapIssuerAuthorizationLeafV1{Schema: 1, AuthorizationID: authorization.AuthorizationID, Generation: 1, AuthorizationHash: authorizationHash}
	canonicalLeaf, _ := MarshalCanonical(leaf)
	root := "sha256:" + hex.EncodeToString(MerkleRoot([][]byte{canonicalLeaf}))
	proof := &BootstrapIssuerAuthorizationProofV1{
		Schema: 1, ClusterID: policy.ClusterID, Authorization: authorization, AuthorizationHash: authorizationHash,
		Leaf: leaf, LeafIndex: 0, RegistryTreeSize: 1, RegistryAuditPath: []string{}, RegistryRoot: root,
	}
	body := BootstrapTunnelCapabilityBodyV1{
		Schema: 1, ClusterID: policy.ClusterID, InviteID: "invite-1",
		CommittedInviteRecordHash: HashRaw("test-record-v1", []byte("record")), InviteIssuancePolicyHash: policyHash,
		BootstrapIssuerAuthorizationHash: authorizationHash, BootstrapIssuerRegistryRoot: root,
		EnrollmentServiceRefHash: HashRaw("test-service-ref-v1", []byte("service")), Mode: "initial_claim",
		IssuedAt: "2026-09-11T11:00:00Z", NotBefore: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:15:00Z",
		AllowedIngressSetHash: ingressHash, AllowedServiceID: "enrollment-service-1", AllowedDestinationIP: "10.30.0.1",
		AllowedDestinationPrefixLength: 32, AllowedDestinationPort: 7444, AllowedInsideTransport: "tcp",
		MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1, MaximumSessionSeconds: 180,
		MaximumTotalBytes: 8 << 20, IssuerEpoch: 1, IssuerKeyID: keyID,
	}
	capabilityID, _ := CapabilityID(&body)
	canonicalBody, _ := MarshalCanonical(body)
	message, _ := Frame(DomainBootstrapCapabilitySignature, canonicalBody)
	capability := &BootstrapTunnelCapabilityV1{
		Body: body, CapabilityID: capabilityID,
		Signature: BootstrapIssuerSignatureV1{Algorithm: "ed25519", KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))},
	}
	trustedTime := time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC)
	if err := VerifyCapabilityAuthorization(capability, proof, &policy, trustedTime); err != nil {
		t.Fatal(err)
	}
	capability.Body.MaximumTotalBytes++
	if err := VerifyCapabilityAuthorization(capability, proof, &policy, trustedTime); err == nil {
		t.Fatal("accepted a modified/over-limit capability")
	}
}

func TestCertifiedInviteUsesPolicyTTL(t *testing.T) {
	policy := testInvitePolicy()
	policyHash, _ := InviteIssuancePolicyHash(&policy)
	hash := func(value string) string { return HashRaw("test-invite-record-v1", []byte(value)) }
	record := &CertifiedInviteRecordV2{
		Schema: 2, ClusterID: policy.ClusterID, InviteID: "invite-1", Generation: 1,
		IssuedAt: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:20:00Z",
		DeviceEnrollmentIntentCommitmentHash: hash("intent"), TokenCommitment: hash("token"),
		TokenArtifactBindingHash: hash("token-artifact"), InviteIssuancePolicyHash: policyHash,
		BootstrapIssuerAuthorizationHash: hash("authorization"), BootstrapIssuerRegistryRoot: hash("registry"),
		BootstrapCatalogHash: hash("catalog"), EnrollmentServiceRefHash: hash("service"),
		OperationID: "operation-1", ParentHeadHash: hash("head"),
	}
	if _, err := CertifiedInviteRecordHash(record, &policy); err != nil {
		t.Fatal(err)
	}
	record.ExpiresAt = "2026-09-11T12:00:01Z"
	if err := ValidateCertifiedInviteRecord(record, &policy); err == nil {
		t.Fatal("accepted Invite TTL above the policy hard bound")
	}
}
