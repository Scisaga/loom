package bootstrapaccess

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func verifiedCapability(t *testing.T, now time.Time) (wire.VerifiedBootstrapCapabilityV1, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-1] = 9
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, _ := wire.ControlKeyID(publicKey)
	policy := wire.InviteIssuancePolicyV2{
		Schema: 2, ClusterID: "demo-cluster", PolicyID: "invite-policy", Generation: 1,
		MinimumTTLSeconds: 300, MaximumTTLSeconds: 1800, MaximumDescriptorBytes: 65536,
		MaximumIntentOpeningBytes: 65536, MinimumDistributionMirrors: 2, MaximumDistributionMirrors: 3,
		AllowedBootstrapTransports: []string{"hysteria2", "trojan_tls"}, MaximumInitialCapabilityTTLSeconds: 900,
		MaximumResumeCapabilityTTLSeconds: 900, MaximumReservationRetrySeconds: 1800,
		BootstrapSessionSeconds: 180, BootstrapTotalBytes: 10, BootstrapConnectionAttempts: 2,
		BootstrapMaxConcurrentSessions: 1,
	}
	policyHash, err := wire.InviteIssuancePolicyHash(&policy)
	if err != nil {
		t.Fatal(err)
	}
	ingressHash := wire.HashRaw("test-bootstrap-ingress-v1", []byte("ingress"))
	authorization := wire.BootstrapIssuerAuthorizationV1{
		Schema: 1, ClusterID: policy.ClusterID, AuthorizationID: "issuer-1", Generation: 1, Status: "active",
		Active: &wire.BootstrapIssuerAuthorizationActiveV1{
			IssuerEpoch: 1, IssuerKeyID: keyID, IssuerPublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
			InviteIssuancePolicyHash: policyHash, ValidFrom: "2026-09-11T00:00:00Z", ValidUntil: "2026-09-12T00:00:00Z",
			MaximumCapabilityTTLSeconds: 900, MaximumConnectionAttempts: 2, MaximumConcurrentSessions: 1,
			MaximumSessionSeconds: 180, MaximumTotalBytes: 10, PermittedIngressSetHashes: []string{ingressHash},
			PermittedServiceIDs: []string{"enrollment-service"}, PermittedModes: []string{"initial_claim"},
		},
		ParentHeadHash: wire.HashRaw("test-bootstrap-head-v1", []byte("head")),
	}
	authorizationHash, err := wire.BootstrapIssuerAuthorizationHash(&authorization)
	if err != nil {
		t.Fatal(err)
	}
	leaf := wire.BootstrapIssuerAuthorizationLeafV1{Schema: 1, AuthorizationID: authorization.AuthorizationID, Generation: 1, AuthorizationHash: authorizationHash}
	leafBytes, _ := wire.MarshalCanonical(leaf)
	root := "sha256:" + hex.EncodeToString(wire.MerkleRoot([][]byte{leafBytes}))
	proof := wire.BootstrapIssuerAuthorizationProofV1{
		Schema: 1, ClusterID: policy.ClusterID, Authorization: authorization, AuthorizationHash: authorizationHash,
		Leaf: leaf, LeafIndex: 0, RegistryTreeSize: 1, RegistryAuditPath: []string{}, RegistryRoot: root,
	}
	body := wire.BootstrapTunnelCapabilityBodyV1{
		Schema: 1, ClusterID: policy.ClusterID, InviteID: "invite-1",
		CommittedInviteRecordHash: wire.HashRaw("test-invite-record-v1", []byte("invite")),
		InviteIssuancePolicyHash:  policyHash, BootstrapIssuerAuthorizationHash: authorizationHash,
		BootstrapIssuerRegistryRoot: root, EnrollmentServiceRefHash: wire.HashRaw("test-service-ref-v1", []byte("service")),
		Mode: "initial_claim", IssuedAt: "2026-09-11T11:00:00Z", NotBefore: "2026-09-11T11:00:00Z",
		ExpiresAt: "2026-09-11T11:10:00Z", AllowedIngressSetHash: ingressHash,
		AllowedServiceID: "enrollment-service", AllowedDestinationIP: "10.30.0.1", AllowedDestinationPrefixLength: 32,
		AllowedDestinationPort: 7444, AllowedInsideTransport: "tcp", MaximumConnectionAttempts: 2,
		MaximumConcurrentSessions: 1, MaximumSessionSeconds: 180, MaximumTotalBytes: 10,
		IssuerEpoch: 1, IssuerKeyID: keyID,
	}
	capability, err := wire.SignBootstrapCapability(body, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := wire.VerifyCapabilityAuthorizationEvidence(&capability, &proof, &policy, now)
	if err != nil {
		t.Fatal(err)
	}
	return verified, ingressHash
}

func TestCapabilityRuntimeEnforcesExactTupleConcurrencyAndDurableBudgets(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	now := func() time.Time { return instant }
	verified, ingressHash := verifiedCapability(t, instant)
	path := filepath.Join(t.TempDir(), "usage.json")
	manager, err := Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.OpenSession(verified, "session-1", ingressHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.AuthorizeDial("tcp4", "10.30.0.1:7444"); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"10.30.0.1:22", "10.30.0.2:7444", "example.test:7444"} {
		if err := first.AuthorizeDial("tcp", target); err == nil {
			t.Fatalf("越权 destination %q 被允许", target)
		}
	}
	if _, err := manager.OpenSession(verified, "session-2", ingressHash); err == nil {
		t.Fatal("同 capability 并发打开第二 session")
	}
	if err := first.AddTransferredBytes(8); err != nil {
		t.Fatal(err)
	}
	if err := first.AddTransferredBytes(3); err == nil {
		t.Fatal("超过 total byte budget 后仍允许传输")
	}
	first.Close()

	reopened, err := Open(path, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.OpenSession(verified, "session-2", ingressHash)
	if err != nil {
		t.Fatal(err)
	}
	second.Close()
	if _, err := reopened.OpenSession(verified, "session-3", ingressHash); err == nil {
		t.Fatal("重启后恢复了 connection attempt budget")
	}
	usage := reopened.SnapshotUsage()
	if len(usage) != 1 || usage[0].ConnectionAttempts != 2 || usage[0].TransferredBytes != 8 {
		t.Fatalf("durable capability accounting 错误: %#v", usage)
	}
}

func TestCapabilityRuntimeRejectsWrongIngressAndExpiry(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	current := instant
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.OpenSession(verified, "session-1", wire.HashRaw("test-bootstrap-ingress-v1", []byte("other"))); err == nil {
		t.Fatal("错误 ingress set 被允许")
	}
	current = time.Date(2026, 9, 11, 11, 10, 0, 0, time.UTC)
	if _, err := manager.OpenSession(verified, "session-2", ingressHash); err == nil {
		t.Fatal("exclusive expiry 时仍允许 capability")
	}
}
