//go:build linux

package clientv2

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestLinuxEnrollmentIdentityIsDurableDistinctAndProducesP256PoP(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "identity.json")
	identity, err := OpenOrCreateEnrollmentIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	firstBody, _ := os.ReadFile(path)
	reopened, err := OpenOrCreateEnrollmentIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	secondBody, _ := os.ReadFile(path)
	if string(firstBody) != string(secondBody) || identity.IdentityPublicKeySPKI != reopened.IdentityPublicKeySPKI {
		t.Fatal("reopening identity generated new key material")
	}
	if identity.IdentityPublicKeySPKI == identity.WrappingPublicKeySPKI {
		t.Fatal("identity and wrapping key were reused")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode=%o", info.Mode().Perm())
	}
	hash := func(value string) string { return wire.HashRaw("linux-identity-test-v1", []byte(value)) }
	core, coreHash, err := identity.PrepareClaimCore(ClaimCoreInputV2{
		ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: hash("record"), DeviceEnrollmentIntentCommitmentHash: hash("commitment"),
		DeviceEnrollmentIntentOpeningHash: hash("opening"), AcceptedDeviceEnrollmentIntentHash: hash("intent"),
		BaseRecoveryEpoch: 1, BaseControlEpoch: 2, BaseControlSetHash: hash("set"), BaseHeadHash: hash("head"),
		ClientNonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil || coreHash == "" {
		t.Fatalf("core hash=%q err=%v", coreHash, err)
	}
	pop := &wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
		ClaimCoreHash: coreHash, TokenCommitment: hash("token"), ChallengeHash: hash("challenge"),
	}
	signature, err := identity.SignPoP(pop)
	if err != nil || signature == "" {
		t.Fatalf("signature=%q err=%v", signature, err)
	}
	identityKey, _, _ := identity.keys()
	if err := wire.VerifyEnrollmentPoPP256(pop, &identityKey.PublicKey, signature); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxEnrollmentIdentityRejectsLoosePermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "identity.json")
	if _, err := OpenOrCreateEnrollmentIdentity(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOrCreateEnrollmentIdentity(path); err == nil {
		t.Fatal("accepted group-readable identity private keys")
	}
}

func TestLinuxEnrollmentIdentityRejectsLooseDirectoryAndSymlinkLock(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "identity.json")
	if _, err := OpenOrCreateEnrollmentIdentity(path); err == nil {
		t.Fatal("接受了 group/world 可遍历的 identity directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOrCreateEnrollmentIdentity(path); err == nil {
		t.Fatal("接受了 symlink identity lock")
	}
}

func TestLinuxPendingClaimReusesExactCoreAcrossRetries(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := OpenOrCreateEnrollmentIdentity(filepath.Join(directory, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash := func(value string) string { return wire.HashRaw("linux-pending-test-v1", []byte(value)) }
	input := ClaimCoreInputV2{
		ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		CertifiedInviteRecordHash: hash("record"), DeviceEnrollmentIntentCommitmentHash: hash("commitment"),
		DeviceEnrollmentIntentOpeningHash: hash("opening"), AcceptedDeviceEnrollmentIntentHash: hash("intent"),
		BaseRecoveryEpoch: 1, BaseControlEpoch: 2, BaseControlSetHash: hash("set"), BaseHeadHash: hash("head"),
	}
	path := filepath.Join(directory, "pending.json")
	first, err := OpenOrCreatePendingClaim(path, identity, input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenOrCreatePendingClaim(path, identity, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ClaimCoreHash != second.ClaimCoreHash || first.ClaimCore.CSRDER != second.ClaimCore.CSRDER || first.ClaimCore.ClientNonce != second.ClaimCore.ClientNonce {
		t.Fatal("retry changed stable claim core/CSR/client nonce")
	}
	input.BaseHeadHash = hash("different-head")
	if _, err := OpenOrCreatePendingClaim(path, identity, input); err == nil {
		t.Fatal("reused pending claim against a different authority head")
	}
}
