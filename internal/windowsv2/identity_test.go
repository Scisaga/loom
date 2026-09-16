package windowsv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

type testProtector struct{}

func (testProtector) Protect(purpose string, plaintext []byte) ([]byte, error) {
	body := append([]byte(purpose+"\x00"), plaintext...)
	for index := len(purpose) + 1; index < len(body); index++ {
		body[index] ^= 0xa7
	}
	return body, nil
}

func (testProtector) Unprotect(purpose string, ciphertext []byte) ([]byte, error) {
	prefix := []byte(purpose + "\x00")
	if !bytes.HasPrefix(ciphertext, prefix) {
		return nil, errors.New("purpose mismatch")
	}
	body := append([]byte(nil), ciphertext[len(prefix):]...)
	for index := range body {
		body[index] ^= 0xa7
	}
	return body, nil
}

func TestProtectedIdentityRoundTripAndSignerBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json.dpapi")
	identity, err := OpenOrCreateIdentity(path, testProtector{}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	t.Cleanup(func() {
		if err := DestroyIdentity(path, testProtector{}); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("清理测试 identity: %v", err)
		}
	})
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		t.Fatal(err)
	}
	wrappingHash, err := identity.WrappingSPKIHash()
	if err != nil || identityHash == wrappingHash {
		t.Fatalf("identity/wrapping separation: identity=%s wrapping=%s err=%v", identityHash, wrappingHash, err)
	}
	core, coreHash, err := identity.PrepareClaimCore(ClaimCoreInput{
		ClusterID: "demo-cluster", InviteID: "demo-invite", RequestID: "demo-request",
		CertifiedInviteRecordHash: wire.EmptyHashV1, DeviceEnrollmentIntentCommitmentHash: wire.EmptyHashV1,
		DeviceEnrollmentIntentOpeningHash: wire.EmptyHashV1, AcceptedDeviceEnrollmentIntentHash: wire.EmptyHashV1,
		BaseControlSetHash: wire.EmptyHashV1, BaseHeadHash: wire.EmptyHashV1,
		ClientNonce: bytes.Repeat([]byte{0x31}, 32), WrappingProfile: WrappingKeyProfile,
	}, rand.Reader)
	if err != nil || coreHash == "" || core.ClientPlatform != "windows-desktop" {
		t.Fatalf("prepare Windows core: hash=%s core=%+v err=%v", coreHash, core, err)
	}
	pop := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
		ClaimCoreHash: coreHash, TokenCommitment: wire.EmptyHashV1, ChallengeHash: wire.EmptyHashV1,
	}
	signature, err := identity.SignEnrollmentPoP(&pop)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := identity.Signer().Public().(*ecdsa.PublicKey)
	if !ok || wire.VerifyEnrollmentPoPP256(&pop, public, signature) != nil {
		t.Fatal("DPAPI 宿主 signer 的 PoP 未通过共享 verifier")
	}
	if _, err := identity.Signer().Sign(rand.Reader, make([]byte, 32), crypto.SHA512); err == nil {
		t.Fatal("identity signer 接受了非 SHA-256 请求")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, identity.IdentitySPKIDER()) || bytes.Contains(onDisk, identity.WrappingSPKIDER()) {
		t.Fatal("protected identity 文件泄露了 public/private state plaintext")
	}

	reloaded, err := LoadIdentity(path, testProtector{})
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if wire.VerifyEnrollmentLocalWireGuardKey(&core, reloaded.wireGuard) != nil {
		t.Fatal("DPAPI 重载改变了本机 WireGuard key")
	}
	corrupt := append([]byte{}, reloaded.wireGuard...)
	corrupt[8] ^= 0x20
	if wire.VerifyEnrollmentLocalWireGuardKey(&core, corrupt) == nil {
		t.Fatal("本机 WireGuard key 替换未被拒绝")
	}
	clear(corrupt)
	reloadedIdentityHash, _ := reloaded.IdentitySPKIHash()
	reloadedWrappingHash, _ := reloaded.WrappingSPKIHash()
	if reloadedIdentityHash != identityHash || reloadedWrappingHash != wrappingHash {
		t.Fatal("protected identity reload 改变了 stable keys")
	}
}

type wrongCurveSigner struct{ key *ecdsa.PrivateKey }

func (signer wrongCurveSigner) Public() crypto.PublicKey { return &signer.key.PublicKey }
func (signer wrongCurveSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("should not sign")
}

func TestSharedSignerRejectsNonP256HostKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "demo-invite", RequestID: "demo-request",
		ClaimCoreHash: wire.EmptyHashV1, TokenCommitment: wire.EmptyHashV1, ChallengeHash: wire.EmptyHashV1,
	}
	if _, err := wire.SignEnrollmentPoPWithSigner(&body, wrongCurveSigner{key: key}); err == nil {
		t.Fatal("共享 signer 边界接受了非 P-256 host key")
	}
}
