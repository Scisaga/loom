//go:build linux

package clientv2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"loom/internal/wire"
)

const LinuxSoftwareKeyProtectionProfile = "linux-root-only-pkcs8-v1"

// EnrollmentIdentityV1 把 Linux 无硬件 keystore 时的降级显式写入受保护状态，绝不伪装成不可导出 key。
type EnrollmentIdentityV1 struct {
	Schema                  int    `json:"schema"`
	ProtectionProfile       string `json:"protection_profile"`
	IdentityPrivateKeyPKCS8 string `json:"identity_private_key_pkcs8"`
	IdentityPublicKeySPKI   string `json:"identity_public_key_spki"`
	WrappingPrivateKeyPKCS8 string `json:"wrapping_private_key_pkcs8"`
	WrappingPublicKeySPKI   string `json:"wrapping_public_key_spki"`
}

type ClaimCoreInputV2 struct {
	ClusterID                            string
	InviteID                             string
	RequestID                            string
	CertifiedInviteRecordHash            string
	DeviceEnrollmentIntentCommitmentHash string
	DeviceEnrollmentIntentOpeningHash    string
	AcceptedDeviceEnrollmentIntentHash   string
	BaseRecoveryEpoch                    int64
	BaseControlEpoch                     int64
	BaseControlSetHash                   string
	BaseHeadHash                         string
	ClientNonce                          string
}

func OpenOrCreateEnrollmentIdentity(path string) (*EnrollmentIdentityV1, error) {
	if path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return nil, errors.New("[D129 Linux] identity path 必须是规范绝对路径")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if state, err := loadEnrollmentIdentity(path); err == nil {
		return state, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	identityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	wrappingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	identityPKCS8, _ := x509.MarshalPKCS8PrivateKey(identityKey)
	wrappingPKCS8, _ := x509.MarshalPKCS8PrivateKey(wrappingKey)
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	state := &EnrollmentIdentityV1{
		Schema: 1, ProtectionProfile: LinuxSoftwareKeyProtectionProfile,
		IdentityPrivateKeyPKCS8: base64.RawURLEncoding.EncodeToString(identityPKCS8),
		IdentityPublicKeySPKI:   base64.RawURLEncoding.EncodeToString(identitySPKI),
		WrappingPrivateKeyPKCS8: base64.RawURLEncoding.EncodeToString(wrappingPKCS8),
		WrappingPublicKeySPKI:   base64.RawURLEncoding.EncodeToString(wrappingSPKI),
	}
	if err := persistEnrollmentIdentity(path, state); err != nil {
		return nil, err
	}
	return loadEnrollmentIdentity(path)
}

// LoadEnrollmentIdentityForResume 只读取既有 key，不会在恢复路径生成替代 identity。
// 缺失或损坏必须失败关闭，否则 descriptor 可能被错误地绑定到新设备（D129、D130）。
func LoadEnrollmentIdentityForResume(path string) (*EnrollmentIdentityV1, error) {
	if path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return nil, errors.New("[D130 Linux resume] identity path 必须是规范绝对路径")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_SH); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return loadEnrollmentIdentity(path)
}

func (state *EnrollmentIdentityV1) PrepareClaimCore(input ClaimCoreInputV2) (wire.EnrollmentClaimCoreV2, string, error) {
	identityKey, wrappingKey, err := state.keys()
	if err != nil {
		return wire.EnrollmentClaimCoreV2{}, "", err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: input.RequestID}}, identityKey)
	if err != nil {
		return wire.EnrollmentClaimCoreV2{}, "", err
	}
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	core := wire.EnrollmentClaimCoreV2{
		Schema: 2, ClusterID: input.ClusterID, InviteID: input.InviteID, RequestID: input.RequestID,
		CertifiedInviteRecordHash:            input.CertifiedInviteRecordHash,
		DeviceEnrollmentIntentCommitmentHash: input.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    input.DeviceEnrollmentIntentOpeningHash,
		AcceptedDeviceEnrollmentIntentHash:   input.AcceptedDeviceEnrollmentIntentHash,
		ClientPlatform:                       "linux-server", BaseRecoveryEpoch: input.BaseRecoveryEpoch,
		BaseControlEpoch: input.BaseControlEpoch, BaseControlSetHash: input.BaseControlSetHash, BaseHeadHash: input.BaseHeadHash,
		DeviceIdentityPublicKey: base64.RawURLEncoding.EncodeToString(identitySPKI), DeviceIdentityKeyProfile: "p256-root-only-pkcs8-sha256-v1",
		WrappingPublicKey: base64.RawURLEncoding.EncodeToString(wrappingSPKI), WrappingKeyProfile: "p256-root-only-pkcs8-ecdh-v1",
		CSRDER: base64.RawURLEncoding.EncodeToString(csrDER), ClientNonce: input.ClientNonce,
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(&core)
	return core, coreHash, err
}

func (state *EnrollmentIdentityV1) SignPoP(body *wire.EnrollmentPoPBodyV2) (string, error) {
	identityKey, _, err := state.keys()
	if err != nil {
		return "", err
	}
	return wire.SignEnrollmentPoPP256(body, identityKey)
}

func (state *EnrollmentIdentityV1) IdentitySPKIHash() (string, error) {
	identityKey, _, err := state.keys()
	if err != nil {
		return "", err
	}
	spki, _ := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	digest := sha256.Sum256(spki)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func loadEnrollmentIdentity(path string) (*EnrollmentIdentityV1, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 64<<10 {
		return nil, errors.New("[D129 Linux] identity state 必须是 0600 小型普通文件")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("[D129 Linux] identity state owner 不是当前服务账号")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state EnrollmentIdentityV1
	canonical, err := wire.DecodeStrict(body, 64<<10, &state)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[D129 Linux] identity state 必须是 exact canonical wire")
	}
	if _, _, err := state.keys(); err != nil {
		return nil, err
	}
	return &state, nil
}

func (state *EnrollmentIdentityV1) keys() (*ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	if state == nil || state.Schema != 1 || state.ProtectionProfile != LinuxSoftwareKeyProtectionProfile {
		return nil, nil, errors.New("[D129 Linux] identity protection profile 无效")
	}
	identityKey, identitySPKI, err := decodeP256Key(state.IdentityPrivateKeyPKCS8, state.IdentityPublicKeySPKI)
	if err != nil {
		return nil, nil, fmt.Errorf("[D129 Linux] identity key: %w", err)
	}
	wrappingKey, wrappingSPKI, err := decodeP256Key(state.WrappingPrivateKeyPKCS8, state.WrappingPublicKeySPKI)
	if err != nil {
		return nil, nil, fmt.Errorf("[D130 Linux] wrapping key: %w", err)
	}
	if bytes.Equal(identitySPKI, wrappingSPKI) {
		return nil, nil, errors.New("[D130 Linux] identity 与 wrapping key 禁止复用")
	}
	return identityKey, wrappingKey, nil
}

func decodeP256Key(encodedPrivate, encodedPublic string) (*ecdsa.PrivateKey, []byte, error) {
	privateDER, err := base64.RawURLEncoding.DecodeString(encodedPrivate)
	if err != nil || base64.RawURLEncoding.EncodeToString(privateDER) != encodedPrivate {
		return nil, nil, errors.New("private key PKCS8 编码无效")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || privateKey.Curve != elliptic.P256() {
		return nil, nil, errors.New("private key 必须是 P-256 PKCS8")
	}
	publicDER, err := base64.RawURLEncoding.DecodeString(encodedPublic)
	if err != nil || base64.RawURLEncoding.EncodeToString(publicDER) != encodedPublic {
		return nil, nil, errors.New("public key SPKI 编码无效")
	}
	wantPublic, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if !bytes.Equal(wantPublic, publicDER) {
		return nil, nil, errors.New("private/public key 不匹配")
	}
	return privateKey, publicDER, nil
}

func persistEnrollmentIdentity(path string, state *EnrollmentIdentityV1) error {
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".identity-v2-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	_, err = temporary.Write(body)
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}
