// Package windowsv2 实现 Windows 原生宿主的 v2 私钥与耐久状态边界。
// 协议对象、QC、Merkle 与 floor 仍统一由 internal/wire 验证。
package windowsv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"loom/internal/clientsecret"
	"loom/internal/wire"
)

const (
	IdentityPurpose           = "windows-v2-identity-v1"
	IdentityProtectionProfile = "windows-dpapi-cng-p256-v1"
	IdentityKeyProfile        = "p256-sha256-v1"
	WrappingKeyProfile        = "p256-keystore-ecdh-v1"
	maximumIdentityState      = 128 << 10
)

type protectedIdentityV1 struct {
	Schema                  int    `json:"schema"`
	Platform                string `json:"platform"`
	ProtectionProfile       string `json:"protection_profile"`
	IdentityProvider        string `json:"identity_provider"`
	IdentityKeyName         string `json:"identity_key_name,omitempty"`
	IdentityMachineScope    bool   `json:"identity_machine_scope,omitempty"`
	IdentityPrivateKeyPKCS8 string `json:"identity_private_key_pkcs8,omitempty"`
	IdentityPublicKeySPKI   string `json:"identity_public_key_spki"`
	WrappingPrivateKeyPKCS8 string `json:"wrapping_private_key_pkcs8"`
	WrappingPublicKeySPKI   string `json:"wrapping_public_key_spki"`
}

type platformIdentityRecord struct {
	Provider        string
	KeyName         string
	MachineScope    bool
	PrivateKeyPKCS8 string
}

// Identity 对外只暴露 public material、受限 crypto.Signer 与解封操作。
// 调用者无法取得 DPAPI 解密后的 identity/wrapping private DER（D129、D130）。
type Identity struct {
	identity     crypto.Signer
	wrapping     *ecdsa.PrivateKey
	identitySPKI []byte
	wrappingSPKI []byte
}

// OpenOrCreateIdentity 必须在宿主的 profile join mutex 内调用。DPAPI purpose
// 与文件原子替换共同保证不同 profile/用途的 ciphertext 不能互换。
func OpenOrCreateIdentity(path string, protector clientsecret.Protector, random io.Reader) (*Identity, error) {
	if err := validateProtectedPath(path); err != nil || protector == nil {
		return nil, errors.New("[D129 Windows] identity path/protector 无效")
	}
	identity, err := LoadIdentity(path, protector)
	if err == nil {
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	wrappingKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, err
	}
	defer zeroPrivateKey(wrappingKey)
	identitySigner, identitySPKI, identityRecord, err := createPlatformIdentity(protector, random)
	if err != nil {
		return nil, err
	}
	defer closePlatformSigner(identitySigner)
	committed := false
	defer func() {
		if !committed {
			_ = destroyPlatformIdentity(identityRecord)
		}
	}()
	wrappingPKCS8, err := x509.MarshalPKCS8PrivateKey(wrappingKey)
	if err != nil {
		return nil, err
	}
	defer clear(wrappingPKCS8)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	state := protectedIdentityV1{
		Schema: 1, Platform: "windows-desktop", ProtectionProfile: IdentityProtectionProfile,
		IdentityProvider:        identityRecord.Provider,
		IdentityKeyName:         identityRecord.KeyName,
		IdentityMachineScope:    identityRecord.MachineScope,
		IdentityPrivateKeyPKCS8: identityRecord.PrivateKeyPKCS8,
		IdentityPublicKeySPKI:   base64.RawURLEncoding.EncodeToString(identitySPKI),
		WrappingPrivateKeyPKCS8: base64.RawURLEncoding.EncodeToString(wrappingPKCS8),
		WrappingPublicKeySPKI:   base64.RawURLEncoding.EncodeToString(wrappingSPKI),
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if err := clientsecret.WriteProtected(path, IdentityPurpose, body, protector); err != nil {
		return nil, err
	}
	committed = true
	loaded, err := LoadIdentity(path, protector)
	if err != nil {
		_ = destroyPlatformIdentity(identityRecord)
		_ = os.Remove(path)
		return nil, err
	}
	return loaded, nil
}

// LoadIdentity 只恢复既有 identity；resume 路径绝不能在损坏/缺失时生成替代 key。
func LoadIdentity(path string, protector clientsecret.Protector) (*Identity, error) {
	if err := validateProtectedPath(path); err != nil || protector == nil {
		return nil, errors.New("[D130 Windows resume] identity path/protector 无效")
	}
	body, err := clientsecret.ReadProtected(path, IdentityPurpose, protector)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if len(body) > maximumIdentityState {
		return nil, errors.New("[D129 Windows] identity state 超过大小边界")
	}
	var state protectedIdentityV1
	canonical, err := wire.DecodeStrict(body, maximumIdentityState, &state)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[D129 Windows] identity state 不是 exact canonical wire")
	}
	return decodeProtectedIdentity(state, protector)
}

func decodeProtectedIdentity(state protectedIdentityV1,
	protector clientsecret.Protector) (*Identity, error) {
	if state.Schema != 1 || state.Platform != "windows-desktop" ||
		state.ProtectionProfile != IdentityProtectionProfile {
		return nil, errors.New("[D129 Windows] identity protection profile 无效")
	}
	identitySigner, identitySPKI, err := loadPlatformIdentity(state, protector)
	if err != nil {
		return nil, fmt.Errorf("[D129 Windows] identity key: %w", err)
	}
	wrappingKey, wrappingSPKI, err := decodeP256Private(state.WrappingPrivateKeyPKCS8,
		state.WrappingPublicKeySPKI)
	if err != nil {
		closePlatformSigner(identitySigner)
		return nil, fmt.Errorf("[D130 Windows] wrapping key: %w", err)
	}
	if bytes.Equal(identitySPKI, wrappingSPKI) {
		closePlatformSigner(identitySigner)
		zeroPrivateKey(wrappingKey)
		return nil, errors.New("[D130 Windows] identity 与 wrapping key 禁止复用")
	}
	return &Identity{identity: identitySigner, wrapping: wrappingKey,
		identitySPKI: identitySPKI, wrappingSPKI: wrappingSPKI}, nil
}

func decodeP256Private(encodedPrivate, encodedPublic string) (*ecdsa.PrivateKey, []byte, error) {
	privateDER, err := decodeCanonicalBase64URL(encodedPrivate, 16<<10)
	if err != nil {
		return nil, nil, errors.New("private key PKCS8 编码无效")
	}
	defer clear(privateDER)
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() ||
		!key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, nil, errors.New("private key 必须是 P-256 PKCS8")
	}
	publicDER, err := decodeCanonicalBase64URL(encodedPublic, 16<<10)
	if err != nil {
		zeroPrivateKey(key)
		return nil, nil, errors.New("public key SPKI 编码无效")
	}
	wanted, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(wanted, publicDER) {
		zeroPrivateKey(key)
		clear(publicDER)
		return nil, nil, errors.New("private/public key 不匹配")
	}
	return key, publicDER, nil
}

func decodeCanonicalBase64URL(encoded string, maximum int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, errors.New("非规范 base64url")
	}
	return decoded, nil
}

// ClaimCoreInput 是已验 Invite proof 与 token-free preflight 的稳定投影。
type ClaimCoreInput struct {
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
	ClientNonce                          []byte
	WrappingProfile                      string
}

func (identity *Identity) PrepareClaimCore(input ClaimCoreInput, random io.Reader) (wire.EnrollmentClaimCoreV2, string, error) {
	if identity == nil || identity.identity == nil || identity.wrapping == nil || len(input.ClientNonce) != 32 {
		return wire.EnrollmentClaimCoreV2{}, "", errors.New("[D129 Windows] identity/core nonce 输入无效")
	}
	if random == nil {
		random = rand.Reader
	}
	profile := input.WrappingProfile
	if profile == "" {
		profile = WrappingKeyProfile
	}
	csrDER, err := x509.CreateCertificateRequest(random,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: input.RequestID}}, identity.Signer())
	if err != nil {
		return wire.EnrollmentClaimCoreV2{}, "", err
	}
	core := wire.EnrollmentClaimCoreV2{
		Schema: 2, ClusterID: input.ClusterID, InviteID: input.InviteID, RequestID: input.RequestID,
		CertifiedInviteRecordHash:            input.CertifiedInviteRecordHash,
		DeviceEnrollmentIntentCommitmentHash: input.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    input.DeviceEnrollmentIntentOpeningHash,
		AcceptedDeviceEnrollmentIntentHash:   input.AcceptedDeviceEnrollmentIntentHash,
		ClientPlatform:                       "windows-desktop", BaseRecoveryEpoch: input.BaseRecoveryEpoch,
		BaseControlEpoch: input.BaseControlEpoch, BaseControlSetHash: input.BaseControlSetHash,
		BaseHeadHash:             input.BaseHeadHash,
		DeviceIdentityPublicKey:  base64.RawURLEncoding.EncodeToString(identity.identitySPKI),
		DeviceIdentityKeyProfile: IdentityKeyProfile,
		WrappingPublicKey:        base64.RawURLEncoding.EncodeToString(identity.wrappingSPKI),
		WrappingKeyProfile:       profile, CSRDER: base64.RawURLEncoding.EncodeToString(csrDER),
		ClientNonce: base64.RawURLEncoding.EncodeToString(input.ClientNonce),
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(&core)
	return core, coreHash, err
}

func (identity *Identity) Signer() crypto.Signer {
	if identity == nil || identity.identity == nil {
		return nil
	}
	return identity.identity
}

type restrictedP256Signer struct{ key *ecdsa.PrivateKey }

func (signer *restrictedP256Signer) Public() crypto.PublicKey {
	if signer == nil || signer.key == nil {
		return nil
	}
	copy := signer.key.PublicKey
	return &copy
}

func (signer *restrictedP256Signer) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	if signer == nil || signer.key == nil || options == nil || options.HashFunc() != crypto.SHA256 ||
		len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("[D129 Windows signer] 只允许 P-256 SHA-256 digest")
	}
	if random == nil {
		random = rand.Reader
	}
	return signer.key.Sign(random, digest, options)
}

func (signer *restrictedP256Signer) Close() error {
	if signer != nil {
		zeroPrivateKey(signer.key)
		signer.key = nil
	}
	return nil
}

func closePlatformSigner(signer crypto.Signer) {
	if closer, ok := signer.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func (identity *Identity) IdentitySPKIDER() []byte {
	if identity == nil {
		return nil
	}
	return append([]byte(nil), identity.identitySPKI...)
}

func (identity *Identity) WrappingSPKIDER() []byte {
	if identity == nil {
		return nil
	}
	return append([]byte(nil), identity.wrappingSPKI...)
}

func (identity *Identity) IdentitySPKIHash() (string, error) {
	if identity == nil || len(identity.identitySPKI) == 0 {
		return "", errors.New("[D129 Windows] identity 缺失")
	}
	return wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identity.identitySPKI)
}

func (identity *Identity) WrappingSPKIHash() (string, error) {
	if identity == nil || len(identity.wrappingSPKI) == 0 {
		return "", errors.New("[D130 Windows] wrapping identity 缺失")
	}
	return wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, identity.wrappingSPKI)
}

func (identity *Identity) SignEnrollmentPoP(body *wire.EnrollmentPoPBodyV2) (string, error) {
	return wire.SignEnrollmentPoPWithSigner(body, identity.Signer())
}

func (identity *Identity) unsealSecret(envelope *wire.SealedSecretEnvelopeV1,
	recipient wire.SealedBlobRecipientKeyRefV1) ([]byte, error) {
	if identity == nil || identity.wrapping == nil {
		return nil, errors.New("[D124 Windows] wrapping key 缺失")
	}
	return wire.UnsealSecretP256(envelope, recipient, identity.wrapping)
}

func (identity *Identity) Close() {
	if identity == nil {
		return
	}
	closePlatformSigner(identity.identity)
	zeroPrivateKey(identity.wrapping)
	clear(identity.identitySPKI)
	clear(identity.wrappingSPKI)
	identity.identity, identity.wrapping = nil, nil
	identity.identitySPKI, identity.wrappingSPKI = nil, nil
}

// DestroyIdentity 删除平台持钥对象后再删除 DPAPI descriptor。普通关闭只释放
// handle，不删除可恢复 identity；tombstone 与本机 Device 删除才调用本函数。
func DestroyIdentity(path string, protector clientsecret.Protector) error {
	if err := validateProtectedPath(path); err != nil || protector == nil {
		return errors.New("[D129 Windows] destroy identity path/protector 无效")
	}
	body, err := clientsecret.ReadProtected(path, IdentityPurpose, protector)
	if err != nil {
		return err
	}
	defer clear(body)
	var state protectedIdentityV1
	canonical, err := wire.DecodeStrict(body, maximumIdentityState, &state)
	if err != nil || !bytes.Equal(canonical, body) {
		return errors.New("[D129 Windows] identity descriptor 损坏，拒绝猜测 CNG key")
	}
	if err := destroyPlatformIdentity(platformIdentityRecord{
		Provider: state.IdentityProvider, KeyName: state.IdentityKeyName,
		MachineScope: state.IdentityMachineScope, PrivateKeyPKCS8: state.IdentityPrivateKeyPKCS8,
	}); err != nil {
		return err
	}
	return os.Remove(path)
}

func zeroPrivateKey(key *ecdsa.PrivateKey) {
	if key != nil && key.D != nil {
		key.D.SetInt64(0)
	}
}

func validateProtectedPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("protected path 必须是规范绝对路径")
	}
	return nil
}
