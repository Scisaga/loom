package windowsv2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"time"

	"loom/internal/clientmigration"
	"loom/internal/clientsecret"
	"loom/internal/wire"
)

// MigrationInstallationV1 保留实际迁移证据，不创建 ClaimCore 或 EnrollmentResult。
// 公钥信任来源在首次验证后随 DPAPI blob 保存，后续回读只能延续同一迁移承诺。
type MigrationInstallationV1 struct {
	DeviceInstallationV1
	Package           wire.RuntimeDeviceMigrationPackageV1 `json:"package"`
	PlatformPublicKey string                               `json:"platform_public_key"`
}

type MigrationInstall struct {
	StatePath         string
	IdentityPath      string
	Protector         clientsecret.Protector
	Package           wire.RuntimeDeviceMigrationPackageV1
	Expected          wire.RuntimeDeviceMigrationExpectedV1
	LegacyFloor       clientmigration.Floor
	Trust             wire.InviteProofTrustV2
	Now               time.Time
	Configs           []InstalledConfigV1
	ValidateCandidate func(*StateV1) error
}

// InstallMigration 要求宿主先从原受保护状态提取 Expected；身份公钥再次与 CNG
// 对照。验证、解封、静态启动校验全部通过后，才一次提交 v2 latch 和配置。
func InstallMigration(input MigrationInstall) (wire.ClientFloorsV2, error) {
	identity, err := LoadIdentity(input.IdentityPath, input.Protector)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	defer identity.Close()
	wrappingHash, err := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, identity.WrappingSPKIDER())
	if err != nil || !bytes.Equal(input.Expected.IdentitySPKIDER, identity.IdentitySPKIDER()) ||
		input.Expected.WrappingKeyHash != wrappingHash || input.Expected.Platform != "windows-desktop" {
		return wire.ClientFloorsV2{}, errors.New("[Windows migration] 原设备身份与本机 CNG 密钥不一致")
	}
	original, err := base64.RawURLEncoding.DecodeString(input.Package.LegacySignedCurrent)
	if err != nil || base64.RawURLEncoding.EncodeToString(original) != input.Package.LegacySignedCurrent {
		return wire.ClientFloorsV2{}, errors.New("[Windows migration] 原签名 current 编码无效")
	}
	input.Expected.LegacyFloor, err = clientmigration.VerifyFloor(original, input.Trust.V1PlatformKey,
		input.Expected.DeviceID, input.LegacyFloor)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	verified, err := wire.VerifyRuntimeDeviceMigration(&input.Package, input.Expected, input.Trust, input.Now)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	envelope := verified.Configuration().Envelope()
	refs, err := decodeSecretArtifactRefs(envelope.SecretArtifactRefs)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	credentials, err := installSecrets(identity, refs, input.Package.Configuration.SecretEnvelopes,
		input.Expected.DeviceID)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	state, err := prepareMigrationState(input.Package, verified, input.Trust.V1PlatformKey, input.Configs, credentials)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	if err := validateCandidateWithoutMutation(&state, input.ValidateCandidate); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	store, err := OpenState(input.StatePath, input.Protector)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state != nil {
		if !wire.EqualCanonical(*store.state, state) {
			return store.state.Floors, errors.New("[Windows migration] 已安装的 v2 身份禁止由迁移包覆盖")
		}
		return store.state.Floors, nil
	}
	if err := store.write(&state); err != nil {
		return wire.ClientFloorsV2{}, err
	}
	return store.state.Floors, nil
}

func prepareMigrationState(delivery wire.RuntimeDeviceMigrationPackageV1,
	verified wire.VerifiedRuntimeDeviceMigrationV1, platformKey ed25519.PublicKey,
	configs []InstalledConfigV1, credentials []InstalledSecretV1) (StateV1, error) {
	configuration, leaf := verified.Configuration(), verified.Leaf()
	envelope, set := configuration.Envelope(), configuration.ControlSet()
	refs, err := decodeSecretArtifactRefs(envelope.SecretArtifactRefs)
	if err != nil {
		return StateV1{}, err
	}
	state := StateV1{Schema: 1, Floors: configuration.Floors(), Envelope: envelope,
		ControlSet: &set, PreviousControlSet: configuration.PreviousControlSet(),
		Migration: &MigrationInstallationV1{
			Package: cloneValue(delivery), PlatformPublicKey: base64.RawURLEncoding.EncodeToString(platformKey),
			DeviceInstallationV1: DeviceInstallationV1{
				Schema: 1, IdentityKeyHash: leaf.IdentitySPKIHash, WrappingKeyHash: leaf.WrappingKeyHash,
				DeviceCertificateHash: leaf.DeviceCertificateHash, DeviceProfileHash: leaf.DeviceCertificateProfileHash,
				DeviceProfile: verified.Profile(), DeviceIssuance: leaf.Issuance, DeviceApprovedAt: verified.ApprovedAt(),
				Configs: cloneValue(configs), Credentials: cloneValue(credentials), CurrentSecretArtifactRefs: refs,
				DistributionMirrors: cloneValue(delivery.DistributionMirrors),
			},
		},
	}
	if err := validateState(&state); err != nil {
		return StateV1{}, err
	}
	return state, nil
}

func validateMigrationInstallation(installation *MigrationInstallationV1,
	envelope *wire.DeviceViewEnvelopeV2, floors wire.ClientFloorsV2) error {
	if installation == nil || envelope == nil {
		return errors.New("[Windows migration] 迁移状态缺失")
	}
	delivery := &installation.Package
	public, err := base64.RawURLEncoding.DecodeString(installation.PlatformPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(public) != installation.PlatformPublicKey {
		return errors.New("[Windows migration] 原平台公钥缺失")
	}
	certificate, err := base64.RawURLEncoding.DecodeString(delivery.DeviceCertificateDER)
	if err != nil {
		return err
	}
	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		return err
	}
	approvedAt, err := wire.ParseTimeZ(installation.DeviceApprovedAt)
	if err != nil {
		return err
	}
	leaf := delivery.Migration.Leaf
	trust, err := clientmigration.RuntimeActivationTrust(public)
	if err != nil {
		return err
	}
	verified, err := wire.VerifyRuntimeDeviceMigration(delivery, wire.RuntimeDeviceMigrationExpectedV1{
		DeviceID: leaf.DeviceID, Platform: "windows-desktop", IdentitySPKIDER: parsed.RawSubjectPublicKeyInfo,
		WrappingKeyHash: installation.WrappingKeyHash, LegacyFloor: leaf.LegacyFloor,
	}, trust, approvedAt)
	if err != nil {
		return err
	}
	initial := verified.Configuration().Envelope()
	if verified.Configuration().Floors().BootstrapTransitionHash != floors.BootstrapTransitionHash ||
		installation.IdentityKeyHash != leaf.IdentitySPKIHash ||
		installation.DeviceCertificateHash != leaf.DeviceCertificateHash ||
		installation.DeviceProfileHash != leaf.DeviceCertificateProfileHash ||
		!wire.EqualCanonical(installation.DeviceProfile, verified.Profile()) ||
		!wire.EqualCanonical(installation.DeviceIssuance, leaf.Issuance) ||
		installation.DeviceApprovedAt != verified.ApprovedAt() ||
		initial.Payload.DeviceGeneration == envelope.Payload.DeviceGeneration &&
			!wire.EqualCanonical(initial.Payload, envelope.Payload) {
		return errors.New("[Windows migration] 本机状态未延续原认证迁移")
	}
	return validateDeviceMaterial(&installation.DeviceInstallationV1, certificate, &initial.Payload, envelope)
}
