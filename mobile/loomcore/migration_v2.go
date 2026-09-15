package loomcore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"loom/internal/clientmigration"
	"loom/internal/wire"
)

type androidMigrationInstallationV1 struct {
	androidDeviceInstallationV1
	Package           wire.RuntimeDeviceMigrationPackageV1 `json:"package"`
	PlatformPublicKey string                               `json:"platform_public_key"`
}

// VerifyAndroidV2MigrationPackage 只接受本机已有身份和 floor，并验证原平台
// 签名与迁移承诺。宿主收到成功结果后才下载配置、解封凭据。
func VerifyAndroidV2MigrationPackage(packageJSON, legacyFloorJSON, pinnedPlatformKey,
	identitySPKIDER, wrappingSPKIDER []byte, deviceID, trustedTime string) ([]byte, error) {
	delivery, _, err := verifyAndroidMigrationInputs(packageJSON, legacyFloorJSON, pinnedPlatformKey,
		identitySPKIDER, wrappingSPKIDER, deviceID, trustedTime)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(delivery)
}

func verifyAndroidMigrationInputs(packageJSON, legacyFloorJSON, pinnedPlatformKey,
	identitySPKIDER, wrappingSPKIDER []byte, deviceID, trustedTime string) (
	wire.RuntimeDeviceMigrationPackageV1, wire.VerifiedRuntimeDeviceMigrationV1, error) {
	var delivery wire.RuntimeDeviceMigrationPackageV1
	var verified wire.VerifiedRuntimeDeviceMigrationV1
	if err := decodeExactAndroidV2(packageJSON, 32<<20, &delivery, "设备迁移包"); err != nil {
		return delivery, verified, err
	}
	floor, err := clientmigration.ParseFloor(legacyFloorJSON)
	if err != nil {
		return delivery, verified, err
	}
	original, err := base64.RawURLEncoding.DecodeString(delivery.LegacySignedCurrent)
	if err != nil || base64.RawURLEncoding.EncodeToString(original) != delivery.LegacySignedCurrent {
		return delivery, verified, errors.New("[Android migration] 原签名 current 编码无效")
	}
	legacy, err := clientmigration.VerifyFloor(original, pinnedPlatformKey, deviceID, floor)
	if err != nil {
		return delivery, verified, err
	}
	wrappingHash, err := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrappingSPKIDER)
	if err != nil {
		return delivery, verified, err
	}
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return delivery, verified, err
	}
	verified, err = wire.VerifyRuntimeDeviceMigration(&delivery, wire.RuntimeDeviceMigrationExpectedV1{
		DeviceID: deviceID, Platform: "android", IdentitySPKIDER: identitySPKIDER,
		WrappingKeyHash: wrappingHash, LegacyFloor: legacy,
	}, wire.InviteProofTrustV2{V1PlatformKey: pinnedPlatformKey,
		V1PlatformKeyID: delivery.Activation.Proof.Statement.V1PlatformKeyID}, now)
	return delivery, verified, err
}

// PrepareAndroidV2MigrationInstallation 一次性组成迁移身份、真实配置、凭据和
// floor；不生成新加入事务，也不把旧 bundle 作为 v2 运行配置。
func PrepareAndroidV2MigrationInstallation(packageJSON, legacyFloorJSON, pinnedPlatformKey,
	identitySPKIDER, wrappingSPKIDER, installedSecretsJSON, installedConfigsJSON []byte,
	deviceID, trustedTime string) ([]byte, error) {
	delivery, verified, err := verifyAndroidMigrationInputs(packageJSON, legacyFloorJSON, pinnedPlatformKey,
		identitySPKIDER, wrappingSPKIDER, deviceID, trustedTime)
	if err != nil {
		return nil, err
	}
	var credentials []androidInstalledSecretV1
	if err := decodeExactAndroidV2(installedSecretsJSON, 16<<20, &credentials, "迁移凭据"); err != nil {
		return nil, err
	}
	var configs []androidInstalledConfigV1
	if err := decodeExactAndroidV2(installedConfigsJSON, androidMaximumConfigTotalBytes+(4<<20),
		&configs, "迁移配置"); err != nil {
		return nil, err
	}
	return prepareAndroidMigrationState(delivery, verified, pinnedPlatformKey, credentials, configs)
}

func prepareAndroidMigrationState(delivery wire.RuntimeDeviceMigrationPackageV1,
	verified wire.VerifiedRuntimeDeviceMigrationV1, platformKey ed25519.PublicKey,
	credentials []androidInstalledSecretV1, configs []androidInstalledConfigV1) ([]byte, error) {
	configuration, leaf := verified.Configuration(), verified.Leaf()
	envelope, set := configuration.Envelope(), configuration.ControlSet()
	profile, issuance := verified.Profile(), leaf.Issuance
	refs, err := decodeAndroidSecretArtifactRefs(envelope.SecretArtifactRefs)
	if err != nil {
		return nil, err
	}
	if credentials == nil || configs == nil {
		return nil, errors.New("[Android migration] 正式配置与凭据必须完整")
	}
	state := androidV2DeviceState{Schema: 1, Floors: configuration.Floors(), Envelope: envelope,
		ControlSet: &set, PreviousControlSet: configuration.PreviousControlSet(),
		Migration: &androidMigrationInstallationV1{
			Package: delivery, PlatformPublicKey: base64.RawURLEncoding.EncodeToString(platformKey),
			androidDeviceInstallationV1: androidDeviceInstallationV1{
				Schema: 1, IdentityKeyHash: leaf.IdentitySPKIHash, WrappingKeyHash: leaf.WrappingKeyHash,
				DeviceCertificateHash: leaf.DeviceCertificateHash, DeviceProfileHash: leaf.DeviceCertificateProfileHash,
				DeviceProfile: &profile, DeviceIssuance: &issuance, DeviceApprovedAt: verified.ApprovedAt(),
				Configs: configs, Credentials: credentials, CurrentSecretArtifactRefs: cloneAndroidSecretArtifactRefs(refs),
				DistributionMirrors: delivery.DistributionMirrors,
			},
		},
	}
	return marshalAndroidV2DeviceState(state)
}

func validateAndroidMigrationInstallation(installation *androidMigrationInstallationV1,
	envelope *wire.DeviceViewEnvelopeV2, floors wire.ClientFloorsV2) error {
	if installation == nil || envelope == nil || installation.CurrentSecretArtifactRefs == nil ||
		installation.DeviceProfile == nil || installation.DeviceIssuance == nil ||
		envelope.Payload.Active != nil && installation.Configs == nil ||
		installation.DistributionMirrors == nil {
		return errors.New("[Android migration] 迁移状态不完整")
	}
	delivery := &installation.Package
	public, err := base64.RawURLEncoding.DecodeString(installation.PlatformPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(public) != installation.PlatformPublicKey {
		return errors.New("[Android migration] 原平台公钥缺失")
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
	verified, err := wire.VerifyRuntimeDeviceMigration(delivery, wire.RuntimeDeviceMigrationExpectedV1{
		DeviceID: leaf.DeviceID, Platform: "android", IdentitySPKIDER: parsed.RawSubjectPublicKeyInfo,
		WrappingKeyHash: installation.WrappingKeyHash, LegacyFloor: leaf.LegacyFloor,
	}, wire.InviteProofTrustV2{V1PlatformKey: public,
		V1PlatformKeyID: delivery.Activation.Proof.Statement.V1PlatformKeyID}, approvedAt)
	if err != nil {
		return err
	}
	initial := verified.Configuration().Envelope()
	if verified.Configuration().Floors().BootstrapTransitionHash != floors.BootstrapTransitionHash ||
		installation.IdentityKeyHash != leaf.IdentitySPKIHash ||
		installation.DeviceCertificateHash != leaf.DeviceCertificateHash ||
		installation.DeviceProfileHash != leaf.DeviceCertificateProfileHash ||
		!wire.EqualCanonical(*installation.DeviceProfile, verified.Profile()) ||
		!wire.EqualCanonical(*installation.DeviceIssuance, leaf.Issuance) ||
		installation.DeviceApprovedAt != verified.ApprovedAt() ||
		initial.Payload.DeviceGeneration == envelope.Payload.DeviceGeneration &&
			!wire.EqualCanonical(initial.Payload, envelope.Payload) {
		return errors.New("[Android migration] 本机状态未延续原认证迁移")
	}
	return validateAndroidDeviceMaterial(&installation.androidDeviceInstallationV1, certificate,
		&initial.Payload, envelope, *installation.CurrentSecretArtifactRefs)
}

// 请求只携带公开材料；identity/wrapping 私钥均留在 Android Keystore。
func PrepareAndroidV2MigrationRequestBody(deviceID string, floorJSON, platformKey,
	identitySPKIDER, wrappingSPKIDER []byte, wrappingProfile string) ([]byte, error) {
	floor, err := clientmigration.ParseFloor(floorJSON)
	if err != nil {
		return nil, err
	}
	floorBody, err := wire.MarshalCanonical(floor)
	if err != nil {
		return nil, err
	}
	body := wire.RuntimeDeviceMigrationRequestBodyV1{Schema: 1, DeviceID: deviceID, Platform: "android",
		PlatformKeyHash:    fmt.Sprintf("sha256:%x", sha256.Sum256(platformKey)),
		IdentitySPKIDER:    base64.RawURLEncoding.EncodeToString(identitySPKIDER),
		WrappingSPKIDER:    base64.RawURLEncoding.EncodeToString(wrappingSPKIDER),
		WrappingKeyProfile: wrappingProfile, LegacyFloor: floorBody}
	if len(platformKey) != ed25519.PublicKeySize {
		return nil, errors.New("[Android migration] 原平台公钥缺失")
	}
	if _, err := wire.RuntimeDeviceMigrationRequestMessage(&body); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(body)
}

func AndroidV2MigrationRequestMessage(bodyJSON []byte) ([]byte, error) {
	var body wire.RuntimeDeviceMigrationRequestBodyV1
	if err := decodeExactAndroidV2(bodyJSON, 1<<20, &body, "设备迁移请求"); err != nil {
		return nil, err
	}
	return wire.RuntimeDeviceMigrationRequestMessage(&body)
}

func AssembleAndroidV2MigrationRequest(bodyJSON, signatureDER []byte) ([]byte, error) {
	var body wire.RuntimeDeviceMigrationRequestBodyV1
	if err := decodeExactAndroidV2(bodyJSON, 1<<20, &body, "设备迁移请求"); err != nil {
		return nil, err
	}
	request := wire.RuntimeDeviceMigrationRequestV1{Schema: 1, Body: body,
		Signature: base64.RawURLEncoding.EncodeToString(signatureDER)}
	public, err := base64.RawURLEncoding.DecodeString(body.IdentitySPKIDER)
	if err != nil {
		return nil, err
	}
	hash, err := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, public)
	if err != nil {
		return nil, err
	}
	if err := wire.VerifyRuntimeDeviceMigrationRequest(&request, hash, body.PlatformKeyHash); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(request)
}
