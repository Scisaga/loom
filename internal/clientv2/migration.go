package clientv2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"loom/internal/clientmigration"
	"loom/internal/wire"
)

type LinuxMigrationEvidenceV1 struct {
	Package           wire.RuntimeDeviceMigrationPackageV1 `json:"package"`
	PlatformPublicKey string                               `json:"platform_public_key"`
	LegacyFloor       clientmigration.Floor                `json:"legacy_floor"`
	ApprovedAt        string                               `json:"approved_at"`
}

func (installation *DeviceInstallationV1) certificateDER() ([]byte, error) {
	if installation == nil {
		return nil, errors.New("[Linux install] 身份材料缺失")
	}
	if installation.MigrationProof == nil {
		return wire.EnrollmentResultCertificateDER(&installation.ResultArtifact)
	}
	value := installation.MigrationProof.Package.DeviceCertificateDER
	der, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != value {
		return nil, errors.New("[Linux migration] 证书编码无效")
	}
	return der, nil
}

func validateLinuxMigrationInstallation(installation *DeviceInstallationV1, envelope *wire.DeviceViewEnvelopeV2, floors wire.ClientFloorsV2) error {
	if installation == nil || installation.Schema != 1 || installation.MigrationProof == nil || installation.Credentials == nil ||
		!wire.EqualCanonical(installation.ClaimCore, wire.EnrollmentClaimCoreV2{}) || installation.ClaimCoreHash != "" ||
		installation.TransactionStateHash != "" || installation.ResultArtifactHash != "" ||
		!wire.EqualCanonical(installation.ResultArtifact, wire.EnrollmentResultArtifactV1{}) {
		return errors.New("[Linux migration] 迁移身份禁止伪造 Enrollment 记录")
	}
	proof := installation.MigrationProof
	public, err := base64.RawURLEncoding.DecodeString(proof.PlatformPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != proof.PlatformPublicKey {
		return errors.New("[Linux migration] 原平台信任公钥无效")
	}
	der, err := installation.certificateDER()
	if err != nil {
		return err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	original, err := base64.RawURLEncoding.DecodeString(proof.Package.LegacySignedCurrent)
	if err != nil || base64.RawURLEncoding.EncodeToString(original) != proof.Package.LegacySignedCurrent {
		return errors.New("[Linux migration] 原 signed current 编码无效")
	}
	legacy, err := clientmigration.VerifyFloor(original, public, envelope.Payload.DeviceID, proof.LegacyFloor)
	if err != nil {
		return err
	}
	at, err := wire.ParseTimeZ(proof.ApprovedAt)
	if err != nil {
		return err
	}
	trust, err := clientmigration.RuntimeActivationTrust(public)
	if err != nil {
		return err
	}
	verified, err := wire.VerifyRuntimeDeviceMigration(&proof.Package, wire.RuntimeDeviceMigrationExpectedV1{
		DeviceID: envelope.Payload.DeviceID, Platform: "linux-server", IdentitySPKIDER: certificate.RawSubjectPublicKeyInfo,
		WrappingKeyHash: installation.WrappingKeyHash, LegacyFloor: legacy},
		trust, at)
	if err != nil {
		return err
	}
	initial := verified.Configuration().Envelope()
	leaf := verified.Leaf()
	if verified.ApprovedAt() != proof.ApprovedAt || installation.IdentityKeyHash != leaf.IdentitySPKIHash ||
		installation.DeviceCertificateHash != leaf.DeviceCertificateHash || verified.Configuration().Floors().BootstrapTransitionHash != floors.BootstrapTransitionHash ||
		initial.Payload.DeviceGeneration > envelope.Payload.DeviceGeneration ||
		initial.Payload.DeviceGeneration == envelope.Payload.DeviceGeneration && !wire.EqualCanonical(initial.Payload, envelope.Payload) ||
		!bytes.Equal(verified.CertificateDER(), der) || envelope.Payload.Active != nil && envelope.Payload.Active.IdentitySPKIHash != leaf.IdentitySPKIHash {
		return errors.New("[Linux migration] 当前安装没有延续原迁移身份、配置与 floors")
	}
	refs, err := decodeLinuxSecretArtifactRefs(initial.SecretArtifactRefs)
	if err != nil {
		return err
	}
	return validateInstalledDeviceMaterial(installation, envelope, &initial.Payload, refs)
}
