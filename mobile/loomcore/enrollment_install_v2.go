package loomcore

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const androidInstalledSecretDomainV1 = "loom-android-installed-secret-v1"

// androidEnrollmentInstallationV1 是 Android 首次 v2 身份的单 blob 提交单元。
// Keystore identity 私钥不在这里；证书、stable core、首次 view 与全部解封凭据
// 必须和 floors 一起由 EncryptedStore 原子替换（D106、D124、D130）。
type androidEnrollmentInstallationV1 struct {
	Schema                int                             `json:"schema"`
	ClaimCore             wire.EnrollmentClaimCoreV2      `json:"claim_core"`
	ClaimCoreHash         string                          `json:"claim_core_hash"`
	IdentityKeyHash       string                          `json:"identity_key_hash"`
	WrappingKeyHash       string                          `json:"wrapping_key_hash"`
	TransactionStateHash  string                          `json:"transaction_state_hash"`
	ResultArtifactHash    string                          `json:"result_artifact_hash"`
	DeviceCertificateHash string                          `json:"device_certificate_hash"`
	ResultArtifact        wire.EnrollmentResultArtifactV1 `json:"result_artifact"`
	Credentials           []androidInstalledSecretV1      `json:"credentials"`
}

type androidInstalledSecretV1 struct {
	SecretID     string `json:"secret_id"`
	Purpose      string `json:"purpose"`
	Generation   int64  `json:"generation"`
	ImmutableRef string `json:"immutable_ref"`
	SecretBytes  string `json:"secret_bytes"`
	SecretDigest string `json:"secret_digest"`
}

// PrepareAndroidInstalledSecretV2 在 Kotlin 解封后立即重绑 exact ref/envelope，
// 再生成受保护状态所需的 canonical credential。明文不能绕过共享 verifier
// 自行标注 purpose/generation（D124）。
func PrepareAndroidInstalledSecretV2(refJSON, envelopeJSON, secret []byte) ([]byte, error) {
	var ref wire.SecretArtifactRefV2
	if err := decodeExactAndroidV2(refJSON, 4<<20, &ref, "secret artifact ref"); err != nil {
		return nil, err
	}
	var envelope wire.SealedSecretEnvelopeV1
	if err := decodeExactAndroidV2(envelopeJSON, 4<<20, &envelope, "sealed secret envelope"); err != nil {
		return nil, err
	}
	if err := wire.VerifySealedSecretBinding(&ref, &envelope); err != nil {
		return nil, err
	}
	if len(secret) == 0 || len(secret) > 8<<20 {
		return nil, errors.New("[D124 Android] 解封 credential 大小无效")
	}
	return wire.MarshalCanonical(androidInstalledSecretV1{
		SecretID: ref.SecretID, Purpose: ref.Purpose, Generation: ref.Generation,
		ImmutableRef: ref.ImmutableRef, SecretBytes: base64.RawURLEncoding.EncodeToString(secret),
		SecretDigest: wire.HashRaw(androidInstalledSecretDomainV1, secret),
	})
}

// PrepareAndroidV2EnrollmentInstallationState 重放 completion receipt 与 exact
// Invite authority，把宿主返回的 credentials 逐项绑定 result/view refs，最后只返回
// 一个可原子持久化的状态。任何局部产物都不足以建立正式 Device 身份（D115、D124、D130）。
func PrepareAndroidV2EnrollmentInstallationState(descriptorJSON, proofBundleJSON,
	preflightJSON, claimCoreJSON, resultJSON, installedSecretsJSON []byte, trustedTime string,
) ([]byte, error) {
	inputs, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	preflight, err := verifyAndroidEnrollmentPreflightV2(inputs, preflightJSON)
	if err != nil {
		return nil, err
	}
	var core wire.EnrollmentClaimCoreV2
	if err := decodeExactAndroidV2(claimCoreJSON, 4<<20, &core, "Enrollment claim core"); err != nil {
		return nil, err
	}
	if err := validateAndroidEnrollmentClaimCoreV2(inputs, preflight, &core); err != nil {
		return nil, err
	}
	now, _ := wire.ParseTimeZ(trustedTime)
	_, result, completion, err := verifyAndroidEnrollmentV2ClaimResult(
		inputs, preflight, core, resultJSON, now,
	)
	if err != nil {
		return nil, err
	}
	if completion == nil || result.ResultArtifact == nil {
		return nil, errors.New("[D130 Android] 安装只能由 verified completed result 解锁")
	}
	if err := completion.VerifyInstallationContext(&result, &core, inputs.verified); err != nil {
		return nil, err
	}
	var credentials []androidInstalledSecretV1
	if err := decodeExactAndroidV2(installedSecretsJSON, 16<<20, &credentials,
		"installed credentials"); err != nil {
		return nil, err
	}
	if credentials == nil {
		return nil, errors.New("[D124 Android] installed credentials 必须是 canonical array")
	}
	return prepareAndroidEnrollmentInstallationState(core, result, *completion,
		inputs.verified, credentials)
}

func prepareAndroidEnrollmentInstallationState(core wire.EnrollmentClaimCoreV2,
	result wire.EnrollmentClaimResultV2, completion enrollmentv2.VerifiedEnrollmentCompletionV1,
	proof wire.VerifiedInviteProofV2, credentials []androidInstalledSecretV1,
) ([]byte, error) {
	if result.ResultArtifact == nil || credentials == nil {
		return nil, errors.New("[D130 Android] enrollment installation 输入不完整")
	}
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&core)
	if err != nil {
		return nil, err
	}
	claimCoreHash, err := wire.EnrollmentClaimCoreHash(&core)
	if err != nil {
		return nil, err
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(result.ResultArtifact)
	if err != nil {
		return nil, err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil {
		return nil, err
	}
	envelope, set := completion.DeviceViewEnvelope(), completion.ControlSet()
	state, err := prepareInitialAndroidV2DeviceStateFromVerified(
		envelope, set, proof, result.ResultArtifact.InitialDeviceView.DeviceID, identityHash,
	)
	if err != nil {
		return nil, err
	}
	state.Enrollment = &androidEnrollmentInstallationV1{
		Schema: 1, ClaimCore: core, ClaimCoreHash: claimCoreHash,
		IdentityKeyHash: identityHash, WrappingKeyHash: wrappingHash,
		TransactionStateHash: result.TransactionStateHash, ResultArtifactHash: result.ResultArtifactHash,
		DeviceCertificateHash: certificateHash, ResultArtifact: *result.ResultArtifact,
		Credentials: credentials,
	}
	return marshalAndroidV2DeviceState(state)
}

// ValidateAndroidV2DeviceState 用于 EncryptedStore 写后回读；成功只说明 exact
// canonical state 内部自洽，不会把未安装状态升级为可连接配置（D106）。
func ValidateAndroidV2DeviceState(stateJSON []byte) error {
	_, err := decodeAndroidV2DeviceState(stateJSON)
	return err
}

// ValidateAndroidV2InstalledPending 处理“正式 blob 已提交、pending 尚未删除”崩溃窗。
// 只有 pending 的 exact stable core/completed result 与安装记录相同才允许清理（D130）。
func ValidateAndroidV2InstalledPending(stateJSON, claimCoreJSON, resultJSON []byte) error {
	state, err := decodeAndroidV2DeviceState(stateJSON)
	if err != nil {
		return err
	}
	if state.Enrollment == nil {
		return errors.New("[D130 Android] protected v2 state 尚无 enrollment installation")
	}
	var core wire.EnrollmentClaimCoreV2
	if err := decodeExactAndroidV2(claimCoreJSON, 4<<20, &core, "pending claim core"); err != nil {
		return err
	}
	var result wire.EnrollmentClaimResultV2
	if err := decodeExactAndroidV2(resultJSON, 32<<20, &result, "pending completed result"); err != nil {
		return err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return err
	}
	installed := state.Enrollment
	if result.Status != "completed" || result.ResultArtifact == nil ||
		!wire.EqualCanonical(core, installed.ClaimCore) ||
		result.TransactionStateHash != installed.TransactionStateHash ||
		result.ResultArtifactHash != installed.ResultArtifactHash ||
		!wire.EqualCanonical(*result.ResultArtifact, installed.ResultArtifact) {
		return errors.New("[D130 Android] pending transaction 与 durable installation 不匹配")
	}
	return nil
}

func validateAndroidEnrollmentInstallation(installation *androidEnrollmentInstallationV1,
	envelope *wire.DeviceViewEnvelopeV2,
) error {
	if installation == nil || envelope == nil || installation.Schema != 1 || installation.Credentials == nil {
		return errors.New("[D130 Android] durable installation header 无效")
	}
	for _, hash := range []string{installation.ClaimCoreHash, installation.IdentityKeyHash,
		installation.WrappingKeyHash, installation.TransactionStateHash, installation.ResultArtifactHash,
		installation.DeviceCertificateHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	resultHash, err := wire.EnrollmentResultArtifactHash(&installation.ResultArtifact)
	initialView := &installation.ResultArtifact.InitialDeviceView
	if err != nil || resultHash != installation.ResultArtifactHash || initialView.Active == nil ||
		initialView.ClusterID != envelope.Payload.ClusterID || initialView.DeviceID != envelope.Payload.DeviceID ||
		initialView.DeviceGeneration > envelope.Payload.DeviceGeneration ||
		initialView.DeviceGeneration == envelope.Payload.DeviceGeneration &&
			!wire.EqualCanonical(*initialView, envelope.Payload) ||
		initialView.Active.IdentitySPKIHash != installation.IdentityKeyHash {
		return errors.New("[D130 Android] durable initial result/current view/identity lineage 无效")
	}
	claimCoreHash, err := wire.EnrollmentClaimCoreHash(&installation.ClaimCore)
	if err != nil || claimCoreHash != installation.ClaimCoreHash {
		return errors.New("[D130 Android] durable stable claim core/hash 不匹配")
	}
	identityHash, wrappingHash, _, err := wire.EnrollmentClaimBinaryHashes(&installation.ClaimCore)
	if err != nil || identityHash != installation.IdentityKeyHash || wrappingHash != installation.WrappingKeyHash {
		return errors.New("[D130 Android] durable stable claim/key binding 无效")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(&installation.ResultArtifact)
	if err != nil {
		return err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	certificate, parseErr := x509.ParseCertificate(certificateDER)
	if err != nil || parseErr != nil || certificateHash != installation.DeviceCertificateHash {
		return errors.New("[D102 Android] durable certificate/hash 无效")
	}
	certificateIdentityHash, err := wire.HashBytes(
		wire.DomainEnrollmentIdentitySPKI, certificate.RawSubjectPublicKeyInfo,
	)
	if err != nil || certificateIdentityHash != installation.IdentityKeyHash {
		return errors.New("[D102 Android] durable certificate 未绑定 Keystore identity")
	}
	refs := installation.ResultArtifact.SecretArtifactRefs
	if len(refs) != len(installation.Credentials) || len(refs) != len(envelope.SecretArtifactRefs) {
		return errors.New("[D124 Android] durable credentials/refs 数量不匹配")
	}
	totalSecretBytes := 0
	for index := range refs {
		canonicalRef, refErr := wire.MarshalCanonical(refs[index])
		canonicalEnvelopeRef, envelopeErr := wire.CanonicalizeStrict(envelope.SecretArtifactRefs[index])
		credential := &installation.Credentials[index]
		if refErr != nil || envelopeErr != nil || !bytes.Equal(canonicalRef, canonicalEnvelopeRef) ||
			credential.SecretID != refs[index].SecretID || credential.Purpose != refs[index].Purpose ||
			credential.Generation != refs[index].Generation || credential.ImmutableRef != refs[index].ImmutableRef {
			return errors.New("[D124 Android] durable credential 未绑定 exact secret ref")
		}
		secret, decodeErr := base64.RawURLEncoding.DecodeString(credential.SecretBytes)
		if decodeErr != nil || len(secret) == 0 ||
			base64.RawURLEncoding.EncodeToString(secret) != credential.SecretBytes ||
			wire.HashRaw(androidInstalledSecretDomainV1, secret) != credential.SecretDigest {
			return errors.New("[D124 Android] durable credential bytes/digest 无效")
		}
		totalSecretBytes += len(secret)
		clear(secret)
		if totalSecretBytes > 8<<20 {
			return errors.New("[D124 Android] durable credentials 超过 bootstrap 总预算")
		}
	}
	return nil
}
