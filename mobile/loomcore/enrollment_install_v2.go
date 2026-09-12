package loomcore

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const androidInstalledSecretDomainV1 = "loom-android-installed-secret-v1"

const (
	androidMaximumConfigArtifacts     = 16
	androidMaximumConfigArtifactBytes = 16 << 20
	androidMaximumConfigTotalBytes    = 32 << 20
)

// androidEnrollmentInstallationV1 是 Android 首次 v2 身份的单 blob 提交单元。
// Keystore identity 私钥不在这里；证书、stable core、首次 view 与全部解封凭据
// 必须和 floors 一起由 EncryptedStore 原子替换（D106、D124、D130）。
type androidEnrollmentInstallationV1 struct {
	Schema                int                                   `json:"schema"`
	ClaimCore             wire.EnrollmentClaimCoreV2            `json:"claim_core"`
	ClaimCoreHash         string                                `json:"claim_core_hash"`
	IdentityKeyHash       string                                `json:"identity_key_hash"`
	WrappingKeyHash       string                                `json:"wrapping_key_hash"`
	TransactionStateHash  string                                `json:"transaction_state_hash"`
	ResultArtifactHash    string                                `json:"result_artifact_hash"`
	DeviceCertificateHash string                                `json:"device_certificate_hash"`
	DeviceProfileHash     string                                `json:"device_profile_hash,omitempty"`
	DeviceProfile         *wire.DeviceCertificateProfileStateV1 `json:"device_profile,omitempty"`
	DeviceIssuance        *wire.IssuanceLogCoordinateV1         `json:"device_issuance,omitempty"`
	DeviceApprovedAt      string                                `json:"device_approved_at,omitempty"`
	ResultArtifact        wire.EnrollmentResultArtifactV1       `json:"result_artifact"`
	Credentials           []androidInstalledSecretV1            `json:"credentials"`
	// CurrentSecretArtifactRefs 与首次 ResultArtifact 证据分离；nil 仅表示
	// 旧版安装 blob，指向空 slice 则表示已合法轮换为零凭据。
	CurrentSecretArtifactRefs *[]wire.SecretArtifactRefV2 `json:"current_secret_artifact_refs,omitempty"`
	// Configs 在旧版已安装 blob 中可缺省；新 Enrollment 不得走该兼容路径。
	Configs             []androidInstalledConfigV1     `json:"configs,omitempty"`
	DistributionMirrors []wire.DistributionMirrorRefV1 `json:"distribution_mirrors,omitempty"`
}

type androidInstalledSecretV1 struct {
	SecretID     string `json:"secret_id"`
	Purpose      string `json:"purpose"`
	Generation   int64  `json:"generation"`
	ImmutableRef string `json:"immutable_ref"`
	SecretBytes  string `json:"secret_bytes"`
	SecretDigest string `json:"secret_digest"`
}

type androidInstalledConfigV1 struct {
	ArtifactID       string          `json:"artifact_id"`
	Generation       int64           `json:"generation"`
	Platform         string          `json:"platform"`
	MediaType        string          `json:"media_type"`
	RenderContractID string          `json:"render_contract_id"`
	SizeBytes        int64           `json:"size_bytes"`
	ContentHash      string          `json:"content_hash"`
	Config           json.RawMessage `json:"config"`
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

// PrepareAndroidInstalledConfigV2 将公开 mirror 返回的 exact canonical 制品
// 重新绑定到 certified Device view ref。Kotlin 不能自行认定 hash/大小/平台（D105、D124）。
func PrepareAndroidInstalledConfigV2(refJSON, config []byte) ([]byte, error) {
	var ref wire.DeviceConfigArtifactRefV1
	if err := decodeExactAndroidV2(refJSON, 1<<20, &ref, "config artifact ref"); err != nil {
		return nil, err
	}
	if err := wire.ValidateDeviceConfigArtifactRef(&ref); err != nil {
		return nil, err
	}
	if ref.Platform != "android" || ref.SizeBytes > androidMaximumConfigArtifactBytes ||
		len(config) != int(ref.SizeBytes) {
		return nil, errors.New("[D124 Android] config artifact 平台或大小无效")
	}
	canonical, err := wire.CanonicalizeStrict(config)
	if err != nil || !bytes.Equal(canonical, config) {
		return nil, errors.New("[D124 Android] config artifact 不是 exact canonical JSON")
	}
	contentHash, err := wire.DeviceConfigArtifactContentHash(config)
	if err != nil || contentHash != ref.ContentHash {
		return nil, errors.New("[D124 Android] config artifact content hash 不匹配")
	}
	return wire.MarshalCanonical(androidInstalledConfigV1{
		ArtifactID: ref.ArtifactID, Generation: ref.Generation, Platform: ref.Platform,
		MediaType: ref.MediaType, RenderContractID: ref.RenderContractID,
		SizeBytes: ref.SizeBytes, ContentHash: ref.ContentHash,
		Config: append(json.RawMessage(nil), config...),
	})
}

// PrepareAndroidV2EnrollmentInstallationStateWithConfigs 是新版生产安装边界：
// certificate/view/config/credentials/floors 只会作为同一 protected blob 提交（Issue #14、D124、D130）。
func PrepareAndroidV2EnrollmentInstallationStateWithConfigs(descriptorJSON, proofBundleJSON,
	preflightJSON, claimCoreJSON, resultJSON, installedSecretsJSON, installedConfigsJSON []byte,
	trustedTime string,
) ([]byte, error) {
	return prepareAndroidV2EnrollmentInstallationStateInputs(descriptorJSON, proofBundleJSON,
		preflightJSON, claimCoreJSON, resultJSON, installedSecretsJSON, installedConfigsJSON,
		trustedTime)
}

func prepareAndroidV2EnrollmentInstallationStateInputs(descriptorJSON, proofBundleJSON,
	preflightJSON, claimCoreJSON, resultJSON, installedSecretsJSON, installedConfigsJSON []byte,
	trustedTime string,
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
	var configs []androidInstalledConfigV1
	if err := decodeExactAndroidV2(installedConfigsJSON, androidMaximumConfigTotalBytes+(4<<20),
		&configs, "installed configs"); err != nil {
		return nil, err
	}
	if configs == nil {
		return nil, errors.New("[D124 Android] installed configs 必须是 canonical array")
	}
	return prepareAndroidEnrollmentInstallationState(core, result, *completion,
		inputs.verified, inputs.descriptor.DistributionMirrors, credentials, configs)
}

func prepareAndroidEnrollmentInstallationState(core wire.EnrollmentClaimCoreV2,
	result wire.EnrollmentClaimResultV2, completion enrollmentv2.VerifiedEnrollmentCompletionV1,
	proof wire.VerifiedInviteProofV2, mirrors []wire.DistributionMirrorRefV1,
	credentials []androidInstalledSecretV1,
	configs []androidInstalledConfigV1,
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
	profile := completion.DeviceCertificateProfile()
	profileHash, err := wire.DeviceCertificateProfileStateHash(&profile)
	if err != nil {
		return nil, err
	}
	envelope, set := completion.DeviceViewEnvelope(), completion.ControlSet()
	issuance := completion.DeviceCertificateIssuance()
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
		DeviceCertificateHash: certificateHash, DeviceProfileHash: profileHash,
		DeviceProfile: &profile, DeviceIssuance: &issuance,
		DeviceApprovedAt: completion.DeviceCertificateApprovedAt(), ResultArtifact: *result.ResultArtifact,
		Credentials: credentials, Configs: configs,
		CurrentSecretArtifactRefs: cloneAndroidSecretArtifactRefs(
			result.ResultArtifact.SecretArtifactRefs),
		DistributionMirrors: append([]wire.DistributionMirrorRefV1(nil), mirrors...),
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
	profileContextMissing := installation.DeviceProfile == nil && installation.DeviceProfileHash == "" &&
		installation.DeviceIssuance == nil && installation.DeviceApprovedAt == ""
	profileContextComplete := installation.DeviceProfile != nil && installation.DeviceProfileHash != "" &&
		installation.DeviceIssuance != nil && installation.DeviceApprovedAt != ""
	if !profileContextMissing && !profileContextComplete {
		return errors.New("[D102 Android] durable Device certificate profile 不完整")
	}
	if profileContextComplete {
		profileHash, profileErr := wire.DeviceCertificateProfileStateHash(installation.DeviceProfile)
		approvedAt, timeErr := wire.ParseTimeZ(installation.DeviceApprovedAt)
		if profileErr != nil || timeErr != nil || profileHash != installation.DeviceProfileHash ||
			installation.DeviceProfile.ClusterID != envelope.Payload.ClusterID ||
			installation.DeviceProfile.Status != "active" {
			return errors.New("[D102 Android] durable Device certificate profile/hash 无效")
		}
		if _, verifyErr := wire.VerifyDeviceCertificateAt(certificateDER, installation.DeviceProfile,
			initialView.DeviceID, installation.IdentityKeyHash, installation.ClaimCore.ClientPlatform,
			initialView.Active.Responsibilities.Values, *installation.DeviceIssuance,
			approvedAt, approvedAt); verifyErr != nil {
			return errors.New("[D102 Android] durable Device certificate verification context 无效")
		}
	}
	certificateIdentityHash, err := wire.HashBytes(
		wire.DomainEnrollmentIdentitySPKI, certificate.RawSubjectPublicKeyInfo,
	)
	if err != nil || certificateIdentityHash != installation.IdentityKeyHash {
		return errors.New("[D102 Android] durable certificate 未绑定 Keystore identity")
	}
	refs := installation.ResultArtifact.SecretArtifactRefs
	if installation.CurrentSecretArtifactRefs != nil {
		refs = *installation.CurrentSecretArtifactRefs
	}
	if len(refs) != len(installation.Credentials) ||
		envelope.Payload.Active != nil && len(refs) != len(envelope.SecretArtifactRefs) {
		return errors.New("[D124 Android] durable credentials/refs 数量不匹配")
	}
	totalSecretBytes := 0
	for index := range refs {
		canonicalRef, refErr := wire.MarshalCanonical(refs[index])
		canonicalEnvelopeRef, envelopeErr := canonicalRef, refErr
		if envelope.Payload.Active != nil {
			canonicalEnvelopeRef, envelopeErr = wire.CanonicalizeStrict(envelope.SecretArtifactRefs[index])
		}
		credential := &installation.Credentials[index]
		if refErr != nil || wire.ValidateSecretArtifactRef(&refs[index]) != nil ||
			refs[index].ClusterID != envelope.Payload.ClusterID || refs[index].Owner.Kind != "device" ||
			refs[index].Owner.Device == nil || refs[index].Owner.Device.DeviceID != envelope.Payload.DeviceID ||
			envelopeErr != nil || !bytes.Equal(canonicalRef, canonicalEnvelopeRef) ||
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
	if installation.Configs != nil {
		configRefs := initialView.Active.ConfigArtifactRefs
		if envelope.Payload.Active != nil {
			configRefs = envelope.Payload.Active.ConfigArtifactRefs
		}
		if err := validateAndroidInstalledConfigs(installation.Configs, configRefs); err != nil {
			return err
		}
	}
	if installation.DistributionMirrors != nil {
		if err := wire.ValidateDistributionMirrorRefs(installation.DistributionMirrors); err != nil {
			return errors.New("[D124 Android] durable distribution mirrors 无效")
		}
	}
	return nil
}

func cloneAndroidSecretArtifactRefs(refs []wire.SecretArtifactRefV2) *[]wire.SecretArtifactRefV2 {
	cloned := append([]wire.SecretArtifactRefV2(nil), refs...)
	return &cloned
}

func validateAndroidInstalledConfigs(configs []androidInstalledConfigV1,
	refs []wire.DeviceConfigArtifactRefV1,
) error {
	androidRefs := make([]wire.DeviceConfigArtifactRefV1, 0, len(refs))
	for index := range refs {
		if err := wire.ValidateDeviceConfigArtifactRef(&refs[index]); err != nil {
			return err
		}
		if refs[index].Platform != "android" {
			return errors.New("[D124 Android] Device view 含非 Android config artifact")
		}
		androidRefs = append(androidRefs, refs[index])
	}
	if len(androidRefs) == 0 || len(androidRefs) > androidMaximumConfigArtifacts ||
		len(configs) != len(androidRefs) {
		return errors.New("[D124 Android] installed configs 未 exact 覆盖 Device view refs")
	}
	totalBytes := 0
	for index := range androidRefs {
		ref, installed := &androidRefs[index], &configs[index]
		if ref.SizeBytes > androidMaximumConfigArtifactBytes ||
			installed.ArtifactID != ref.ArtifactID || installed.Generation != ref.Generation ||
			installed.Platform != ref.Platform || installed.MediaType != ref.MediaType ||
			installed.RenderContractID != ref.RenderContractID || installed.SizeBytes != ref.SizeBytes ||
			installed.ContentHash != ref.ContentHash {
			return errors.New("[D124 Android] installed config 未绑定 exact ref")
		}
		raw := []byte(installed.Config)
		if len(raw) != int(ref.SizeBytes) {
			return errors.New("[D124 Android] installed config bytes/size 无效")
		}
		canonical, canonicalErr := wire.CanonicalizeStrict(raw)
		hash, hashErr := wire.DeviceConfigArtifactContentHash(raw)
		if canonicalErr != nil || !bytes.Equal(canonical, raw) || hashErr != nil || hash != ref.ContentHash {
			return errors.New("[D124 Android] installed config canonical bytes/hash 无效")
		}
		totalBytes += len(raw)
		if totalBytes > androidMaximumConfigTotalBytes {
			return errors.New("[D124 Android] installed configs 超过总预算")
		}
	}
	return nil
}
