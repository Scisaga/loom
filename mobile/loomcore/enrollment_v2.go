package loomcore

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"

	"loom/internal/wire"
)

const androidV2InviteURIPrefix = "loom://enroll/v2#d="

// DecodeAndroidV2InviteURI 只解码 QR carrier；descriptor 不因载体
// 变成 trust root，后续仍必须下载并验证 proof。
func DecodeAndroidV2InviteURI(raw string) ([]byte, error) {
	if len(raw) <= len(androidV2InviteURIPrefix) || len(raw) > 1800 ||
		!strings.HasPrefix(raw, androidV2InviteURIPrefix) {
		return nil, errors.New("[Android] v2 Invite URI 形状或大小无效")
	}
	for index := range raw {
		if raw[index] < 0x21 || raw[index] > 0x7e {
			return nil, errors.New("[Android] Invite URI 必须是无空白 ASCII")
		}
	}
	encoded := strings.TrimPrefix(raw, androidV2InviteURIPrefix)
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != encoded {
		return nil, errors.New("[Android] descriptor 必须是 canonical base64url")
	}
	return DecodeAndroidV2InviteFile(body)
}

// DecodeAndroidV2InviteFile 只接受 `.loom-invite` 的 exact canonical object。
func DecodeAndroidV2InviteFile(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("[Android] Invite descriptor 大小无效")
	}
	var descriptor wire.InviteBootstrapDescriptorV2
	canonical, err := wire.DecodeStrict(raw, 1<<20, &descriptor)
	if err != nil || !bytes.Equal(canonical, raw) || descriptor.Schema != 2 {
		return nil, errors.New("[Android] .loom-invite 必须是 exact canonical descriptor")
	}
	return canonical, nil
}

type androidEnrollmentInputsV2 struct {
	descriptor wire.InviteBootstrapDescriptorV2
	bundle     wire.InviteProofBundleV2
	recordHash string
	head       wire.HeadEntryV2
	set        wire.ControlSetV1
	verified   wire.VerifiedInviteProofV2
}

type androidMirrorFetchPlanV2 struct {
	Schema      int                            `json:"schema"`
	ProofHash   string                         `json:"proof_hash"`
	CatalogHash string                         `json:"catalog_hash"`
	Mirrors     []wire.DistributionMirrorRefV1 `json:"mirrors"`
}

// PrepareAndroidV2MirrorFetchPlan 在 proof 取回前只放行 descriptor
// 明示绑定的 2–3 个 HTTPS URL/SPKI pin 和内容哈希。
func PrepareAndroidV2MirrorFetchPlan(descriptorJSON []byte, trustedTime string) ([]byte, error) {
	var descriptor wire.InviteBootstrapDescriptorV2
	if err := decodeExactAndroidV2(descriptorJSON, 8<<20, &descriptor, "Invite descriptor"); err != nil {
		return nil, err
	}
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, errors.New("[Android] Invite trusted time 无效")
	}
	if descriptor.Schema != 2 || descriptor.ClusterID == "" || descriptor.InviteID == "" ||
		descriptor.MinimumRecoveryEpoch < 0 {
		return nil, errors.New("[Android] Invite descriptor header 无效")
	}
	descriptorExpiry, err := wire.ParseTimeZ(descriptor.ExpiresAt)
	if err != nil || !now.Before(descriptorExpiry) {
		return nil, errors.New("[Android] Invite 已过期")
	}
	tokenCommitment, err := wire.TokenCommitment(descriptor.ClusterID, descriptor.InviteID, descriptor.Token)
	if err != nil || tokenCommitment != descriptor.TokenCommitment {
		return nil, errors.New("[Android] Invite token commitment 不匹配")
	}
	if err := wire.ValidateDistributionMirrorRefs(descriptor.DistributionMirrors); err != nil {
		return nil, err
	}
	if err := wire.ValidateCapabilityBody(&descriptor.BootstrapTunnelCapability.Body); err != nil {
		return nil, err
	}
	capabilityID, err := wire.CapabilityID(&descriptor.BootstrapTunnelCapability.Body)
	if err != nil || capabilityID != descriptor.BootstrapTunnelCapability.CapabilityID {
		return nil, errors.New("[Android] bootstrap capability ID 无效")
	}
	if err := wire.ValidatePrivateEnrollmentServiceRef(&descriptor.EnrollmentServiceRef); err != nil {
		return nil, err
	}
	serviceHash, _ := wire.PrivateEnrollmentServiceRefHash(&descriptor.EnrollmentServiceRef)
	body := descriptor.BootstrapTunnelCapability.Body
	notBefore, _ := wire.ParseTimeZ(body.NotBefore)
	capabilityExpiry, _ := wire.ParseTimeZ(body.ExpiresAt)
	if body.ClusterID != descriptor.ClusterID || body.InviteID != descriptor.InviteID ||
		body.Mode != "initial_claim" || body.EnrollmentServiceRefHash != serviceHash ||
		body.AllowedServiceID != descriptor.EnrollmentServiceRef.ServiceID ||
		body.AllowedDestinationIP != descriptor.EnrollmentServiceRef.OverlayIP ||
		body.AllowedDestinationPort != descriptor.EnrollmentServiceRef.TCPPort ||
		now.Before(notBefore) || !now.Before(capabilityExpiry) || capabilityExpiry.After(descriptorExpiry) {
		return nil, errors.New("[Android] descriptor/capability/private Enrollment tuple 不匹配")
	}
	for _, hash := range []string{descriptor.ProofBundleHash, descriptor.BootstrapCatalogHash,
		descriptor.TrustedCheckpointHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return nil, err
		}
	}
	return wire.MarshalCanonical(androidMirrorFetchPlanV2{
		Schema: 1, ProofHash: descriptor.ProofBundleHash,
		CatalogHash: descriptor.BootstrapCatalogHash,
		Mirrors:     descriptor.DistributionMirrors,
	})
}

// VerifyAndroidV2InviteProof 返回原 exact bytes，只用作验证边界；
// 运行时不得使用未经此路径的 mirror 响应。
func VerifyAndroidV2InviteProof(descriptorJSON, proofBundleJSON []byte, trustedTime string) ([]byte, error) {
	if _, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime); err != nil {
		return nil, err
	}
	return append([]byte(nil), proofBundleJSON...), nil
}

// VerifyAndroidV2BootstrapCatalog 把 catalog 的 typed hash、有效期、ingress
// binding 和 config QC 绑到同一份已验 Invite lineage。
func VerifyAndroidV2BootstrapCatalog(descriptorJSON, proofBundleJSON, catalogJSON []byte,
	trustedTime string, clientProtocol int64) ([]byte, error) {
	inputs, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	var catalog wire.BootstrapEndpointCatalogV1
	if err := decodeExactAndroidV2(catalogJSON, 16<<20, &catalog, "bootstrap catalog"); err != nil {
		return nil, err
	}
	now, _ := wire.ParseTimeZ(trustedTime)
	if err := wire.ValidateBootstrapEndpointCatalogAt(&catalog, now, clientProtocol); err != nil {
		return nil, err
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(&catalog)
	if err != nil || catalogHash != inputs.descriptor.BootstrapCatalogHash ||
		catalog.ClusterID != inputs.descriptor.ClusterID ||
		catalog.BootstrapIngressSetHash != inputs.descriptor.BootstrapTunnelCapability.Body.AllowedIngressSetHash {
		return nil, errors.New("[Android] descriptor/capability/catalog binding 不匹配")
	}
	head, current, previous, ok := inputs.verified.AuthorityForHead(catalog.ParentHeadHash)
	if !ok || wire.VerifyConfigQCAuthority(catalog.ParentHeadHash,
		catalog.BootstrapIngressSet.ConfigQC, &head, &current, previous) != nil {
		return nil, errors.New("[Android] catalog parent Head/QC 不在已验 Invite lineage")
	}
	return append([]byte(nil), catalogJSON...), nil
}

// PrepareAndroidEnrollmentV2Preflight 只投影不含 token/key/CSR 的 private
// preflight request；所有字段都来自 exact descriptor 与已验证 proof。
func PrepareAndroidEnrollmentV2Preflight(descriptorJSON, proofBundleJSON []byte, trustedTime string) ([]byte, error) {
	inputs, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	request, err := androidEnrollmentPreflightRequestV2(inputs)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(request)
}

// VerifyAndroidEnrollmentV2Preflight 必须在 Android 创建 identity/wrapping key
// 之前调用。它只接受 public commitment 对应的 exact opening 与 android intent。
func VerifyAndroidEnrollmentV2Preflight(descriptorJSON, proofBundleJSON, responseJSON []byte, trustedTime string) ([]byte, error) {
	inputs, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	response, err := verifyAndroidEnrollmentPreflightV2(inputs, responseJSON)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(response.DeviceEnrollmentIntentOpening)
}

// PrepareAndroidEnrollmentV2ClaimCore 在 preflight 已通过后把 Keystore public
// material 固定成 stable core；重试必须复用相同 request/client nonce/CSR/key。
func PrepareAndroidEnrollmentV2ClaimCore(descriptorJSON, proofBundleJSON, responseJSON []byte,
	requestID string, identitySPKIDER, csrDER, wrappingSPKIDER []byte,
	wrappingProfile string, clientNonce []byte, trustedTime string) ([]byte, error) {
	inputs, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	preflight, err := verifyAndroidEnrollmentPreflightV2(inputs, responseJSON)
	if err != nil {
		return nil, err
	}
	core, err := buildAndroidEnrollmentClaimCoreV2(inputs, preflight, requestID,
		identitySPKIDER, csrDER, wrappingSPKIDER, wrappingProfile, clientNonce)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(core)
}

func buildAndroidEnrollmentClaimCoreV2(inputs androidEnrollmentInputsV2,
	preflight wire.EnrollmentIntentPreflightResponseV1, requestID string,
	identitySPKIDER, csrDER, wrappingSPKIDER []byte, wrappingProfile string,
	clientNonce []byte) (wire.EnrollmentClaimCoreV2, error) {
	if len(clientNonce) != 32 {
		return wire.EnrollmentClaimCoreV2{}, errors.New("[Android] client nonce 必须是 32 bytes")
	}
	opening := &preflight.DeviceEnrollmentIntentOpening
	openingHash, _ := wire.IntentOpeningHash(opening)
	intentHash, _ := wire.EnrollmentIntentHash(&opening.DeviceEnrollmentIntent)
	setHash, _ := wire.ControlSetHash(&inputs.set)
	core := wire.EnrollmentClaimCoreV2{
		Schema: 2, ClusterID: inputs.descriptor.ClusterID, InviteID: inputs.descriptor.InviteID,
		RequestID: requestID, CertifiedInviteRecordHash: inputs.recordHash,
		DeviceEnrollmentIntentCommitmentHash: inputs.bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    openingHash, AcceptedDeviceEnrollmentIntentHash: intentHash,
		ClientPlatform: "android", BaseRecoveryEpoch: inputs.head.Body.Payload.RecoveryEpoch,
		BaseControlEpoch: inputs.head.Body.Payload.ControlEpoch, BaseControlSetHash: setHash,
		BaseHeadHash:             inputs.head.HeadHash,
		DeviceIdentityPublicKey:  base64.RawURLEncoding.EncodeToString(identitySPKIDER),
		DeviceIdentityKeyProfile: "p256-android-keystore-sha256-v1",
		WrappingPublicKey:        base64.RawURLEncoding.EncodeToString(wrappingSPKIDER),
		WrappingKeyProfile:       wrappingProfile, CSRDER: base64.RawURLEncoding.EncodeToString(csrDER),
		ClientNonce: base64.RawURLEncoding.EncodeToString(clientNonce),
	}
	if err := validateAndroidEnrollmentClaimCoreV2(inputs, preflight, &core); err != nil {
		return wire.EnrollmentClaimCoreV2{}, err
	}
	return core, nil
}

// PrepareAndroidEnrollmentV2PoPBody 重验 stable core 与 fresh server challenge，
// 返回给 Keystore callback 的唯一 canonical PoP body。
func PrepareAndroidEnrollmentV2PoPBody(descriptorJSON, proofBundleJSON, responseJSON,
	claimCoreJSON, challengeJSON []byte, trustedTime string) ([]byte, error) {
	inputs, preflight, core, _, coreHash, challengeHash, err :=
		loadAndroidEnrollmentAttemptV2(descriptorJSON, proofBundleJSON, responseJSON,
			claimCoreJSON, challengeJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	pop := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: inputs.descriptor.ClusterID, InviteID: inputs.descriptor.InviteID,
		RequestID: core.RequestID, ClaimCoreHash: coreHash,
		TokenCommitment: inputs.bundle.CertifiedInviteRecord.TokenCommitment,
		ChallengeHash:   challengeHash,
	}
	if err := validateAndroidEnrollmentClaimCoreV2(inputs, preflight, &core); err != nil {
		return nil, err
	}
	if _, err := wire.EnrollmentPoPMessage(&pop); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(pop)
}

// AssembleAndroidEnrollmentV2ClaimSubmission 在 token 被发送前执行与
// server voter 同义的完整本地验证，包括 Keystore low-S PoP。
func AssembleAndroidEnrollmentV2ClaimSubmission(descriptorJSON, proofBundleJSON, responseJSON,
	claimCoreJSON, challengeJSON, popBodyJSON []byte, proofSignature, trustedTime string) ([]byte, error) {
	inputs, preflight, core, challenge, _, _, err :=
		loadAndroidEnrollmentAttemptV2(descriptorJSON, proofBundleJSON, responseJSON,
			claimCoreJSON, challengeJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	if err := validateAndroidEnrollmentClaimCoreV2(inputs, preflight, &core); err != nil {
		return nil, err
	}
	var pop wire.EnrollmentPoPBodyV2
	if err := decodeExactAndroidV2(popBodyJSON, 1<<20, &pop, "Enrollment PoP body"); err != nil {
		return nil, err
	}
	result := wire.EnrollmentClaimSubmissionV2{
		Schema: 2, Token: inputs.descriptor.Token, ClaimCore: core,
		Challenge: challenge, PoPBody: pop, ProofSignature: proofSignature,
	}
	now, _ := wire.ParseTimeZ(trustedTime)
	if _, err := wire.VerifyEnrollmentClaimSubmission(&result,
		&inputs.bundle.CertifiedInviteRecord, &inputs.bundle.InviteIssuancePolicy,
		&preflight.DeviceEnrollmentIntentOpening, inputs.descriptor.EnrollmentServiceRef.ServiceID, now); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(result)
}

func loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON []byte, trustedTime string) (androidEnrollmentInputsV2, error) {
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return androidEnrollmentInputsV2{}, errors.New("[Android] Enrollment trusted time 无效")
	}
	var descriptor wire.InviteBootstrapDescriptorV2
	if err := decodeExactAndroidV2(descriptorJSON, 8<<20, &descriptor, "Invite descriptor"); err != nil {
		return androidEnrollmentInputsV2{}, err
	}
	var bundle wire.InviteProofBundleV2
	if err := decodeExactAndroidV2(proofBundleJSON, 32<<20, &bundle, "Invite proof bundle"); err != nil {
		return androidEnrollmentInputsV2{}, err
	}
	verified, err := wire.VerifyInviteProofBundle(&bundle, &descriptor, now, wire.InviteProofTrustV2{})
	if err != nil {
		return androidEnrollmentInputsV2{}, err
	}
	recordHash, err := wire.CertifiedInviteRecordHash(&bundle.CertifiedInviteRecord, &bundle.InviteIssuancePolicy)
	head, set := verified.Head(), verified.ControlSet()
	setHash, setErr := wire.ControlSetHash(&set)
	if err != nil || setErr != nil || recordHash != verified.CertifiedInviteRecordHash() ||
		head.Body.Payload.ControlSetHash != setHash || !wire.EqualCanonical(head, bundle.RecordHead) {
		return androidEnrollmentInputsV2{}, errors.New("[Android] proof evidence 与 record authority 不匹配")
	}
	return androidEnrollmentInputsV2{
		descriptor: descriptor, bundle: bundle, recordHash: recordHash, head: head, set: set,
		verified: verified,
	}, nil
}

func androidEnrollmentPreflightRequestV2(inputs androidEnrollmentInputsV2) (wire.EnrollmentIntentPreflightRequestV1, error) {
	return wire.AuthorizeInitialEnrollmentPreflight(wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: inputs.descriptor.ClusterID, InviteID: inputs.descriptor.InviteID,
		CertifiedInviteRecordHash: inputs.recordHash,
		CapabilityID:              inputs.descriptor.BootstrapTunnelCapability.CapabilityID,
	}, inputs.descriptor.Token)
}

func verifyAndroidEnrollmentPreflightV2(inputs androidEnrollmentInputsV2, responseJSON []byte) (wire.EnrollmentIntentPreflightResponseV1, error) {
	var response wire.EnrollmentIntentPreflightResponseV1
	if err := decodeExactAndroidV2(responseJSON, 8<<20, &response, "Enrollment preflight response"); err != nil {
		return response, err
	}
	request, err := androidEnrollmentPreflightRequestV2(inputs)
	if err != nil {
		return response, err
	}
	expected := inputs.bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash
	if err := wire.VerifyEnrollmentIntentPreflight(&response, &request, expected); err != nil {
		return response, err
	}
	if response.DeviceEnrollmentIntentOpening.DeviceEnrollmentIntent.Platform != "android" ||
		!wire.EqualCanonical(response.DeviceEnrollmentIntentCommitment,
			inputs.bundle.DeviceEnrollmentIntentCommitment) {
		return response, errors.New("[Android] preflight intent/platform 与 certified Invite 不匹配")
	}
	return response, nil
}

func validateAndroidEnrollmentClaimCoreV2(inputs androidEnrollmentInputsV2,
	preflight wire.EnrollmentIntentPreflightResponseV1, core *wire.EnrollmentClaimCoreV2) error {
	if core == nil {
		return errors.New("[Android] stable claim core 缺失")
	}
	if _, err := wire.EnrollmentClaimCoreHash(core); err != nil {
		return err
	}
	opening := &preflight.DeviceEnrollmentIntentOpening
	openingHash, _ := wire.IntentOpeningHash(opening)
	intentHash, _ := wire.EnrollmentIntentHash(&opening.DeviceEnrollmentIntent)
	setHash, _ := wire.ControlSetHash(&inputs.set)
	if core.ClusterID != inputs.descriptor.ClusterID || core.InviteID != inputs.descriptor.InviteID ||
		core.CertifiedInviteRecordHash != inputs.recordHash ||
		core.DeviceEnrollmentIntentCommitmentHash != inputs.bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash ||
		core.DeviceEnrollmentIntentOpeningHash != openingHash || core.AcceptedDeviceEnrollmentIntentHash != intentHash ||
		core.ClientPlatform != "android" || core.BaseRecoveryEpoch != inputs.head.Body.Payload.RecoveryEpoch ||
		core.BaseControlEpoch != inputs.head.Body.Payload.ControlEpoch || core.BaseControlSetHash != setHash ||
		core.BaseHeadHash != inputs.head.HeadHash || !containsAndroidV2(
		opening.DeviceEnrollmentIntent.WrappingKeyProfiles, core.WrappingKeyProfile) {
		return errors.New("[Android] stable claim core 与 verified record/opening/authority 不匹配")
	}
	return nil
}

func loadAndroidEnrollmentAttemptV2(descriptorJSON, proofBundleJSON, responseJSON,
	claimCoreJSON, challengeJSON []byte, trustedTime string) (androidEnrollmentInputsV2,
	wire.EnrollmentIntentPreflightResponseV1, wire.EnrollmentClaimCoreV2,
	wire.EnrollmentPoPChallengeV1, string, string, error) {
	inputs, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime)
	if err != nil {
		return androidEnrollmentInputsV2{}, wire.EnrollmentIntentPreflightResponseV1{},
			wire.EnrollmentClaimCoreV2{}, wire.EnrollmentPoPChallengeV1{}, "", "", err
	}
	preflight, err := verifyAndroidEnrollmentPreflightV2(inputs, responseJSON)
	if err != nil {
		return inputs, preflight, wire.EnrollmentClaimCoreV2{}, wire.EnrollmentPoPChallengeV1{}, "", "", err
	}
	var core wire.EnrollmentClaimCoreV2
	if err := decodeExactAndroidV2(claimCoreJSON, 4<<20, &core, "Enrollment claim core"); err != nil {
		return inputs, preflight, core, wire.EnrollmentPoPChallengeV1{}, "", "", err
	}
	if err := validateAndroidEnrollmentClaimCoreV2(inputs, preflight, &core); err != nil {
		return inputs, preflight, core, wire.EnrollmentPoPChallengeV1{}, "", "", err
	}
	var challenge wire.EnrollmentPoPChallengeV1
	if err := decodeExactAndroidV2(challengeJSON, 1<<20, &challenge, "Enrollment challenge"); err != nil {
		return inputs, preflight, core, challenge, "", "", err
	}
	coreHash, _ := wire.EnrollmentClaimCoreHash(&core)
	now, _ := wire.ParseTimeZ(trustedTime)
	challengeHash, err := wire.EnrollmentChallengeHash(&challenge, coreHash, now)
	if err != nil || challenge.ClusterID != core.ClusterID || challenge.InviteID != core.InviteID ||
		challenge.RequestID != core.RequestID || challenge.EnrollmentServiceID != inputs.descriptor.EnrollmentServiceRef.ServiceID {
		if err != nil {
			return inputs, preflight, core, challenge, coreHash, "", err
		}
		return inputs, preflight, core, challenge, coreHash, "",
			errors.New("[Android] challenge 与 stable core/service 不匹配")
	}
	return inputs, preflight, core, challenge, coreHash, challengeHash, nil
}

func containsAndroidV2(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
