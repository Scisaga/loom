package loomcore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const androidV2ResumeURIPrefix = "loom://enroll/resume/v1#d="

type androidEnrollmentResumeInputsV1 struct {
	descriptor wire.EnrollmentResumeDescriptorV1
	bundle     wire.InviteProofBundleV2
	catalog    wire.BootstrapEndpointCatalogV1
	verified   wire.VerifiedInviteProofV2
	recordHash string
	head       wire.HeadEntryV2
	set        wire.ControlSetV1
	core       wire.EnrollmentClaimCoreV2
	status     string
	expected   wire.EnrollmentResumeExpectedV1
}

// DecodeAndroidV2ResumeURI/File 只接受显式带外 carrier；resume schema 没有 token，
// 也不会被当作普通 Invite 自动发现或刷新（D130）。
func DecodeAndroidV2ResumeURI(raw string) ([]byte, error) {
	if len(raw) <= len(androidV2ResumeURIPrefix) || len(raw) > 1800 ||
		!strings.HasPrefix(raw, androidV2ResumeURIPrefix) {
		return nil, errors.New("[D130 Android resume] URI 形状或大小无效")
	}
	for index := range raw {
		if raw[index] < 0x21 || raw[index] > 0x7e {
			return nil, errors.New("[D130 Android resume] URI 必须是无空白 ASCII")
		}
	}
	encoded := strings.TrimPrefix(raw, androidV2ResumeURIPrefix)
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != encoded {
		return nil, errors.New("[D130 Android resume] descriptor carrier 不是 canonical base64url")
	}
	return DecodeAndroidV2ResumeFile(body)
}

func DecodeAndroidV2ResumeFile(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("[D130 Android resume] descriptor 大小无效")
	}
	var descriptor wire.EnrollmentResumeDescriptorV1
	if err := decodeExactAndroidV2(raw, 1<<20, &descriptor, "Enrollment resume descriptor"); err != nil ||
		descriptor.Schema != 1 {
		return nil, errors.New("[D130 Android resume] .loom-resume 必须是 exact canonical descriptor")
	}
	return append([]byte(nil), raw...), nil
}

// PrepareAndroidV2ResumeMirrorFetchPlan 在取得 issuer proof 前，只投影用户带外
// descriptor 明示的 pinned mirrors/content hashes。签名与本机 transaction binding
// 在下载 proof 后由 loadAndroidEnrollmentResumeInputsV1 完成（D115、D130）。
func PrepareAndroidV2ResumeMirrorFetchPlan(descriptorJSON []byte, trustedTime string) ([]byte, error) {
	var descriptor wire.EnrollmentResumeDescriptorV1
	if err := decodeExactAndroidV2(descriptorJSON, 1<<20, &descriptor,
		"Enrollment resume descriptor"); err != nil {
		return nil, err
	}
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, errors.New("[D130 Android resume] trusted time 无效")
	}
	if err := validateAndroidResumeDescriptorUnsigned(&descriptor, now); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(androidMirrorFetchPlanV2{
		Schema: 1, ProofHash: descriptor.ProofBundleHash,
		CatalogHash: descriptor.BootstrapCatalogHash, Mirrors: descriptor.DistributionMirrors,
	})
}

func VerifyAndroidV2ResumeInviteProof(descriptorJSON, proofBundleJSON,
	pinnedPlatformKey []byte, trustedTime string,
) ([]byte, error) {
	var descriptor wire.EnrollmentResumeDescriptorV1
	if err := decodeExactAndroidV2(descriptorJSON, 1<<20, &descriptor,
		"Enrollment resume descriptor"); err != nil {
		return nil, err
	}
	var bundle wire.InviteProofBundleV2
	if err := decodeExactAndroidV2(proofBundleJSON, 32<<20, &bundle,
		"resume Invite proof bundle"); err != nil {
		return nil, err
	}
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, errors.New("[D130 Android resume] trusted time 无效")
	}
	if _, err := verifyAndroidResumeProof(&descriptor, &bundle, pinnedPlatformKey, now); err != nil {
		return nil, err
	}
	return append([]byte(nil), proofBundleJSON...), nil
}

func VerifyAndroidV2ResumeBootstrapCatalog(descriptorJSON, proofBundleJSON, catalogJSON,
	pinnedPlatformKey []byte, trustedTime string, clientProtocol int64,
) ([]byte, error) {
	var descriptor wire.EnrollmentResumeDescriptorV1
	if err := decodeExactAndroidV2(descriptorJSON, 1<<20, &descriptor,
		"Enrollment resume descriptor"); err != nil {
		return nil, err
	}
	var bundle wire.InviteProofBundleV2
	if err := decodeExactAndroidV2(proofBundleJSON, 32<<20, &bundle,
		"resume Invite proof bundle"); err != nil {
		return nil, err
	}
	var catalog wire.BootstrapEndpointCatalogV1
	if err := decodeExactAndroidV2(catalogJSON, 16<<20, &catalog, "resume bootstrap catalog"); err != nil {
		return nil, err
	}
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, errors.New("[D130 Android resume] trusted time 无效")
	}
	verified, err := verifyAndroidResumeProof(&descriptor, &bundle, pinnedPlatformKey, now)
	if err != nil {
		return nil, err
	}
	if err := verifyAndroidResumeCatalog(&descriptor, &bundle, &catalog, verified, now, clientProtocol); err != nil {
		return nil, err
	}
	return append([]byte(nil), catalogJSON...), nil
}

// ValidateAndroidV2ResumeInputs 是宿主写入 EncryptedStore 前的完整边界：除公开
// proof/catalog 外，还必须绑定本机已验 stable core 与 progress floor（D115、D130）。
func ValidateAndroidV2ResumeInputs(descriptorJSON, proofBundleJSON, catalogJSON,
	claimCoreJSON, resumeExpectedJSON, pinnedPlatformKey []byte, progressStatus, trustedTime string,
) error {
	_, err := loadAndroidEnrollmentResumeInputsV1(
		descriptorJSON, proofBundleJSON, catalogJSON, claimCoreJSON, resumeExpectedJSON,
		pinnedPlatformKey, progressStatus, trustedTime,
	)
	return err
}

func ValidateAndroidV2PendingProgress(claimCoreJSON []byte, status string,
	resumeExpectedJSON []byte,
) error {
	core, expected, err := decodeAndroidPendingProgress(claimCoreJSON, status, resumeExpectedJSON)
	if err != nil {
		return err
	}
	return validateAndroidPendingProgress(&core, status, &expected)
}

// AdvanceAndroidV2PendingProgress 只允许 exact replay 或
// reserved→issued_provisional→completed 的单调推进，稳定 binding 不得被旧
// ingress 响应改写（D130）。
func AdvanceAndroidV2PendingProgress(claimCoreJSON []byte, previousStatus string,
	previousExpectedJSON []byte, candidateStatus string, candidateExpectedJSON []byte,
) error {
	core, previous, err := decodeAndroidPendingProgress(claimCoreJSON, previousStatus, previousExpectedJSON)
	if err != nil {
		return err
	}
	if err := validateAndroidPendingProgress(&core, previousStatus, &previous); err != nil {
		return err
	}
	_, candidate, err := decodeAndroidPendingProgress(claimCoreJSON, candidateStatus, candidateExpectedJSON)
	if err != nil {
		return err
	}
	if err := validateAndroidPendingProgress(&core, candidateStatus, &candidate); err != nil {
		return err
	}
	if previousStatus == candidateStatus && wire.EqualCanonical(previous, candidate) {
		return nil
	}
	oldStable, nextStable := previous, candidate
	oldStable.EnrollmentTransactionStateHash = ""
	nextStable.EnrollmentTransactionStateHash = ""
	allowed := previousStatus == "reserved" &&
		(candidateStatus == "issued_provisional" || candidateStatus == "completed") ||
		previousStatus == "issued_provisional" && candidateStatus == "completed"
	if !allowed ||
		!wire.EqualCanonical(oldStable, nextStable) {
		return errors.New("[D130 Android] pending progress 回退、分叉或改写 stable binding")
	}
	return nil
}

func loadAndroidEnrollmentResumeInputsV1(descriptorJSON, proofBundleJSON, catalogJSON,
	claimCoreJSON, resumeExpectedJSON, pinnedPlatformKey []byte, progressStatus, trustedTime string,
) (androidEnrollmentResumeInputsV1, error) {
	var result androidEnrollmentResumeInputsV1
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return result, errors.New("[D130 Android resume] trusted time 无效")
	}
	if err := decodeExactAndroidV2(descriptorJSON, 1<<20, &result.descriptor,
		"Enrollment resume descriptor"); err != nil {
		return result, err
	}
	if err := decodeExactAndroidV2(proofBundleJSON, 32<<20, &result.bundle,
		"resume Invite proof bundle"); err != nil {
		return result, err
	}
	if err := decodeExactAndroidV2(catalogJSON, 16<<20, &result.catalog,
		"resume bootstrap catalog"); err != nil {
		return result, err
	}
	if err := decodeExactAndroidV2(claimCoreJSON, 4<<20, &result.core,
		"pending Enrollment claim core"); err != nil {
		return result, err
	}
	if err := decodeExactAndroidV2(resumeExpectedJSON, 1<<20, &result.expected,
		"pending resume expected"); err != nil {
		return result, err
	}
	result.status = progressStatus
	if err := validateAndroidPendingProgress(&result.core, result.status, &result.expected); err != nil {
		return result, err
	}
	result.verified, err = verifyAndroidResumeProof(
		&result.descriptor, &result.bundle, pinnedPlatformKey, now,
	)
	if err != nil {
		return result, err
	}
	if err := verifyAndroidResumeCatalog(&result.descriptor, &result.bundle, &result.catalog,
		result.verified, now, androidBootstrapClientProtocol); err != nil {
		return result, err
	}
	result.recordHash, _ = wire.CertifiedInviteRecordHash(
		&result.bundle.CertifiedInviteRecord, &result.bundle.InviteIssuancePolicy,
	)
	result.head, result.set = result.verified.Head(), result.verified.ControlSet()
	setHash, err := wire.ControlSetHash(&result.set)
	if err != nil || result.core.ClusterID != result.descriptor.ClusterID ||
		result.core.InviteID != result.descriptor.InviteID || result.core.RequestID != result.descriptor.RequestID ||
		result.core.CertifiedInviteRecordHash != result.recordHash ||
		result.core.DeviceEnrollmentIntentCommitmentHash !=
			result.bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash ||
		result.core.BaseHeadHash != result.head.HeadHash ||
		result.core.BaseRecoveryEpoch != result.head.Body.Payload.RecoveryEpoch ||
		result.core.BaseControlEpoch != result.head.Body.Payload.ControlEpoch ||
		result.core.BaseControlSetHash != setHash || result.core.ClientPlatform != "android" {
		return result, errors.New("[D130 Android resume] pending core 未绑定 exact Invite authority")
	}
	if err := wire.VerifyEnrollmentResumeDescriptorBindings(&result.descriptor, result.expected,
		&result.catalog, &result.bundle.BootstrapIssuerAuthorizationProof,
		&result.bundle.InviteIssuancePolicy, now, androidBootstrapClientProtocol); err != nil {
		return result, err
	}
	return result, nil
}

func androidEnrollmentResumePreflightRequest(inputs androidEnrollmentResumeInputsV1) wire.EnrollmentIntentPreflightRequestV1 {
	return wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: inputs.core.ClusterID, InviteID: inputs.core.InviteID,
		CertifiedInviteRecordHash: inputs.recordHash,
		CapabilityID:              inputs.descriptor.ResumeTunnelCapability.CapabilityID,
		Authorization:             wire.EnrollmentPreflightAuthorizationV1{Mode: "identity_p256_sha256", IdentityPublicKey: inputs.core.DeviceIdentityPublicKey},
	}
}

func verifyAndroidEnrollmentResumePreflight(inputs androidEnrollmentResumeInputsV1,
	request wire.EnrollmentIntentPreflightRequestV1, body []byte,
) (wire.EnrollmentIntentPreflightResponseV1, error) {
	var response wire.EnrollmentIntentPreflightResponseV1
	if err := decodeExactAndroidV2(body, 4<<20, &response,
		"resume Enrollment preflight response"); err != nil {
		return response, err
	}
	expected := androidEnrollmentResumePreflightRequest(inputs)
	expected.Authorization.ProofSignature = request.Authorization.ProofSignature
	if !wire.EqualCanonical(expected, request) || wire.VerifyResumeEnrollmentPreflight(&request, inputs.expected.IdentityKeyHash) != nil {
		return response, errors.New("[D130 Android resume] preflight 未绑定原设备签名")
	}
	commitmentHash := inputs.bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash
	if err := wire.VerifyEnrollmentIntentPreflight(&response, &request, commitmentHash); err != nil {
		return response, err
	}
	opening := &response.DeviceEnrollmentIntentOpening
	openingHash, err := wire.IntentOpeningHash(opening)
	intentHash, intentErr := wire.EnrollmentIntentHash(&opening.DeviceEnrollmentIntent)
	if err != nil || intentErr != nil || opening.DeviceEnrollmentIntent.Platform != "android" ||
		openingHash != inputs.core.DeviceEnrollmentIntentOpeningHash ||
		intentHash != inputs.core.AcceptedDeviceEnrollmentIntentHash ||
		!wire.EqualCanonical(response.DeviceEnrollmentIntentCommitment,
			inputs.bundle.DeviceEnrollmentIntentCommitment) {
		return response, errors.New("[D130 Android resume] preflight 未恢复 exact committed opening")
	}
	return response, nil
}

func androidResumeProgressExpected(inputs androidEnrollmentResumeInputsV1,
	preflight wire.EnrollmentIntentPreflightResponseV1,
) enrollmentv2.EnrollmentProgressExpectedV1 {
	return enrollmentv2.EnrollmentProgressExpectedV1{
		Record: inputs.bundle.CertifiedInviteRecord, Policy: inputs.bundle.InviteIssuancePolicy,
		Opening: preflight.DeviceEnrollmentIntentOpening, ClaimCore: inputs.core,
		BaseHead: inputs.head, BaseControlSet: inputs.set,
	}
}

func validateAndroidResumeDescriptorUnsigned(descriptor *wire.EnrollmentResumeDescriptorV1,
	now time.Time,
) error {
	if descriptor == nil || descriptor.Schema != 1 || descriptor.ClusterID == "" ||
		descriptor.InviteID == "" || descriptor.RequestID == "" {
		return errors.New("[D130 Android resume] descriptor identity 无效")
	}
	if err := wire.ValidateCapabilityBody(&descriptor.ResumeTunnelCapability.Body); err != nil {
		return err
	}
	capabilityID, err := wire.CapabilityID(&descriptor.ResumeTunnelCapability.Body)
	if err != nil || capabilityID != descriptor.ResumeTunnelCapability.CapabilityID {
		return errors.New("[D130 Android resume] capability ID 无效")
	}
	body := &descriptor.ResumeTunnelCapability.Body
	binding := body.ResumeBinding
	serviceHash, serviceErr := wire.PrivateEnrollmentServiceRefHash(&descriptor.EnrollmentServiceRef)
	descriptorExpiry, expiryErr := wire.ParseTimeZ(descriptor.ExpiresAt)
	notBefore, notBeforeErr := wire.ParseTimeZ(body.NotBefore)
	capabilityExpiry, capabilityExpiryErr := wire.ParseTimeZ(body.ExpiresAt)
	if binding == nil || serviceErr != nil || expiryErr != nil || notBeforeErr != nil || capabilityExpiryErr != nil ||
		body.Mode != "resume_committed_claim" || body.ClusterID != descriptor.ClusterID ||
		body.InviteID != descriptor.InviteID || binding.RequestID != descriptor.RequestID ||
		body.EnrollmentServiceRefHash != serviceHash || body.AllowedServiceID != descriptor.EnrollmentServiceRef.ServiceID ||
		body.AllowedDestinationIP != descriptor.EnrollmentServiceRef.OverlayIP ||
		body.AllowedDestinationPort != descriptor.EnrollmentServiceRef.TCPPort ||
		descriptor.ClaimCoreHash != binding.ClaimCoreHash || descriptor.ClaimOperationHash != binding.ClaimOperationHash ||
		descriptor.AdmissionQCHash != binding.AdmissionQCHash ||
		descriptor.EnrollmentTransactionStateHash != binding.EnrollmentTransactionStateHash ||
		now.Before(notBefore) || !now.Before(descriptorExpiry) || descriptorExpiry.After(capabilityExpiry) {
		return errors.New("[D130 Android resume] descriptor/capability/transaction tuple 无效或已过期")
	}
	for _, hash := range []string{descriptor.ClaimCoreHash, descriptor.ClaimOperationHash,
		descriptor.AdmissionQCHash, descriptor.EnrollmentTransactionStateHash,
		descriptor.BootstrapCatalogHash, descriptor.ProofBundleHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	return wire.ValidateDistributionMirrorRefs(descriptor.DistributionMirrors)
}

func verifyAndroidResumeProof(descriptor *wire.EnrollmentResumeDescriptorV1,
	bundle *wire.InviteProofBundleV2, pinnedPlatformKey []byte, now time.Time,
) (wire.VerifiedInviteProofV2, error) {
	if len(pinnedPlatformKey) != ed25519.PublicKeySize {
		return wire.VerifiedInviteProofV2{}, errors.New("[D130 Android resume] APK platform trust root 长度无效")
	}
	if err := validateAndroidResumeDescriptorUnsigned(descriptor, now); err != nil {
		return wire.VerifiedInviteProofV2{}, err
	}
	digest := sha256.Sum256(pinnedPlatformKey)
	trust := wire.InviteProofTrustV2{
		V1PlatformKey:           append(ed25519.PublicKey(nil), pinnedPlatformKey...),
		V1PlatformKeyID:         bundle.PlatformKeyID(),
		V1MigrationAnchorDigest: fmt.Sprintf("sha256:%x", digest[:]),
	}
	return wire.VerifyResumeInviteProofBundle(bundle, descriptor, now, trust)
}

func verifyAndroidResumeCatalog(descriptor *wire.EnrollmentResumeDescriptorV1,
	bundle *wire.InviteProofBundleV2, catalog *wire.BootstrapEndpointCatalogV1,
	verified wire.VerifiedInviteProofV2, now time.Time, clientProtocol int64,
) error {
	if clientProtocol < 1 {
		return errors.New("[D130 Android resume] client protocol 无效")
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(catalog)
	if err != nil || catalogHash != descriptor.BootstrapCatalogHash ||
		wire.ValidateBootstrapEndpointCatalogAt(catalog, now, clientProtocol) != nil ||
		catalog.BootstrapIngressSetHash != descriptor.ResumeTunnelCapability.Body.AllowedIngressSetHash ||
		bundle.BootstrapCatalogHash != descriptor.BootstrapCatalogHash {
		return errors.New("[D130 Android resume] catalog/hash/ingress binding 无效")
	}
	head, set, previous, ok := verified.AuthorityForHead(catalog.ParentHeadHash)
	if !ok || wire.VerifyConfigQCAuthority(catalog.ParentHeadHash,
		catalog.BootstrapIngressSet.ConfigQC, &head, &set, previous) != nil {
		return errors.New("[D130 Android resume] catalog QC authority 未通过 Invite lineage")
	}
	return nil
}

func decodeAndroidPendingProgress(claimCoreJSON []byte, status string,
	resumeExpectedJSON []byte,
) (wire.EnrollmentClaimCoreV2, wire.EnrollmentResumeExpectedV1, error) {
	var core wire.EnrollmentClaimCoreV2
	if err := decodeExactAndroidV2(claimCoreJSON, 4<<20, &core, "pending claim core"); err != nil {
		return core, wire.EnrollmentResumeExpectedV1{}, err
	}
	var expected wire.EnrollmentResumeExpectedV1
	if err := decodeExactAndroidV2(resumeExpectedJSON, 1<<20, &expected,
		"pending resume expected"); err != nil {
		return core, expected, err
	}
	return core, expected, nil
}

func validateAndroidPendingProgress(core *wire.EnrollmentClaimCoreV2, status string,
	expected *wire.EnrollmentResumeExpectedV1,
) error {
	if core == nil || expected == nil ||
		(status != "reserved" && status != "issued_provisional" && status != "completed") {
		return errors.New("[D130 Android] pending progress header 无效")
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(core)
	if err != nil || expected.ClusterID != core.ClusterID || expected.InviteID != core.InviteID ||
		expected.RequestID != core.RequestID || expected.ClaimCoreHash != coreHash {
		return errors.New("[D130 Android] pending progress/core binding 无效")
	}
	identityHash, wrappingHash, csrHash, err := wire.EnrollmentClaimBinaryHashes(core)
	if err != nil || expected.IdentityKeyHash != identityHash || expected.WrappingKeyHash != wrappingHash ||
		expected.CSRHash != csrHash {
		return errors.New("[D130 Android] pending progress identity/wrapping/CSR binding 无效")
	}
	for _, hash := range []string{expected.ClaimOperationHash, expected.AdmissionQCHash,
		expected.EnrollmentTransactionStateHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	if _, err := wire.ParseTimeZ(expected.RetryNotAfter); err != nil {
		return err
	}
	return nil
}
