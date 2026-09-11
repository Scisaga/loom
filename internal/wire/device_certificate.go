package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	DomainDeviceCertificateProfileIntent = "loom-device-certificate-profile-intent-v1"
	DomainDeviceCertificateProfileState  = "loom-device-certificate-profile-state-v1"
	DomainDeviceIssuerCertificateDER     = "loom-device-issuer-certificate-der-v1"
	DomainDeviceIssuerChain              = "loom-device-issuer-chain-v1"
	DomainDeviceCertificateDER           = "loom-device-certificate-der-v1"
)

type IssuanceLogCoordinateV1 struct {
	RecoveryEpoch int64 `json:"recovery_epoch"`
	RaftIndex     int64 `json:"raft_index"`
}

type DeviceCertificateProfileIntentV1 struct {
	Schema                           int      `json:"schema"`
	ClusterID                        string   `json:"cluster_id"`
	ProfileID                        string   `json:"profile_id"`
	Generation                       int64    `json:"generation"`
	ExpectedPreviousProfileStateHash string   `json:"expected_previous_profile_state_hash,omitempty"`
	TargetStatus                     string   `json:"target_status"`
	IssuerID                         string   `json:"issuer_id"`
	IssuerGeneration                 int64    `json:"issuer_generation"`
	IssuerFencingEpoch               int64    `json:"issuer_fencing_epoch"`
	IssuanceNotBefore                string   `json:"issuance_not_before"`
	IssuanceNotAfter                 string   `json:"issuance_not_after"`
	RevocationReason                 string   `json:"revocation_reason,omitempty"`
	ProfileKind                      string   `json:"profile_kind"`
	IssuerCertificateDER             string   `json:"issuer_certificate_der"`
	IssuerCertificateHash            string   `json:"issuer_certificate_hash"`
	IssuerChainDER                   []string `json:"issuer_chain_der"`
	IssuerChainHash                  string   `json:"issuer_chain_hash"`
	IssuerKeyArtifactHash            string   `json:"issuer_key_artifact_hash"`
	AllowedPlatforms                 []string `json:"allowed_platforms"`
	AllowedResponsibilities          []string `json:"allowed_responsibilities"`
	ValiditySeconds                  int64    `json:"validity_seconds"`
	AllowedSubjectKeyAlgorithm       string   `json:"allowed_subject_key_algorithm"`
	SignatureAlgorithm               string   `json:"signature_algorithm"`
	SubjectMode                      string   `json:"subject_mode"`
	SANURIPrefix                     string   `json:"san_uri_prefix"`
	KeyUsageBits                     []string `json:"key_usage_bits"`
	BasicConstraintsCA               bool     `json:"basic_constraints_ca"`
	RequiredEKUOIDs                  []string `json:"required_eku_oids"`
	RequiredPolicyOIDs               []string `json:"required_policy_oids"`
	ExtensionOrderOIDs               []string `json:"extension_order_oids"`
}

type DeviceCertificateProfileStateV1 struct {
	Schema                             int                              `json:"schema"`
	ClusterID                          string                           `json:"cluster_id"`
	ProfileID                          string                           `json:"profile_id"`
	Generation                         int64                            `json:"generation"`
	ProfileIntent                      DeviceCertificateProfileIntentV1 `json:"profile_intent"`
	DeviceCertificateProfileIntentHash string                           `json:"device_certificate_profile_intent_hash"`
	Status                             string                           `json:"status"`
	StatusChangedAt                    string                           `json:"status_changed_at"`
	IssuanceCutoff                     *IssuanceLogCoordinateV1         `json:"issuance_cutoff,omitempty"`
}

func ValidateDeviceCertificateProfileIntent(intent *DeviceCertificateProfileIntentV1) error {
	if intent == nil || intent.Schema != 1 || !validIdentifier(intent.ClusterID, 128) ||
		!validIdentifier(intent.ProfileID, 128) || !validIdentifier(intent.IssuerID, 128) ||
		intent.Generation < 1 || intent.IssuerGeneration < 1 || intent.IssuerFencingEpoch < 1 ||
		!oneOf(intent.TargetStatus, "staged", "active", "retired", "revoked") ||
		intent.ProfileKind != "loom-device-x509-v1" || intent.ValiditySeconds < 1 ||
		intent.ValiditySeconds > math.MaxInt64/int64(time.Second) ||
		intent.AllowedSubjectKeyAlgorithm != "p256" || intent.SignatureAlgorithm != "ed25519" ||
		intent.SubjectMode != "empty" || intent.BasicConstraintsCA ||
		!sortedEnum(intent.AllowedPlatforms, []string{"windows-desktop", "android", "linux-server"}, true) ||
		!sortedEnum(intent.AllowedResponsibilities, []string{"use_loom", "forward", "internet_egress"}, true) ||
		!sortedEnum(intent.KeyUsageBits, []string{"digital_signature", "key_encipherment", "key_agreement"}, true) ||
		!contains(intent.KeyUsageBits, "digital_signature") || !sortedOIDStrings(intent.RequiredEKUOIDs) ||
		!contains(intent.RequiredEKUOIDs, "1.3.6.1.5.5.7.3.2") ||
		!sortedOIDStrings(intent.RequiredPolicyOIDs) || len(intent.RequiredPolicyOIDs) == 0 ||
		!validOIDSequence(intent.ExtensionOrderOIDs) ||
		!containsAll(intent.ExtensionOrderOIDs, "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.32", "2.5.29.37") {
		return errors.New("[D102 Device CA] Device certificate profile intent 无效")
	}
	if (intent.Generation == 1) != (intent.ExpectedPreviousProfileStateHash == "") {
		return errors.New("[D102 Device CA] profile generation/previous hash 无效")
	}
	if intent.ExpectedPreviousProfileStateHash != "" {
		if _, err := ParseHash(intent.ExpectedPreviousProfileStateHash); err != nil {
			return err
		}
	}
	if intent.TargetStatus == "revoked" {
		if !oneOf(intent.RevocationReason, "issuer_compromise", "administrative") {
			return errors.New("[D102 Device CA] revoked profile 缺规范原因")
		}
	} else if intent.RevocationReason != "" {
		return errors.New("[D102 Device CA] 非 revoked profile 禁止 revocation reason")
	}
	from, err := ParseTimeZ(intent.IssuanceNotBefore)
	if err != nil {
		return err
	}
	until, err := ParseTimeZ(intent.IssuanceNotAfter)
	if err != nil || !from.Before(until) {
		return errors.New("[D102 Device CA] issuance window 无效")
	}
	parsedPrefix, err := url.Parse(intent.SANURIPrefix)
	if err != nil || parsedPrefix.Scheme == "" || parsedPrefix.Host == "" || parsedPrefix.RawQuery != "" ||
		parsedPrefix.Fragment != "" || !strings.HasSuffix(intent.SANURIPrefix, "/") || parsedPrefix.String() != intent.SANURIPrefix {
		return errors.New("[D102 Device CA] SAN URI prefix 必须是规范 absolute URI directory")
	}
	for _, hash := range []string{intent.IssuerCertificateHash, intent.IssuerChainHash, intent.IssuerKeyArtifactHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	certificates, err := parseDeviceIssuerChain(intent)
	if err != nil {
		return err
	}
	latestNotAfter := until.Add(time.Duration(intent.ValiditySeconds) * time.Second)
	if !latestNotAfter.After(until) {
		return errors.New("[D102 Device CA] leaf validity 上界溢出")
	}
	for _, certificate := range certificates {
		if certificate.NotBefore.After(from) || certificate.NotAfter.Before(latestNotAfter) {
			return errors.New("[D102 Device CA] issuer chain 未覆盖完整 issuance/leaf validity window")
		}
	}
	return nil
}

func DeviceCertificateProfileIntentHash(intent *DeviceCertificateProfileIntentV1) (string, error) {
	if err := ValidateDeviceCertificateProfileIntent(intent); err != nil {
		return "", err
	}
	return HashObject(DomainDeviceCertificateProfileIntent, intent)
}

func ValidateDeviceCertificateProfileState(state *DeviceCertificateProfileStateV1) error {
	if state == nil || state.Schema != 1 || state.ClusterID != state.ProfileIntent.ClusterID ||
		state.ProfileID != state.ProfileIntent.ProfileID || state.Generation != state.ProfileIntent.Generation ||
		state.Status != state.ProfileIntent.TargetStatus {
		return errors.New("[D102 Device CA] profile state identity/status 无效")
	}
	if err := ValidateDeviceCertificateProfileIntent(&state.ProfileIntent); err != nil {
		return err
	}
	intentHash, _ := DeviceCertificateProfileIntentHash(&state.ProfileIntent)
	if state.DeviceCertificateProfileIntentHash != intentHash {
		return errors.New("[D102 Device CA] profile state 未绑定 exact intent")
	}
	if _, err := ParseTimeZ(state.StatusChangedAt); err != nil {
		return err
	}
	terminal := oneOf(state.Status, "retired", "revoked")
	if terminal != (state.IssuanceCutoff != nil) {
		return errors.New("[D102 Device CA] terminal profile/cutoff tagged union 无效")
	}
	if state.IssuanceCutoff != nil && (state.IssuanceCutoff.RecoveryEpoch < 0 || state.IssuanceCutoff.RaftIndex < 0) {
		return errors.New("[D102 Device CA] issuance cutoff 坐标无效")
	}
	return nil
}

func DeviceCertificateProfileStateHash(state *DeviceCertificateProfileStateV1) (string, error) {
	if err := ValidateDeviceCertificateProfileState(state); err != nil {
		return "", err
	}
	return HashObject(DomainDeviceCertificateProfileState, state)
}

// ReduceDeviceCertificateProfile 用 candidate Head 的认证逻辑时间与 Raft 坐标派生 state；
// admin intent 不携这些不可预知字段。bootstrapActive 只允许 ceremony 创建首代 active（D102）。
func ReduceDeviceCertificateProfile(previous *DeviceCertificateProfileStateV1,
	intent DeviceCertificateProfileIntentV1, head *HeadEntryV2, bootstrapActive bool) (DeviceCertificateProfileStateV1, error) {
	if head == nil || ValidateHeadEntry(head, nil) != nil || head.Body.Payload.ClusterID != intent.ClusterID {
		return DeviceCertificateProfileStateV1{}, errors.New("[D102 Device CA] candidate Head/profile cluster 无效")
	}
	if err := ValidateDeviceCertificateProfileIntent(&intent); err != nil {
		return DeviceCertificateProfileStateV1{}, err
	}
	if previous == nil {
		if intent.Generation != 1 || intent.ExpectedPreviousProfileStateHash != "" ||
			(intent.TargetStatus != "staged" && !(bootstrapActive && intent.TargetStatus == "active")) {
			return DeviceCertificateProfileStateV1{}, errors.New("[D102 Device CA] 非 bootstrap 首代 profile 只能 staged")
		}
	} else if err := validateDeviceProfileSuccessor(previous, &intent); err != nil {
		return DeviceCertificateProfileStateV1{}, err
	}
	committedAt, _ := ParseTimeZ(head.Body.Payload.CommittedLogicalTime)
	issuanceFrom, _ := ParseTimeZ(intent.IssuanceNotBefore)
	issuanceUntil, _ := ParseTimeZ(intent.IssuanceNotAfter)
	if intent.TargetStatus == "active" && (committedAt.Before(issuanceFrom) || !committedAt.Before(issuanceUntil)) {
		return DeviceCertificateProfileStateV1{}, errors.New("[D102 Device CA] active transition 不在 issuance window")
	}
	intentHash, _ := DeviceCertificateProfileIntentHash(&intent)
	state := DeviceCertificateProfileStateV1{
		Schema: 1, ClusterID: intent.ClusterID, ProfileID: intent.ProfileID, Generation: intent.Generation,
		ProfileIntent: intent, DeviceCertificateProfileIntentHash: intentHash,
		Status: intent.TargetStatus, StatusChangedAt: head.Body.Payload.CommittedLogicalTime,
	}
	if oneOf(state.Status, "retired", "revoked") {
		if head.Body.Payload.RaftIndex < 2 {
			return DeviceCertificateProfileStateV1{}, errors.New("[D102 Device CA] terminal profile 缺前一 issuance 坐标")
		}
		state.IssuanceCutoff = &IssuanceLogCoordinateV1{
			RecoveryEpoch: head.Body.Payload.RecoveryEpoch, RaftIndex: head.Body.Payload.RaftIndex - 1,
		}
	}
	if err := ValidateDeviceCertificateProfileStateAtHead(&state, head); err != nil {
		return DeviceCertificateProfileStateV1{}, err
	}
	return state, nil
}

func ValidateDeviceCertificateProfileStateAtHead(state *DeviceCertificateProfileStateV1, head *HeadEntryV2) error {
	if err := ValidateDeviceCertificateProfileState(state); err != nil {
		return err
	}
	if head == nil || ValidateHeadEntry(head, nil) != nil || state.ClusterID != head.Body.Payload.ClusterID ||
		state.StatusChangedAt != head.Body.Payload.CommittedLogicalTime {
		return errors.New("[D102 Device CA] profile state 未绑定 candidate Head 时间/cluster")
	}
	if state.IssuanceCutoff != nil && (state.IssuanceCutoff.RecoveryEpoch != head.Body.Payload.RecoveryEpoch ||
		state.IssuanceCutoff.RaftIndex != head.Body.Payload.RaftIndex-1) {
		return errors.New("[D102 Device CA] terminal cutoff 未由 candidate Head 精确派生")
	}
	return nil
}

func ValidateDeviceCertificateProfileRef(ref *DeviceCertificateProfileRefV1, state *DeviceCertificateProfileStateV1) error {
	if ref == nil || state == nil || ValidateDeviceCertificateProfileState(state) != nil {
		return errors.New("[D102 Device CA] profile ref/state 无效")
	}
	intentHash, _ := DeviceCertificateProfileIntentHash(&state.ProfileIntent)
	stateHash, _ := DeviceCertificateProfileStateHash(state)
	if ref.ProfileID != state.ProfileID || ref.Generation != state.Generation ||
		ref.DeviceCertificateProfileIntentHash != intentHash || ref.DeviceCertificateProfileStateHash != stateHash {
		return errors.New("[D102 Device CA] Enrollment profile ref 未绑定 exact intent/state")
	}
	return nil
}

func validateDeviceProfileSuccessor(previous *DeviceCertificateProfileStateV1, next *DeviceCertificateProfileIntentV1) error {
	if err := ValidateDeviceCertificateProfileState(previous); err != nil {
		return err
	}
	previousHash, _ := DeviceCertificateProfileStateHash(previous)
	if next.ClusterID != previous.ClusterID || next.ProfileID != previous.ProfileID ||
		next.Generation != previous.Generation+1 || next.ExpectedPreviousProfileStateHash != previousHash ||
		next.IssuerFencingEpoch <= previous.ProfileIntent.IssuerFencingEpoch ||
		oneOf(previous.Status, "retired", "revoked") || !allowedDeviceProfileTransition(previous.Status, next.TargetStatus) {
		return errors.New("[D102 Device CA] profile successor generation/CAS/fence/status 无效")
	}
	oldFrozen, newFrozen := previous.ProfileIntent, *next
	for _, intent := range []*DeviceCertificateProfileIntentV1{&oldFrozen, &newFrozen} {
		intent.Generation = 0
		intent.ExpectedPreviousProfileStateHash = ""
		intent.TargetStatus = ""
		intent.IssuerFencingEpoch = 0
		intent.RevocationReason = ""
	}
	if !EqualCanonical(oldFrozen, newFrozen) {
		return errors.New("[D102 Device CA] profile successor 改写了冻结的 X.509/issuer scope")
	}
	return nil
}

func allowedDeviceProfileTransition(previous, next string) bool {
	return previous == "staged" && oneOf(next, "active", "revoked") ||
		previous == "active" && oneOf(next, "retired", "revoked")
}

func parseDeviceIssuerChain(intent *DeviceCertificateProfileIntentV1) ([]*x509.Certificate, error) {
	if len(intent.IssuerChainDER) == 0 || intent.IssuerChainDER[0] != intent.IssuerCertificateDER {
		return nil, errors.New("[D102 Device CA] issuer chain 缺失或首项不等于 online issuer")
	}
	certificates := make([]*x509.Certificate, len(intent.IssuerChainDER))
	for i, encoded := range intent.IssuerChainDER {
		der, err := decodeCanonicalBase64URL(encoded)
		if err != nil {
			return nil, errors.New("[D102 Device CA] issuer chain DER 编码无效")
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || certificate.PublicKeyAlgorithm != x509.Ed25519 ||
			len(certificate.UnhandledCriticalExtensions) != 0 {
			return nil, errors.New("[D102 Device CA] issuer chain certificate profile 无效")
		}
		certificates[i] = certificate
		if i > 0 && bytes.Equal(certificates[i-1].Raw, certificate.Raw) {
			return nil, errors.New("[D102 Device CA] issuer chain certificate 重复")
		}
	}
	for i := 0; i+1 < len(certificates); i++ {
		if certificates[i].CheckSignatureFrom(certificates[i+1]) != nil {
			return nil, errors.New("[D102 Device CA] issuer chain signature 断裂")
		}
	}
	anchor := certificates[len(certificates)-1]
	if !bytes.Equal(anchor.RawSubject, anchor.RawIssuer) ||
		anchor.CheckSignature(anchor.SignatureAlgorithm, anchor.RawTBSCertificate, anchor.Signature) != nil {
		return nil, errors.New("[D102 Device CA] issuer chain anchor 不是有效自签根")
	}
	issuerDER, _ := decodeCanonicalBase64URL(intent.IssuerCertificateDER)
	issuerHash, _ := HashBytes(DomainDeviceIssuerCertificateDER, issuerDER)
	chainHash, _ := HashObject(DomainDeviceIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{Schema: 1, IssuerChainDER: intent.IssuerChainDER})
	if intent.IssuerCertificateHash != issuerHash || intent.IssuerChainHash != chainHash {
		return nil, errors.New("[D102 Device CA] issuer certificate/chain hash 不匹配")
	}
	return certificates, nil
}

func validOIDSequence(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if parsed, ok := parseOID(value); !ok || parsed.String() != value {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func deviceCertificateKeyUsage(bits []string) x509.KeyUsage {
	var result x509.KeyUsage
	for _, bit := range bits {
		switch bit {
		case "digital_signature":
			result |= x509.KeyUsageDigitalSignature
		case "key_encipherment":
			result |= x509.KeyUsageKeyEncipherment
		case "key_agreement":
			result |= x509.KeyUsageKeyAgreement
		}
	}
	return result
}

// VerifyDeviceCertificateAt 只接受 exact profile anchor 与 Device P-256 identity。
// retired 只放行 cutoff 前已 approval 的证书，revoked/staged 一律拒绝（D102、D131）。
func VerifyDeviceCertificateAt(certificateDER []byte, state *DeviceCertificateProfileStateV1,
	expectedDeviceID, expectedIdentitySPKIHash, platform string, responsibilities []string,
	issuance IssuanceLogCoordinateV1, approvedAt, trustedTime time.Time) (*x509.Certificate, error) {
	if err := ValidateDeviceCertificateProfileState(state); err != nil {
		return nil, err
	}
	if len(certificateDER) == 0 || !validIdentifier(expectedDeviceID, 128) || trustedTime.IsZero() || approvedAt.IsZero() ||
		issuance.RecoveryEpoch < 0 || issuance.RaftIndex < 1 ||
		!contains(state.ProfileIntent.AllowedPlatforms, platform) ||
		!sortedEnum(responsibilities, []string{"use_loom", "forward", "internet_egress"}, true) {
		return nil, errors.New("[D102 Device identity] certificate verification context 无效")
	}
	for _, responsibility := range responsibilities {
		if !contains(state.ProfileIntent.AllowedResponsibilities, responsibility) {
			return nil, errors.New("[D102 Device identity] Device responsibility 超出 certificate profile scope")
		}
	}
	if state.Status == "staged" || state.Status == "revoked" {
		return nil, errors.New("[D102 Device identity] profile 尚未 active 或已经 revoked")
	}
	changedAt, _ := ParseTimeZ(state.StatusChangedAt)
	if state.Status == "retired" && (compareIssuanceCoordinate(issuance, *state.IssuanceCutoff) > 0 || !approvedAt.Before(changedAt)) {
		return nil, errors.New("[D102 Device identity] retired profile 拒绝 cutoff 后 issuance/approval")
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !bytes.Equal(certificate.Raw, certificateDER) || !certificate.BasicConstraintsValid || certificate.IsCA ||
		certificate.PublicKeyAlgorithm != x509.ECDSA || certificate.SignatureAlgorithm != x509.PureEd25519 ||
		certificate.KeyUsage != deviceCertificateKeyUsage(state.ProfileIntent.KeyUsageBits) ||
		len(certificate.UnhandledCriticalExtensions) != 0 || !bytes.Equal(certificate.RawSubject, []byte{0x30, 0x00}) {
		return nil, errors.New("[D102 Device identity] leaf DER/algorithm/subject/usage 无效")
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("[D102 Device identity] leaf subject key 必须是 P-256")
	}
	identityHash, _ := HashBytes(DomainEnrollmentIdentitySPKI, certificate.RawSubjectPublicKeyInfo)
	if identityHash != expectedIdentitySPKIHash {
		return nil, errors.New("[D102 Device identity] leaf SPKI 未绑定 Enrollment identity")
	}
	expectedURI := state.ProfileIntent.SANURIPrefix + url.PathEscape(expectedDeviceID)
	if len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedURI ||
		len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 {
		return nil, errors.New("[D102 Device identity] leaf SAN 未 exact-bind Device URI")
	}
	if !exactCertificateOIDs(certificate, state.ProfileIntent.RequiredEKUOIDs, state.ProfileIntent.RequiredPolicyOIDs) ||
		!equalCertificateExtensionOrder(certificate, state.ProfileIntent.ExtensionOrderOIDs) {
		return nil, errors.New("[D102 Device identity] leaf EKU/policy/extension order 不匹配")
	}
	issuers, err := parseDeviceIssuerChain(&state.ProfileIntent)
	if err != nil || certificate.CheckSignatureFrom(issuers[0]) != nil {
		return nil, errors.New("[D102 Device identity] leaf 不由 exact profile issuer 签发")
	}
	from, _ := ParseTimeZ(state.ProfileIntent.IssuanceNotBefore)
	until, _ := ParseTimeZ(state.ProfileIntent.IssuanceNotAfter)
	if approvedAt.Before(from) || !approvedAt.Before(until) || approvedAt.Before(certificate.NotBefore) ||
		certificate.NotBefore.Before(from) || !certificate.NotBefore.Before(until) ||
		certificate.NotAfter.After(until.Add(time.Duration(state.ProfileIntent.ValiditySeconds)*time.Second)) ||
		certificate.NotAfter.Sub(certificate.NotBefore) > time.Duration(state.ProfileIntent.ValiditySeconds)*time.Second ||
		trustedTime.Before(certificate.NotBefore) || !trustedTime.Before(certificate.NotAfter) {
		return nil, errors.New("[D102 Device identity] leaf issuance/validity/trusted time 无效")
	}
	return certificate, nil
}

func DeviceCertificateHash(certificateDER []byte) (string, error) {
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !bytes.Equal(certificate.Raw, certificateDER) {
		return "", errors.New("[D102 Device identity] certificate DER 无效")
	}
	return HashBytes(DomainDeviceCertificateDER, certificateDER)
}

func compareIssuanceCoordinate(left, right IssuanceLogCoordinateV1) int {
	if left.RecoveryEpoch < right.RecoveryEpoch {
		return -1
	}
	if left.RecoveryEpoch > right.RecoveryEpoch {
		return 1
	}
	if left.RaftIndex < right.RaftIndex {
		return -1
	}
	if left.RaftIndex > right.RaftIndex {
		return 1
	}
	return 0
}

func equalCertificateExtensionOrder(certificate *x509.Certificate, expected []string) bool {
	actual := make([]string, len(certificate.Extensions))
	for i, extension := range certificate.Extensions {
		actual[i] = extension.Id.String()
	}
	return EqualCanonical(actual, expected)
}

func containsAll(values []string, required ...string) bool {
	for _, item := range required {
		if !contains(values, item) {
			return false
		}
	}
	return true
}
