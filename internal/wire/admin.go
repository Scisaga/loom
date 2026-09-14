package wire

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DomainAdminResourceScope      = "loom-admin-resource-scope-v1"
	DomainAdminCertificateProfile = "loom-admin-certificate-profile-v1"
	DomainAdminIssuerChain        = "loom-admin-issuer-chain-v1"
	DomainAdminAuthorization      = "loom-admin-authorization-v1"
	DomainAdminCertificateDER     = "loom-admin-certificate-der-v1"
)

type AdminScopeIDsV1 struct {
	DeviceIDs []string `json:"device_ids"`
}

type AdminEndpointScopeV1 struct {
	EndpointIDs []string `json:"endpoint_ids"`
}

type AdminManagedZoneScopeV1 struct {
	ZoneIDs []string `json:"zone_ids"`
}

type AdminCAProfileScopeV1 struct {
	ProfileIDs []string `json:"profile_ids"`
}

type AdminResourceScopeV1 struct {
	ScopeKind         string                   `json:"scope_kind"`
	Cluster           *struct{}                `json:"cluster,omitempty"`
	Device            *AdminScopeIDsV1         `json:"device,omitempty"`
	Endpoint          *AdminEndpointScopeV1    `json:"endpoint,omitempty"`
	ManagedZone       *AdminManagedZoneScopeV1 `json:"managed_zone,omitempty"`
	ControlMembership *struct{}                `json:"control_membership,omitempty"`
	RecoveryPolicy    *struct{}                `json:"recovery_policy,omitempty"`
	CAProfile         *AdminCAProfileScopeV1   `json:"ca_profile,omitempty"`
}

type AdminCertificateProfileRefV1 struct {
	ProfileID                   string `json:"profile_id"`
	Generation                  int64  `json:"generation"`
	AdminCertificateProfileHash string `json:"admin_certificate_profile_hash"`
}

type AdminCertificateProfileV1 struct {
	Schema                      int      `json:"schema"`
	ClusterID                   string   `json:"cluster_id"`
	ProfileID                   string   `json:"profile_id"`
	Generation                  int64    `json:"generation"`
	IssuerChainDER              []string `json:"issuer_chain_der"`
	AdminIssuerChainHash        string   `json:"admin_issuer_chain_hash"`
	SubjectKeyAlgorithm         string   `json:"subject_key_algorithm"`
	OperationSignatureAlgorithm string   `json:"operation_signature_algorithm"`
	RequiredEKUOIDs             []string `json:"required_eku_oids"`
	RequiredPolicyOIDs          []string `json:"required_policy_oids"`
	MaximumValiditySeconds      int64    `json:"maximum_validity_seconds"`
}

type AdminAuthorizationV1 struct {
	Schema                    int                          `json:"schema"`
	ClusterID                 string                       `json:"cluster_id"`
	AuthorizationID           string                       `json:"authorization_id"`
	Generation                int64                        `json:"generation"`
	PreviousAuthorizationHash string                       `json:"previous_authorization_hash,omitempty"`
	AdminID                   string                       `json:"admin_id"`
	AdminCertificateDER       string                       `json:"admin_certificate_der"`
	AdminCertificateDigest    string                       `json:"admin_certificate_digest"`
	AdminKeyID                string                       `json:"admin_key_id"`
	CertificateProfileRef     AdminCertificateProfileRefV1 `json:"certificate_profile_ref"`
	NotBefore                 string                       `json:"not_before"`
	NotAfter                  string                       `json:"not_after"`
	Status                    string                       `json:"status"`
	AllowedOperationKinds     []string                     `json:"allowed_operation_kinds"`
	Capabilities              []string                     `json:"capabilities"`
	Scopes                    []AdminResourceScopeV1       `json:"scopes"`
}

type AdminACLLeafV1 struct {
	Schema                 int    `json:"schema"`
	AuthorizationID        string `json:"authorization_id"`
	Generation             int64  `json:"generation"`
	AdminAuthorizationHash string `json:"admin_authorization_hash"`
}

// VerifiedAdminOperationV1 是私有 control_api 完成 mTLS、base-head 与 certified
// ACL 验证后的不透明结果；reducer 不接受调用方自行拼接的“已授权”布尔值（D104）。
type VerifiedAdminOperationV1 struct {
	operation ControlOperationV1
	headHash  string
	scopeHash string
}

func (verified VerifiedAdminOperationV1) Operation() ControlOperationV1 {
	return verified.operation
}

func (verified VerifiedAdminOperationV1) HeadHash() string {
	return verified.headHash
}

func (verified VerifiedAdminOperationV1) ScopeHash() string {
	return verified.scopeHash
}

func ValidateAdminResourceScope(scope *AdminResourceScopeV1) error {
	if scope == nil {
		return errors.New("[D104 admin ACL] resource scope 不能为空")
	}
	variants := 0
	for _, present := range []bool{scope.Cluster != nil, scope.Device != nil, scope.Endpoint != nil,
		scope.ManagedZone != nil, scope.ControlMembership != nil, scope.RecoveryPolicy != nil, scope.CAProfile != nil} {
		if present {
			variants++
		}
	}
	if variants != 1 {
		return errors.New("[D104 admin ACL] resource scope 必须恰有一个 variant")
	}
	switch scope.ScopeKind {
	case "cluster":
		if scope.Cluster == nil {
			return errors.New("[D104 admin ACL] cluster scope tag 不匹配")
		}
	case "device":
		if scope.Device == nil || !sortedUnique(scope.Device.DeviceIDs) || len(scope.Device.DeviceIDs) == 0 {
			return errors.New("[D104 admin ACL] device scope 无效")
		}
	case "endpoint":
		if scope.Endpoint == nil || !sortedUnique(scope.Endpoint.EndpointIDs) || len(scope.Endpoint.EndpointIDs) == 0 {
			return errors.New("[D104 admin ACL] endpoint scope 无效")
		}
	case "managed_zone":
		if scope.ManagedZone == nil || !sortedUnique(scope.ManagedZone.ZoneIDs) || len(scope.ManagedZone.ZoneIDs) == 0 {
			return errors.New("[D104 admin ACL] managed-zone scope 无效")
		}
	case "control_membership":
		if scope.ControlMembership == nil {
			return errors.New("[D104 admin ACL] control-membership scope tag 不匹配")
		}
	case "recovery_policy":
		if scope.RecoveryPolicy == nil {
			return errors.New("[D104 admin ACL] recovery-policy scope tag 不匹配")
		}
	case "ca_profile":
		if scope.CAProfile == nil || !sortedUnique(scope.CAProfile.ProfileIDs) || len(scope.CAProfile.ProfileIDs) == 0 {
			return errors.New("[D104 admin ACL] CA-profile scope 无效")
		}
	default:
		return errors.New("[D104 admin ACL] resource scope kind 未获协议授权")
	}
	return nil
}

func AdminResourceScopeHash(scope *AdminResourceScopeV1) (string, error) {
	if err := ValidateAdminResourceScope(scope); err != nil {
		return "", err
	}
	return HashObject(DomainAdminResourceScope, scope)
}

func ValidateAdminCertificateProfile(profile *AdminCertificateProfileV1) error {
	if profile == nil || profile.Schema != 1 || !validIdentifier(profile.ClusterID, 128) ||
		!validIdentifier(profile.ProfileID, 128) || profile.Generation < 1 || len(profile.IssuerChainDER) == 0 ||
		!validAdminAlgorithms(profile.SubjectKeyAlgorithm, profile.OperationSignatureAlgorithm) ||
		profile.MaximumValiditySeconds < 1 || !sortedOIDStrings(profile.RequiredEKUOIDs) || len(profile.RequiredEKUOIDs) == 0 ||
		!sortedOIDStrings(profile.RequiredPolicyOIDs) || len(profile.RequiredPolicyOIDs) == 0 {
		return errors.New("[D104 admin ACL] admin certificate profile 无效")
	}
	certificates := make([]*x509.Certificate, len(profile.IssuerChainDER))
	for i, encoded := range profile.IssuerChainDER {
		der, err := decodeCanonicalBase64URL(encoded)
		if err != nil {
			return errors.New("[D104 admin ACL] issuer chain DER 编码无效")
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || !adminCertificateAlgorithm(certificate, profile) ||
			len(certificate.UnhandledCriticalExtensions) != 0 {
			return errors.New("[D104 admin ACL] issuer chain certificate profile 无效")
		}
		certificates[i] = certificate
		if i > 0 && bytes.Equal(certificates[i-1].Raw, certificate.Raw) {
			return errors.New("[D104 admin ACL] issuer chain certificate 重复")
		}
	}
	for i := 0; i+1 < len(certificates); i++ {
		if certificates[i].CheckSignatureFrom(certificates[i+1]) != nil {
			return errors.New("[D104 admin ACL] issuer chain signature 断裂")
		}
	}
	root := certificates[len(certificates)-1]
	if !bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignature(root.SignatureAlgorithm, root.RawTBSCertificate, root.Signature) != nil {
		return errors.New("[D104 admin ACL] issuer chain anchor 不是有效自签根")
	}
	chainHash, err := adminIssuerChainHash(profile.IssuerChainDER)
	if err != nil || chainHash != profile.AdminIssuerChainHash {
		return errors.New("[D104 admin ACL] issuer chain hash 不匹配")
	}
	return nil
}

func adminIssuerChainHash(chain []string) (string, error) {
	return HashObject(DomainAdminIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{Schema: 1, IssuerChainDER: chain})
}

func AdminCertificateProfileHash(profile *AdminCertificateProfileV1) (string, error) {
	if err := ValidateAdminCertificateProfile(profile); err != nil {
		return "", err
	}
	return HashObject(DomainAdminCertificateProfile, profile)
}

func AdminCertificateDigest(rawDER []byte) (string, error) {
	if certificate, err := x509.ParseCertificate(rawDER); err != nil || !bytes.Equal(certificate.Raw, rawDER) {
		return "", errors.New("[D104 admin ACL] admin certificate DER 无效")
	}
	return HashBytes(DomainAdminCertificateDER, rawDER)
}

func ValidateAdminAuthorization(authorization *AdminAuthorizationV1, profile *AdminCertificateProfileV1) error {
	return validateAdminAuthorization(authorization, profile, time.Time{}, false)
}

func ValidateAdminAuthorizationAt(authorization *AdminAuthorizationV1, profile *AdminCertificateProfileV1, trustedTime time.Time) error {
	return validateAdminAuthorization(authorization, profile, trustedTime, true)
}

func validateAdminAuthorization(authorization *AdminAuthorizationV1, profile *AdminCertificateProfileV1, trustedTime time.Time, checkTrustedTime bool) error {
	if authorization == nil || profile == nil || checkTrustedTime && trustedTime.IsZero() || authorization.Schema != 1 ||
		authorization.ClusterID != profile.ClusterID || !validIdentifier(authorization.AuthorizationID, 128) ||
		!validIdentifier(authorization.AdminID, 128) || authorization.Generation < 1 ||
		!oneOf(authorization.Status, "active", "revoked") || !sortedUnique(authorization.AllowedOperationKinds) ||
		len(authorization.AllowedOperationKinds) == 0 || !sortedEnum(authorization.Capabilities,
		[]string{"manage_admin_acl", "manage_ca_profiles"}, false) || len(authorization.Scopes) == 0 {
		return errors.New("[D104 admin ACL] authorization header/permissions 无效")
	}
	if err := ValidateAdminCertificateProfile(profile); err != nil {
		return err
	}
	profileHash, _ := AdminCertificateProfileHash(profile)
	if authorization.CertificateProfileRef.ProfileID != profile.ProfileID || authorization.CertificateProfileRef.Generation != profile.Generation ||
		authorization.CertificateProfileRef.AdminCertificateProfileHash != profileHash {
		return errors.New("[D104 admin ACL] certificate profile ref 不匹配")
	}
	if (authorization.Generation == 1) != (authorization.PreviousAuthorizationHash == "") {
		return errors.New("[D104 admin ACL] previous authorization hash/generation 无效")
	}
	if authorization.PreviousAuthorizationHash != "" {
		if _, err := ParseHash(authorization.PreviousAuthorizationHash); err != nil {
			return err
		}
	}
	previousScopeHash := ""
	for i := range authorization.Scopes {
		hash, err := AdminResourceScopeHash(&authorization.Scopes[i])
		if err != nil || i > 0 && previousScopeHash >= hash {
			return errors.New("[D104 admin ACL] scopes 必须按 scope hash 严格排序")
		}
		previousScopeHash = hash
	}
	certificateDER, err := decodeCanonicalBase64URL(authorization.AdminCertificateDER)
	if err != nil {
		return errors.New("[D104 admin ACL] admin certificate 编码无效")
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !bytes.Equal(certificate.Raw, certificateDER) {
		return errors.New("[D104 admin ACL] admin certificate strict DER 无效")
	}
	digest, _ := AdminCertificateDigest(certificateDER)
	keyID, keyErr := AdminKeyID(certificate.RawSubjectPublicKeyInfo)
	if digest != authorization.AdminCertificateDigest || keyErr != nil || keyID != authorization.AdminKeyID {
		return errors.New("[D104 admin ACL] admin certificate digest/key ID 不匹配")
	}
	if !certificate.BasicConstraintsValid || certificate.IsCA || certificate.KeyUsage != x509.KeyUsageDigitalSignature ||
		!adminCertificateAlgorithm(certificate, profile) || len(certificate.UnhandledCriticalExtensions) != 0 {
		return errors.New("[D104 admin ACL] admin leaf CA/KeyUsage 无效")
	}
	if !exactCertificateOIDs(certificate, profile.RequiredEKUOIDs, profile.RequiredPolicyOIDs) {
		return errors.New("[D104 admin ACL] admin leaf EKU/policy OID 不匹配")
	}
	notBefore, err := ParseTimeZ(authorization.NotBefore)
	if err != nil {
		return err
	}
	notAfter, err := ParseTimeZ(authorization.NotAfter)
	if err != nil || !notBefore.Before(notAfter) || notBefore.Before(certificate.NotBefore) || notAfter.After(certificate.NotAfter) ||
		int64(certificate.NotAfter.Sub(certificate.NotBefore)/time.Second) > profile.MaximumValiditySeconds {
		return errors.New("[D104 admin ACL] authorization/certificate validity 无效")
	}
	issuers, err := parseAdminIssuerChain(profile)
	if err != nil || certificate.CheckSignatureFrom(issuers[0]) != nil {
		return errors.New("[D104 admin ACL] admin leaf 不由 exact profile issuer 签发")
	}
	for _, issuer := range issuers {
		if certificate.NotBefore.Before(issuer.NotBefore) || certificate.NotAfter.After(issuer.NotAfter) {
			return errors.New("[D104 admin ACL] admin leaf validity 超出 exact issuer chain")
		}
	}
	if checkTrustedTime && authorization.Status == "active" {
		instant := trustedTime.UTC()
		for _, issuer := range issuers {
			if instant.Before(issuer.NotBefore) || !instant.Before(issuer.NotAfter) {
				return errors.New("[D104 admin ACL] issuer chain 在可信时间无效")
			}
		}
		if instant.Before(notBefore) || !instant.Before(notAfter) ||
			instant.Before(certificate.NotBefore) || !instant.Before(certificate.NotAfter) {
			return errors.New("[D104 admin ACL] active authorization/certificate 已过期或尚未生效")
		}
	}
	return nil
}

func validAdminAlgorithms(subject, signature string) bool {
	return subject == "ed25519" && signature == "ed25519" ||
		subject == "p256" && signature == "ecdsa-p256-sha256"
}

func adminCertificateAlgorithm(certificate *x509.Certificate, profile *AdminCertificateProfileV1) bool {
	if adminSignatureAlgorithm(certificate.PublicKey) != profile.OperationSignatureAlgorithm {
		return false
	}
	return profile.SubjectKeyAlgorithm == "ed25519" && certificate.SignatureAlgorithm == x509.PureEd25519 ||
		profile.SubjectKeyAlgorithm == "p256" && certificate.SignatureAlgorithm == x509.ECDSAWithSHA256
}

func ValidateAdminAuthorizationSuccessor(previous, next *AdminAuthorizationV1, profile *AdminCertificateProfileV1, trustedTime time.Time) error {
	if err := ValidateAdminAuthorizationAt(previous, profile, trustedTime); err != nil {
		return err
	}
	if err := ValidateAdminAuthorizationAt(next, profile, trustedTime); err != nil {
		return err
	}
	previousHash, _ := AdminAuthorizationHash(previous, profile)
	if previous.ClusterID != next.ClusterID || previous.AuthorizationID != next.AuthorizationID ||
		next.Generation != previous.Generation+1 || next.PreviousAuthorizationHash != previousHash ||
		previous.Status == "revoked" || next.Status != "revoked" ||
		previous.AdminID != next.AdminID || previous.AdminCertificateDER != next.AdminCertificateDER ||
		previous.AdminCertificateDigest != next.AdminCertificateDigest || previous.AdminKeyID != next.AdminKeyID ||
		!EqualCanonical(previous.CertificateProfileRef, next.CertificateProfileRef) ||
		!EqualCanonical(previous.AllowedOperationKinds, next.AllowedOperationKinds) ||
		!EqualCanonical(previous.Capabilities, next.Capabilities) || !EqualCanonical(previous.Scopes, next.Scopes) {
		return errors.New("[D104 admin ACL] authorization successor 非连续撤销或改变既有权限 bytes")
	}
	return nil
}

func AdminAuthorizationHash(authorization *AdminAuthorizationV1, profile *AdminCertificateProfileV1) (string, error) {
	if err := ValidateAdminAuthorization(authorization, profile); err != nil {
		return "", err
	}
	return HashObject(DomainAdminAuthorization, authorization)
}

func AdminACLRoot(authorizations []AdminAuthorizationV1, profiles map[string]AdminCertificateProfileV1) (string, error) {
	ordered := append([]AdminAuthorizationV1(nil), authorizations...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].AuthorizationID < ordered[j].AuthorizationID })
	leaves := make([][]byte, len(ordered))
	for i := range ordered {
		authorization := &ordered[i]
		if i > 0 && ordered[i-1].AuthorizationID == authorization.AuthorizationID {
			return "", errors.New("[D104 admin ACL] 每个 authorization ID 只能保留最新一代")
		}
		profile, ok := profiles[authorization.CertificateProfileRef.ProfileID]
		if !ok {
			return "", errors.New("[D104 admin ACL] authorization 缺 exact certificate profile")
		}
		hash, err := AdminAuthorizationHash(authorization, &profile)
		if err != nil {
			return "", err
		}
		leaf := AdminACLLeafV1{Schema: 1, AuthorizationID: authorization.AuthorizationID, Generation: authorization.Generation, AdminAuthorizationHash: hash}
		leaves[i], _ = MarshalCanonical(leaf)
	}
	return "sha256:" + hex.EncodeToString(MerkleRoot(leaves)), nil
}

func AuthorizeControlOperation(operation *ControlOperationV1, authorization *AdminAuthorizationV1, profile *AdminCertificateProfileV1, resourceScope *AdminResourceScopeV1, trustedTime time.Time, schemas OperationSchemaRegistry) error {
	if err := ValidateAdminAuthorizationAt(authorization, profile, trustedTime); err != nil {
		return err
	}
	if authorization.Status != "active" || operation.Body.AuthorID != authorization.AdminID ||
		operation.Body.AdminCertDigest != authorization.AdminCertificateDigest || !contains(authorization.AllowedOperationKinds, operation.Body.Kind) {
		return errors.New("[D104 admin ACL] operation author/cert/kind 未获 base ACL 授权")
	}
	scopeHash, err := AdminResourceScopeHash(resourceScope)
	if err != nil {
		return err
	}
	allowed := false
	for i := range authorization.Scopes {
		hash, _ := AdminResourceScopeHash(&authorization.Scopes[i])
		if hash == scopeHash {
			allowed = true
		}
	}
	if !allowed {
		return errors.New("[D104 admin ACL] operation resource scope 未获授权")
	}
	certificateDER, _ := decodeCanonicalBase64URL(authorization.AdminCertificateDER)
	certificate, _ := x509.ParseCertificate(certificateDER)
	return VerifyControlOperation(operation, certificate.RawSubjectPublicKeyInfo, trustedTime, schemas)
}

// AuthorizeControlOperationAtHead 是 private control_api 的完整授权边界：TLS leaf、
// exact base head、ControlSet 与 certified ACL root 必须同时匹配，任一角色证书都不能
// 仅凭可验证签名越权提交管理操作（D104）。
func AuthorizeControlOperationAtHead(operation *ControlOperationV1, peerCertificateDER []byte,
	resourceScope *AdminResourceScopeV1, trustedTime time.Time, schemas OperationSchemaRegistry,
	head *HeadEntryV2, configQC json.RawMessage, set, previousSet *ControlSetV1, authorizations []AdminAuthorizationV1,
	profiles map[string]AdminCertificateProfileV1) (VerifiedAdminOperationV1, error) {
	if operation == nil || head == nil || set == nil || len(peerCertificateDER) == 0 {
		return VerifiedAdminOperationV1{}, errors.New("[D104 admin ACL] private control request 缺 operation/TLS leaf/base authority")
	}
	if err := ValidateControlSet(set); err != nil {
		return VerifiedAdminOperationV1{}, err
	}
	if err := VerifyConfigQCAuthority(head.HeadHash, configQC, head, set, previousSet); err != nil {
		return VerifiedAdminOperationV1{}, errors.New("[D104 admin ACL] base head 缺有效 replication QC")
	}
	setHash, _ := ControlSetHash(set)
	payload := head.Body.Payload
	body := operation.Body
	if body.ClusterID != payload.ClusterID || body.BaseRecoveryEpoch != payload.RecoveryEpoch ||
		body.BaseRecoveryStatementHash != payload.RecoveryStatementHash || body.BaseRecoveryPolicyHash != payload.RecoveryPolicyHash ||
		body.BaseControlEpoch != payload.ControlEpoch || body.BaseControlSetHash != payload.ControlSetHash ||
		body.BaseControlRevision != payload.ControlRevision || body.ParentHeadHash != head.HeadHash || payload.ControlSetHash != setHash {
		return VerifiedAdminOperationV1{}, errors.New("[D104 admin ACL] operation base 与 exact certified head/ControlSet 不一致")
	}
	root, err := AdminACLRoot(authorizations, profiles)
	if err != nil || root != payload.AdminACLRoot {
		return VerifiedAdminOperationV1{}, errors.New("[D104 admin ACL] ACL view 未绑定 base head root")
	}
	peerDigest, err := AdminCertificateDigest(peerCertificateDER)
	if err != nil {
		return VerifiedAdminOperationV1{}, err
	}
	var authorization *AdminAuthorizationV1
	var profile *AdminCertificateProfileV1
	for i := range authorizations {
		candidate := &authorizations[i]
		if candidate.AdminCertificateDigest != peerDigest || candidate.AdminID != body.AuthorID {
			continue
		}
		if authorization != nil {
			return VerifiedAdminOperationV1{}, errors.New("[D104 admin ACL] TLS leaf 对应多个 authorization")
		}
		selectedProfile, ok := profiles[candidate.CertificateProfileRef.ProfileID]
		if !ok {
			return VerifiedAdminOperationV1{}, errors.New("[D104 admin ACL] authorization 缺 certificate profile")
		}
		authorization = candidate
		profile = &selectedProfile
	}
	if authorization == nil || profile == nil {
		return VerifiedAdminOperationV1{}, errors.New("[D104 admin ACL] TLS leaf 未获 base ACL 授权")
	}
	encodedDER, err := decodeCanonicalBase64URL(authorization.AdminCertificateDER)
	if err != nil || !bytes.Equal(encodedDER, peerCertificateDER) {
		return VerifiedAdminOperationV1{}, errors.New("[D104 admin ACL] TLS leaf 与 authorization exact DER 不一致")
	}
	if err := AuthorizeControlOperation(operation, authorization, profile, resourceScope, trustedTime, schemas); err != nil {
		return VerifiedAdminOperationV1{}, err
	}
	scopeHash, _ := AdminResourceScopeHash(resourceScope)
	return VerifiedAdminOperationV1{operation: *operation, headHash: head.HeadHash, scopeHash: scopeHash}, nil
}

func parseAdminIssuerChain(profile *AdminCertificateProfileV1) ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, len(profile.IssuerChainDER))
	for i, encoded := range profile.IssuerChainDER {
		der, err := decodeCanonicalBase64URL(encoded)
		if err != nil {
			return nil, err
		}
		result[i], err = x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func sortedOIDStrings(values []string) bool {
	for i, value := range values {
		if parsed, ok := parseOID(value); !ok || parsed.String() != value || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func parseOID(value string) (asn1.ObjectIdentifier, bool) {
	var result asn1.ObjectIdentifier
	if value == "" {
		return nil, false
	}
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 1 && part[0] == '0' {
			return nil, false
		}
		component, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return nil, false
		}
		result = append(result, int(component))
	}
	if len(result) < 2 || result[0] > 2 || result[0] < 2 && result[1] >= 40 {
		return nil, false
	}
	return result, true
}

func exactCertificateOIDs(certificate *x509.Certificate, eku, policies []string) bool {
	ekuOID := asn1.ObjectIdentifier{2, 5, 29, 37}
	var actualEKU []asn1.ObjectIdentifier
	foundEKU := false
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(ekuOID) {
			if foundEKU {
				return false
			}
			rest, err := asn1.Unmarshal(extension.Value, &actualEKU)
			if err != nil || len(rest) != 0 {
				return false
			}
			foundEKU = true
		}
	}
	if !foundEKU || len(actualEKU) != len(eku) || len(certificate.PolicyIdentifiers) != len(policies) {
		return false
	}
	actualEKUStrings := make([]string, len(actualEKU))
	for i, oid := range actualEKU {
		actualEKUStrings[i] = oid.String()
	}
	sort.Strings(actualEKUStrings)
	actualPolicyStrings := make([]string, len(certificate.PolicyIdentifiers))
	for i, oid := range certificate.PolicyIdentifiers {
		actualPolicyStrings[i] = oid.String()
	}
	sort.Strings(actualPolicyStrings)
	return EqualCanonical(actualEKUStrings, eku) && EqualCanonical(actualPolicyStrings, policies)
}
