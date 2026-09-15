package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	DomainCertificateIdentityProjection = "loom-certificate-identity-projection-v1"
	DomainCertificateIntent             = "loom-certificate-intent-v1"
	DomainCertificateCSRDER             = "loom-certificate-csr-der-v1"
)

// CertificateIdentityProjectionV1 把 listener 可长期依赖的 TLS 身份与一次
// ACME 签发分开；renew policy 或 order 变化不能悄悄改变入口 SPKI。
type CertificateIdentityProjectionV1 struct {
	Schema             int      `json:"schema"`
	ClusterID          string   `json:"cluster_id"`
	IntentID           string   `json:"intent_id"`
	IdentityGeneration int64    `json:"identity_generation"`
	EndpointIDs        []string `json:"endpoint_ids"`
	DNSNames           []string `json:"dns_names"`
	IssuerProfileRef   string   `json:"issuer_profile_ref"`
	KeyOwnerDeviceID   string   `json:"key_owner_device_id"`
	KeyArtifactHash    string   `json:"key_artifact_hash"`
	SPKIHash           string   `json:"spki_hash"`
}

// CertificateIntentV1 是一次获 certified authority 的签发请求。CSR 是公开材料，
// private key 仍只留在 KeyOwnerDeviceID 对应节点。
type CertificateIntentV1 struct {
	Schema                 int                             `json:"schema"`
	IdentityProjection     CertificateIdentityProjectionV1 `json:"identity_projection"`
	IdentityProjectionHash string                          `json:"identity_projection_hash"`
	IssuanceGeneration     int64                           `json:"issuance_generation"`
	CSRDER                 string                          `json:"csr_der"`
	CSRHash                string                          `json:"csr_hash"`
	RenewBeforeSeconds     int64                           `json:"renew_before_seconds"`
	SPKIOverlapSeconds     int64                           `json:"spki_overlap_seconds"`
}

func ValidateCertificateIdentityProjection(projection *CertificateIdentityProjectionV1) error {
	if projection == nil || projection.Schema != 1 ||
		!validIdentifier(projection.ClusterID, 128) || !validIdentifier(projection.IntentID, 128) ||
		projection.IdentityGeneration < 1 || !validIdentifier(projection.IssuerProfileRef, 128) ||
		!validIdentifier(projection.KeyOwnerDeviceID, 128) ||
		len(projection.EndpointIDs) == 0 || !sortedUnique(projection.EndpointIDs) ||
		len(projection.DNSNames) == 0 || len(projection.DNSNames) > 16 || !sortedUnique(projection.DNSNames) {
		return errors.New("[TLS] certificate identity projection 字段无效")
	}
	for _, endpointID := range projection.EndpointIDs {
		if !validIdentifier(endpointID, 128) {
			return errors.New("[TLS] certificate endpoint ID 无效")
		}
	}
	for _, name := range projection.DNSNames {
		if !ValidFQDN(name) {
			return errors.New("[TLS] certificate DNS name 必须是规范 FQDN")
		}
	}
	for _, hash := range []string{projection.KeyArtifactHash, projection.SPKIHash} {
		if _, err := ParseHash(hash); err != nil {
			return errors.New("[TLS] certificate key artifact/SPKI hash 无效")
		}
	}
	return nil
}

func CertificateIdentityProjectionHash(projection *CertificateIdentityProjectionV1) (string, error) {
	if err := ValidateCertificateIdentityProjection(projection); err != nil {
		return "", err
	}
	return HashObject(DomainCertificateIdentityProjection, projection)
}

func ValidateCertificateIntent(intent *CertificateIntentV1) error {
	if intent == nil || intent.Schema != 1 || intent.IssuanceGeneration < 1 ||
		intent.RenewBeforeSeconds < 3600 || intent.RenewBeforeSeconds > 365*24*60*60 ||
		intent.SPKIOverlapSeconds < 3600 || intent.SPKIOverlapSeconds > 365*24*60*60 {
		return errors.New("[TLS] certificate intent generation/renew/overlap policy 无效")
	}
	projectionHash, err := CertificateIdentityProjectionHash(&intent.IdentityProjection)
	if err != nil || projectionHash != intent.IdentityProjectionHash {
		return errors.New("[TLS] certificate intent 未绑定 exact identity projection")
	}
	csrDER, err := decodeCanonicalBase64URL(intent.CSRDER)
	if err != nil {
		return errors.New("[TLS] certificate CSR 必须是规范 DER/base64url")
	}
	csrHash, err := HashBytes(DomainCertificateCSRDER, csrDER)
	if err != nil || csrHash != intent.CSRHash {
		return errors.New("[TLS] certificate CSR hash 不匹配")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || !bytes.Equal(csr.Raw, csrDER) || csr.CheckSignature() != nil ||
		csr.SignatureAlgorithm != x509.ECDSAWithSHA256 || len(csr.IPAddresses) != 0 ||
		len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 ||
		!equalStrings(csr.DNSNames, intent.IdentityProjection.DNSNames) ||
		csr.Subject.CommonName != intent.IdentityProjection.DNSNames[0] {
		return errors.New("[TLS] certificate CSR identity/profile 无效")
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("[TLS] public TLS identity 必须使用 P-256")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return errors.New("[TLS] certificate CSR SPKI 无法编码")
	}
	digest := sha256.Sum256(spki)
	wantSPKI := "sha256:" + hex.EncodeToString(digest[:])
	if wantSPKI != intent.IdentityProjection.SPKIHash {
		return errors.New("[TLS] certificate CSR 与 identity SPKI 不匹配")
	}
	return nil
}

func CertificateIntentHash(intent *CertificateIntentV1) (string, error) {
	if err := ValidateCertificateIntent(intent); err != nil {
		return "", err
	}
	return HashObject(DomainCertificateIntent, intent)
}

// NewCertificateIntentV1 只组装调用方已准备好的本地 CSR；它不读取时钟、网络或
// 随机数，因而 reducer/proposal 可对同一输入得到相同 bytes。
func NewCertificateIntentV1(projection CertificateIdentityProjectionV1, issuanceGeneration int64,
	csrDER []byte, renewBeforeSeconds, overlapSeconds int64) (CertificateIntentV1, error) {
	projectionHash, err := CertificateIdentityProjectionHash(&projection)
	if err != nil {
		return CertificateIntentV1{}, err
	}
	csrHash, err := HashBytes(DomainCertificateCSRDER, csrDER)
	if err != nil {
		return CertificateIntentV1{}, err
	}
	intent := CertificateIntentV1{
		Schema: 1, IdentityProjection: projection, IdentityProjectionHash: projectionHash,
		IssuanceGeneration: issuanceGeneration, CSRDER: base64.RawURLEncoding.EncodeToString(csrDER),
		CSRHash: csrHash, RenewBeforeSeconds: renewBeforeSeconds, SPKIOverlapSeconds: overlapSeconds,
	}
	if err := ValidateCertificateIntent(&intent); err != nil {
		return CertificateIntentV1{}, err
	}
	return intent, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
