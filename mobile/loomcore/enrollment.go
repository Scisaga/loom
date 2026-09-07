package loomcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	enrollmentSchema = 1
	// PlatformAndroid is the only enrollment platform emitted by this mobile
	// binding. Responsibilities remain fixed by the server-side invitation.
	PlatformAndroid = "android"
)

type enrollmentInvite struct {
	Schema            int    `json:"schema"`
	Endpoint          string `json:"endpoint"`
	Token             string `json:"token"`
	ExpiresAt         string `json:"expires_at"`
	PlatformKeySHA256 string `json:"platform_key_sha256,omitempty"`
}

type enrollmentClaim struct {
	Token     string `json:"token"`
	Platform  string `json:"platform"`
	CSRPEM    string `json:"csr_pem"`
	RequestID string `json:"request_id"`
}

type enrollmentBootstrap struct {
	NodeID            string   `json:"node_id"`
	DistributionURLs  []string `json:"distribution_urls"`
	DNS               []string `json:"dns"`
	SecretsEnv        string   `json:"secrets_env"`
	PlatformPublicKey string   `json:"platform_public_key"`
	ReleaseAuthority  string   `json:"release_authority"`
	CACertPEM         string   `json:"ca_cert_pem"`
	NodeCertPEM       string   `json:"node_cert_pem"`
}

type enrollmentResponse struct {
	Schema        int                  `json:"schema"`
	ClientID      string               `json:"client_id"`
	Status        string               `json:"status"`
	ClaimedAt     string               `json:"claimed_at"`
	Replay        bool                 `json:"replay"`
	Next          string               `json:"next"`
	Configuration string               `json:"configuration"`
	Bootstrap     *enrollmentBootstrap `json:"bootstrap,omitempty"`
}

type validatedEnrollment struct {
	Schema         int                `json:"schema"`
	ReportEndpoint string             `json:"report_endpoint"`
	Response       enrollmentResponse `json:"response"`
}

// ParseEnrollmentInvite strictly decodes a loom://enroll#... artifact and
// returns its canonical JSON form for Keystore-protected pending state. The
// returned bytes contain the bearer token. Every failure is deliberately
// generic and never includes the input URI, decoded payload, or token.
func ParseEnrollmentInvite(raw string) ([]byte, error) {
	invite, err := parseEnrollmentInvite(raw)
	if err != nil {
		return nil, invalidEnrollmentInvite()
	}
	return json.Marshal(&invite)
}

func parseEnrollmentInvite(raw string) (enrollmentInvite, error) {
	var out enrollmentInvite
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > maxInviteBytes {
		return out, invalidEnrollmentInvite()
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "loom" || parsed.Host != "enroll" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment == "" {
		return out, invalidEnrollmentInvite()
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parsed.Fragment)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != parsed.Fragment || len(decoded) > maxInviteBytes {
		return out, invalidEnrollmentInvite()
	}
	if err := decodeStrictJSON(decoded, maxInviteBytes, &out); err != nil {
		return enrollmentInvite{}, invalidEnrollmentInvite()
	}
	if err := validateEnrollmentInvite(out); err != nil {
		return enrollmentInvite{}, invalidEnrollmentInvite()
	}
	return out, nil
}

func decodeEnrollmentInvite(body []byte) (enrollmentInvite, error) {
	var invite enrollmentInvite
	if err := decodeStrictJSON(body, maxInviteBytes, &invite); err != nil || validateEnrollmentInvite(invite) != nil {
		return enrollmentInvite{}, invalidEnrollmentInvite()
	}
	return invite, nil
}

func validateEnrollmentInvite(invite enrollmentInvite) error {
	if invite.Schema != enrollmentSchema {
		return invalidEnrollmentInvite()
	}
	endpoint, err := url.ParseRequestURI(invite.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.String() != invite.Endpoint {
		return invalidEnrollmentInvite()
	}
	token, err := base64.RawURLEncoding.DecodeString(invite.Token)
	if err != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != invite.Token {
		return invalidEnrollmentInvite()
	}
	if _, err := time.Parse(time.RFC3339, invite.ExpiresAt); err != nil {
		return invalidEnrollmentInvite()
	}
	if invite.PlatformKeySHA256 != "" {
		digest, err := hex.DecodeString(invite.PlatformKeySHA256)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != invite.PlatformKeySHA256 {
			return invalidEnrollmentInvite()
		}
	}
	return nil
}

func invalidEnrollmentInvite() error {
	return errors.New("[§9.1 加入二维码] 加入码无效；请重新获取，不要复制或记录其原始内容")
}

// EnrollmentEndpoint extracts the credential-free HTTPS request target from a
// canonical invite. It also requires the production /loom-client/enroll path,
// so report routing cannot be discovered only after consuming the token.
func EnrollmentEndpoint(inviteJSON []byte) (string, error) {
	invite, err := decodeEnrollmentInvite(inviteJSON)
	if err != nil {
		return "", err
	}
	if _, err := ReportEndpoint(invite.Endpoint); err != nil {
		return "", invalidEnrollmentInvite()
	}
	return invite.Endpoint, nil
}

// ValidateEnrollmentInvitePlatformKey checks the QR fingerprint against the
// raw Ed25519 key pinned in the application before any bearer token is sent.
func ValidateEnrollmentInvitePlatformKey(inviteJSON, pinnedPlatformKey []byte) error {
	invite, err := decodeEnrollmentInvite(inviteJSON)
	if err != nil {
		return err
	}
	if len(pinnedPlatformKey) != ed25519.PublicKeySize || invite.PlatformKeySHA256 == "" {
		return errors.New("加入码缺少或客户端未提供有效的平台信任根")
	}
	digest := sha256.Sum256(pinnedPlatformKey)
	if !bytes.Equal([]byte(invite.PlatformKeySHA256), []byte(hex.EncodeToString(digest[:]))) {
		return errors.New("加入码所属控制中心与客户端平台信任根不匹配")
	}
	return nil
}

// BuildAndroidClaim constructs the exact v1 claim POST body around a
// Keystore-backed CSR. It validates the CSR signature, P-256 key, sole CN
// request_id, and empty SAN set. No private key enters this API.
func BuildAndroidClaim(inviteJSON, csrPEM, publicSPKI []byte, requestID string) ([]byte, error) {
	invite, err := decodeEnrollmentInvite(inviteJSON)
	if err != nil {
		return nil, err
	}
	if _, err := EnrollmentEndpoint(inviteJSON); err != nil {
		return nil, err
	}
	if invite.PlatformKeySHA256 == "" {
		return nil, errors.New("加入码缺少平台公钥指纹")
	}
	if err := validateRequestID(requestID); err != nil {
		return nil, err
	}
	devicePublicKey, err := parseP256PublicKey(publicSPKI)
	if err != nil {
		return nil, err
	}
	if err := validateEnrollmentCSR(csrPEM, requestID, devicePublicKey); err != nil {
		return nil, err
	}
	return json.Marshal(&enrollmentClaim{
		Token: invite.Token, Platform: PlatformAndroid, CSRPEM: string(csrPEM), RequestID: requestID,
	})
}

func validateEnrollmentCSR(csrPEM []byte, requestID string, expectedPublicKey *ecdsa.PublicKey) error {
	if len(csrPEM) == 0 || len(csrPEM) > maxInviteBytes {
		return errors.New("[§4.3 设备绑定] 加入身份 CSR 大小无效")
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "" {
		return errors.New("[§4.3 设备绑定] 加入身份 CSR 无效")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil ||
		len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 {
		return errors.New("[§4.3 设备绑定] 加入身份 CSR 签名/SAN 无效")
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || expectedPublicKey == nil ||
		publicKey.X.Cmp(expectedPublicKey.X) != 0 || publicKey.Y.Cmp(expectedPublicKey.Y) != 0 ||
		csr.Subject.CommonName != requestID || len(csr.Subject.Names) != 1 {
		return errors.New("[§4.3 设备绑定] 加入身份 CSR/request_id 不匹配")
	}
	return nil
}

// ValidateAndroidEnrollmentResponse strictly validates either a pending or a
// ready response. Ready additionally binds the node certificate to publicSPKI,
// verifies its CA/name/client-auth chain, checks the invitation's pinned
// Ed25519 hash, and verifies/selects the signed release authority. The returned
// JSON contains no invitation token and is suitable for protected journaling.
func ValidateAndroidEnrollmentResponse(inviteJSON, responseJSON, publicSPKI []byte, statusCode int) ([]byte, error) {
	invite, err := decodeEnrollmentInvite(inviteJSON)
	if err != nil {
		return nil, err
	}
	reportEndpoint, err := ReportEndpoint(invite.Endpoint)
	if err != nil {
		return nil, err
	}
	devicePublicKey, err := parseP256PublicKey(publicSPKI)
	if err != nil {
		return nil, err
	}
	var response enrollmentResponse
	if err := decodeStrictJSON(responseJSON, maxResponseBytes, &response); err != nil {
		return nil, errors.New("[§9.2 加入流程] 控制中心返回了无法识别的响应")
	}
	if err := validateEnrollmentResponse(response, statusCode); err != nil {
		return nil, err
	}
	if response.Configuration == "ready" {
		if err := validateEnrollmentBootstrap(response.Bootstrap, response.ClientID, invite, devicePublicKey); err != nil {
			return nil, err
		}
	}
	return json.Marshal(&validatedEnrollment{
		Schema: enrollmentSchema, ReportEndpoint: reportEndpoint, Response: response,
	})
}

func validateEnrollmentResponse(response enrollmentResponse, statusCode int) error {
	if response.Schema != enrollmentSchema || !validNodeID(response.ClientID) {
		return errors.New("[§9.2 加入流程] 加入响应 schema/client_id 无效")
	}
	if _, err := time.Parse(time.RFC3339, response.ClaimedAt); err != nil {
		return errors.New("[§9.2 加入流程] 加入响应 claimed_at 无效")
	}
	switch response.Configuration {
	case "pending":
		if statusCode != 202 || response.Status != "provisioning" ||
			response.Next != "wait_for_configuration" || response.Bootstrap != nil {
			return errors.New("[§9.2 加入流程] pending 加入响应语义不一致")
		}
	case "ready":
		if statusCode != 200 || response.Status != "ready" || response.Next != "pull" || response.Bootstrap == nil {
			return errors.New("[§9.2 加入流程] ready 加入响应语义不一致")
		}
		if response.Bootstrap.NodeID != response.ClientID {
			return errors.New("[§4.3 设备绑定] ready 加入响应的 client_id 与 node_id 不一致")
		}
	default:
		return errors.New("[§4.5 fail closed] 不识别加入配置状态")
	}
	return nil
}

func validateEnrollmentBootstrap(bootstrap *enrollmentBootstrap, clientID string, invite enrollmentInvite, devicePublicKey *ecdsa.PublicKey) error {
	if bootstrap == nil || !validNodeID(bootstrap.NodeID) || bootstrap.NodeID != clientID {
		return errors.New("[§4.3 设备绑定] bootstrap 节点 id 无效")
	}
	if err := validateDistributionCoordinates(bootstrap.DistributionURLs, bootstrap.DNS); err != nil {
		return err
	}
	if _, err := parseSecretsEnv(bootstrap.SecretsEnv); err != nil {
		return fmt.Errorf("[§4.2 配置与秘密分离] bootstrap 秘密层无效:%w", err)
	}
	platformKey, err := decodePlatformPublicKey(bootstrap.PlatformPublicKey)
	if err != nil {
		return err
	}
	if invite.PlatformKeySHA256 == "" {
		return errors.New("[§4.3 签名高于传输信任] 加入码缺少平台公钥指纹")
	}
	digest := sha256.Sum256(platformKey)
	if !bytes.Equal([]byte(invite.PlatformKeySHA256), []byte(hex.EncodeToString(digest[:]))) {
		return errors.New("[§4.3 签名高于传输信任] bootstrap 平台公钥与加入码指纹不匹配")
	}
	current, err := decodeAndVerifyCurrent([]byte(bootstrap.ReleaseAuthority), platformKey)
	if err != nil {
		return fmt.Errorf("[§4.3 签名高于传输信任] bootstrap release authority 无效:%w", err)
	}
	if _, err := current.selectSnapshot(bootstrap.NodeID); err != nil {
		return fmt.Errorf("[§4.3 设备绑定] signed current 未授权本设备:%w", err)
	}
	if err := validateNodeCertificates(bootstrap.CACertPEM, bootstrap.NodeCertPEM, bootstrap.NodeID, devicePublicKey); err != nil {
		return err
	}
	// Normalize only values whose alternate wire encodings are not meaningful.
	bootstrap.PlatformPublicKey = base64.StdEncoding.EncodeToString(platformKey)
	return nil
}

func validateDistributionCoordinates(mirrors, dnsEntries []string) error {
	if len(mirrors) == 0 || len(mirrors) > 8 {
		return errors.New("[§14.2 节点自取] bootstrap 分发镜像数量无效")
	}
	seen := map[string]bool{}
	for _, raw := range mirrors {
		parsed, err := url.ParseRequestURI(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.New("[§14.2 节点自取] bootstrap 分发镜像无效")
		}
		normalized := strings.TrimRight(raw, "/")
		if seen[normalized] {
			return errors.New("[§14.2 节点自取] bootstrap 分发镜像重复")
		}
		seen[normalized] = true
	}
	if len(dnsEntries) > 4 {
		return errors.New("[§7.3.2 DNS] bootstrap DNS 坐标过多")
	}
	for _, raw := range dnsEntries {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.IsValid() || address.IsUnspecified() {
			return errors.New("[§7.3.2 DNS] bootstrap DNS 坐标无效")
		}
	}
	return nil
}

func decodePlatformPublicKey(encoded string) (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(encoded)
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("[§4.3 签名高于传输信任] bootstrap 平台公钥无效")
	}
	return ed25519.PublicKey(key), nil
}

func parseP256PublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("解析设备公钥:%w", err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("设备公钥必须是 ECDSA P-256")
	}
	return publicKey, nil
}

func validateNodeCertificates(caPEM, certPEM, nodeID string, devicePublicKey *ecdsa.PublicKey) error {
	ca, err := parseSingleCertificate([]byte(caPEM))
	if err != nil || !ca.IsCA {
		return errors.New("[§9.3 稳态认证] bootstrap CA 证书无效")
	}
	certificate, err := parseSingleCertificate([]byte(certPEM))
	if err != nil {
		return errors.New("[§9.3 稳态认证] bootstrap 节点证书无效")
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || publicKey.X.Cmp(devicePublicKey.X) != 0 || publicKey.Y.Cmp(devicePublicKey.Y) != 0 {
		return errors.New("[§4.3 设备绑定] 签发证书与 Android Keystore 公钥不匹配")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: nodeID + ".node.internal",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("[§9.3 稳态认证] 节点证书无法回溯到 bootstrap CA:%w", err)
	}
	return nil
}

func parseSingleCertificate(certPEM []byte) (*x509.Certificate, error) {
	if len(certPEM) == 0 || len(certPEM) > 32<<10 {
		return nil, errors.New("证书 PEM 长度无效")
	}
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("证书 PEM 必须只含一张证书")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ReportEndpoint applies the production endpoint contract without performing
// network I/O. Scheme, authority, and port are preserved exactly.
func ReportEndpoint(enrollmentEndpoint string) (string, error) {
	parsed, err := url.Parse(enrollmentEndpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "/loom-client/enroll" || parsed.RawPath != "" || strings.ContainsAny(enrollmentEndpoint, "?#") {
		return "", errors.New("[D98 上报] 加入入口必须是无附加参数的 HTTPS /loom-client/enroll")
	}
	parsed.Path = "/loom-client/report"
	return parsed.String(), nil
}
