package clientenroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// PreparedIdentity is a complete, replayable enrollment identity. Callers
// must protect the whole value before persistence; it contains the TLS private
// key. The same value is reused while an invitation remains pending.
type PreparedIdentity struct {
	Schema        int    `json:"schema"`
	Platform      string `json:"platform"`
	Endpoint      string `json:"endpoint"`
	RequestID     string `json:"request_id"`
	PrivateKeyPEM []byte `json:"private_key_pem"`
	CSRPEM        []byte `json:"csr_pem"`
}

// ReadyMaterial is the canonical, fully verified bootstrap. No field should be
// written to an active path until ValidateReady succeeds.
type ReadyMaterial struct {
	NodeID            string
	DistributionURLs  []string
	DNS               []string
	SecretsEnv        []byte
	PlatformPublicKey []byte
	ReleaseAuthority  []byte
	CACertPEM         []byte
	NodeCertPEM       []byte
}

// GeneratePreparedIdentity creates the device key and CSR without touching
// disk. Windows callers can therefore DPAPI-protect it before persistence.
func GeneratePreparedIdentity(platform, endpoint string, random io.Reader) (PreparedIdentity, error) {
	var out PreparedIdentity
	if !supportedEnrollmentPlatform(platform) {
		return out, fmt.Errorf("[§9.2 加入流程] 不支持的平台 %q", platform)
	}
	if err := validateEnrollmentEndpoint(endpoint); err != nil {
		return out, err
	}
	if random == nil {
		random = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return out, fmt.Errorf("生成设备 P-256 私钥:%w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return out, err
	}
	requestID, err := randomUUID(random)
	if err != nil {
		return out, err
	}
	csrDER, err := x509.CreateCertificateRequest(random, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: requestID},
	}, key)
	if err != nil {
		return out, fmt.Errorf("生成 P-256 CSR:%w", err)
	}
	out = PreparedIdentity{
		Schema: Schema, Platform: platform, Endpoint: endpoint, RequestID: requestID,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		CSRPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}
	if err := ValidatePreparedIdentity(out); err != nil {
		return PreparedIdentity{}, err
	}
	return out, nil
}

// ValidatePreparedIdentity rejects a modified or cross-platform identity.
func ValidatePreparedIdentity(identity PreparedIdentity) error {
	if identity.Schema != Schema || !supportedEnrollmentPlatform(identity.Platform) {
		return errors.New("[§4.3 设备绑定] 加入身份 schema/platform 无效")
	}
	if err := validateEnrollmentEndpoint(identity.Endpoint); err != nil {
		return err
	}
	if identity.RequestID == "" || len(identity.RequestID) > 128 ||
		strings.TrimSpace(identity.RequestID) != identity.RequestID || strings.IndexFunc(identity.RequestID, unicode.IsControl) >= 0 {
		return errors.New("[§4.3 设备绑定] 加入身份 request_id 无效")
	}
	key, err := parsePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return err
	}
	if len(identity.CSRPEM) == 0 || len(identity.CSRPEM) > 16<<10 {
		return errors.New("[§4.3 设备绑定] 加入身份 CSR 大小无效")
	}
	block, rest := pem.Decode(identity.CSRPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "" {
		return errors.New("[§4.3 设备绑定] 加入身份 CSR 无效")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 {
		return errors.New("[§4.3 设备绑定] 加入身份 CSR 签名/SAN 无效")
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || publicKey.X.Cmp(key.X) != 0 || publicKey.Y.Cmp(key.Y) != 0 ||
		csr.Subject.CommonName != identity.RequestID {
		return errors.New("[§4.3 设备绑定] 加入身份 key/CSR/request_id 不匹配")
	}
	return nil
}

// ClaimPrepared performs one idempotent claim without persisting identity or
// response data. It never follows redirects carrying the invitation token.
func ClaimPrepared(ctx context.Context, client *http.Client, invite Invite, identity PreparedIdentity, server *ServerEnrollment) (Response, error) {
	var zero Response
	if client == nil {
		return zero, errors.New("设备加入 HTTP 客户端为空")
	}
	if err := ValidatePreparedIdentity(identity); err != nil {
		return zero, err
	}
	if invite.Endpoint != identity.Endpoint {
		return zero, errors.New("[§4.3 设备绑定] 加入端点与本机加入身份不一致")
	}
	token, err := base64.RawURLEncoding.DecodeString(invite.Token)
	if err != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != invite.Token {
		return zero, invalidInvite()
	}
	body, err := json.Marshal(claimRequest{
		Token: invite.Token, Platform: identity.Platform, CSRPEM: string(identity.CSRPEM),
		RequestID: identity.RequestID, Server: server,
	})
	if err != nil {
		return zero, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, invite.Endpoint, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("创建设备加入请求:%w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	safeClient := *client
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return errEnrollmentRedirect }
	response, err := safeClient.Do(req)
	if err != nil {
		if errors.Is(err, errEnrollmentRedirect) {
			return zero, fmt.Errorf("[§9.2 加入流程] 控制中心加入端点拒绝直连:%w", errEnrollmentRedirect)
		}
		return zero, &TransientError{cause: fmt.Errorf("[§9.2 加入流程] 提交设备 CSR 的临时网络失败:%w", err)}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		statusErr := enrollmentStatusError(response, invite.Token)
		if response.StatusCode >= 500 && response.StatusCode <= 599 {
			return zero, &TransientError{cause: statusErr}
		}
		return zero, statusErr
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return zero, errors.New("[§9.2 加入流程] 控制中心未返回 application/json")
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(responseBody) > maxResponseBytes {
		return zero, errors.New("[§9.2 加入流程] 控制中心响应超出 4 MiB 边界")
	}
	dec := json.NewDecoder(bytes.NewReader(responseBody))
	dec.DisallowUnknownFields()
	var result Response
	if err := dec.Decode(&result); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return zero, errors.New("[§9.2 加入流程] 控制中心返回了无法识别的响应")
	}
	if err := validateResponse(result, response.StatusCode); err != nil {
		return zero, err
	}
	return result, nil
}

func enrollmentStatusError(response *http.Response, token string) error {
	prefix := fmt.Sprintf("[§9.2 加入流程] 控制中心返回 HTTP %d", response.StatusCode)
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) == 0 || len(body) > 4096 {
		return errors.New(prefix)
	}
	var payload struct {
		Error string `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New(prefix)
	}
	detail := strings.TrimSpace(payload.Error)
	if detail == "" || len(detail) > 512 || strings.Contains(detail, token) ||
		strings.IndexFunc(detail, unicode.IsControl) >= 0 {
		return errors.New(prefix)
	}
	return fmt.Errorf("%s：%s", prefix, detail)
}

// ValidateReady binds every bootstrap input to the local private identity and
// returns canonical bytes suitable for an all-or-nothing platform installer.
func ValidateReady(response Response, identity PreparedIdentity) (ReadyMaterial, error) {
	var out ReadyMaterial
	if err := ValidatePreparedIdentity(identity); err != nil {
		return out, err
	}
	if err := validateResponse(response, http.StatusOK); err != nil {
		return out, err
	}
	material, err := validateBootstrap(*response.Bootstrap, identity.PrivateKeyPEM)
	if err != nil {
		return out, err
	}
	bootstrap := response.Bootstrap
	out = ReadyMaterial{
		NodeID: material.nodeID, DistributionURLs: append([]string(nil), bootstrap.DistributionURLs...),
		DNS: append([]string(nil), bootstrap.DNS...), SecretsEnv: []byte(bootstrap.SecretsEnv),
		PlatformPublicKey: append([]byte(nil), material.platformPublicKey...),
		ReleaseAuthority:  append([]byte(nil), material.releaseAuthority...),
		CACertPEM:         append([]byte(nil), bootstrap.CACertPEM...), NodeCertPEM: append([]byte(nil), bootstrap.NodeCertPEM...),
	}
	return out, nil
}

func supportedEnrollmentPlatform(platform string) bool {
	return platform == PlatformLinuxServer || platform == PlatformWindowsDesktop
}

func validateEnrollmentEndpoint(endpoint string) error {
	u, err := url.ParseRequestURI(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.String() != endpoint {
		return errors.New("[§9.2 加入流程] 加入身份的控制中心 HTTPS 端点无效")
	}
	return nil
}
