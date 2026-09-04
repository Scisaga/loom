// Package clientenroll implements the platform-neutral identity-claim protocol.
// Linux keeps the existing file-backed transaction in this file. Windows uses
// PreparedIdentity so its private key can be protected with DPAPI before it is
// ever persisted.
package clientenroll

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"loom/internal/model"
	"loom/internal/publish"
)

const (
	Schema                 = 1
	PlatformLinuxServer    = "linux-server"
	PlatformWindowsDesktop = "windows-desktop"
	// Platform is retained for compatibility with the Linux file-backed API.
	Platform         = PlatformLinuxServer
	maxInviteBytes   = 16 << 10
	maxResponseBytes = 4 << 20
	identityKeyFile  = "identity.key"
	identityCSRFile  = "identity.csr"
	identityMetaFile = "identity.json"
	enrollmentFile   = "enrollment.json"
	enrollmentLock   = ".enrollment.lock"
)

var errEnrollmentRedirect = errors.New("设备加入 HTTPS 端点不允许重定向")

// Invite is the decoded fragment payload. Token must never be serialized or
// included in diagnostics after ParseInvite returns it.
type Invite struct {
	Endpoint          string
	Token             string
	ExpiresAt         string
	PlatformKeySHA256 string
}

type invitePayload struct {
	Schema            int    `json:"schema"`
	Endpoint          string `json:"endpoint"`
	Token             string `json:"token"`
	ExpiresAt         string `json:"expires_at"`
	PlatformKeySHA256 string `json:"platform_key_sha256,omitempty"`
}

type identityMeta struct {
	Schema    int    `json:"schema"`
	Platform  string `json:"platform"`
	Endpoint  string `json:"endpoint"`
	RequestID string `json:"request_id"`
	CSR       string `json:"csr_sha256"`
	PublicKey string `json:"public_key_sha256"`
}

type claimRequest struct {
	Token     string            `json:"token"`
	Platform  string            `json:"platform"`
	CSRPEM    string            `json:"csr_pem"`
	RequestID string            `json:"request_id"`
	Server    *ServerEnrollment `json:"server,omitempty"`
}

// TransientError marks a claim attempt that is safe to replay with the same
// token/key/request_id/CSR. Protocol rejection and malformed success responses
// are deliberately not transient.
type TransientError struct{ cause error }

func (e *TransientError) Error() string { return e.cause.Error() }
func (e *TransientError) Unwrap() error { return e.cause }

// IsTransient reports whether an exact idempotent claim may be retried.
func IsTransient(err error) bool {
	var transient *TransientError
	return errors.As(err, &transient)
}

// Bootstrap is present only after the control plane has committed SSOT,
// credentials, certificates and signed release authority for this device.
type Bootstrap struct {
	NodeID            string   `json:"node_id"`
	DistributionURLs  []string `json:"distribution_urls"`
	DNS               []string `json:"dns"`
	SecretsEnv        string   `json:"secrets_env"`
	PlatformPublicKey string   `json:"platform_public_key"`
	ReleaseAuthority  string   `json:"release_authority"`
	CACertPEM         string   `json:"ca_cert_pem"`
	NodeCertPEM       string   `json:"node_cert_pem"`
}

// Response is the strict v1 enrollment response. No invitation token is part
// of this type, which also prevents accidentally persisting it.
type Response struct {
	Schema        int        `json:"schema"`
	ClientID      string     `json:"client_id"`
	Status        string     `json:"status"`
	ClaimedAt     string     `json:"claimed_at"`
	Replay        bool       `json:"replay"`
	Next          string     `json:"next"`
	Configuration string     `json:"configuration"`
	Bootstrap     *Bootstrap `json:"bootstrap,omitempty"`
}

// Paths names every file materialized before the first signed pull. Tests and
// recovery tools can move the whole bootstrap into an isolated root without
// changing protocol semantics.
type Paths struct {
	StateDir          string
	TLSKey            string
	TLSCert           string
	CACert            string
	PlatformPublicKey string
	Secrets           string
	NodeID            string
	ExpectedCurrent   string
}

// DefaultPaths uses the Linux locations already consumed by render/pull.
func DefaultPaths(stateDir string) Paths {
	return Paths{
		StateDir: stateDir, TLSKey: "/etc/loom/tls/node.key",
		TLSCert: "/etc/loom/tls/node.crt", CACert: "/etc/loom/tls/ca.crt",
		PlatformPublicKey: "/etc/loom/trust/platform.pub",
		Secrets:           "/etc/loom/secrets/node.env", NodeID: "/etc/loom/node-id",
		ExpectedCurrent: filepath.Join(stateDir, "expected-current.json"),
	}
}

// ParseInvite accepts only the fragment form. The bearer token therefore does
// not enter an HTTP request target, referrer, reverse-proxy log, or query log.
func ParseInvite(raw string) (Invite, error) {
	var out Invite
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > maxInviteBytes {
		return out, invalidInvite()
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "loom" || u.Host != "enroll" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment == "" {
		return out, invalidInvite()
	}
	decoded, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != u.Fragment || len(decoded) > maxInviteBytes {
		return out, invalidInvite()
	}
	var payload invitePayload
	dec := json.NewDecoder(bytes.NewReader(decoded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil || dec.Decode(&struct{}{}) != io.EOF || payload.Schema != Schema {
		return out, invalidInvite()
	}
	out = Invite{
		Endpoint: payload.Endpoint, Token: payload.Token, ExpiresAt: payload.ExpiresAt,
		PlatformKeySHA256: payload.PlatformKeySHA256,
	}
	if err := ValidateInvite(out); err != nil {
		return out, invalidInvite()
	}
	return out, nil
}

// ValidateInvite validates a decoded or protected join artifact without
// serializing its bearer token into an error. Windows uses it when recovering
// a DPAPI-protected pending join after the original QR is no longer present.
func ValidateInvite(invite Invite) error {
	endpoint, err := url.ParseRequestURI(invite.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.String() != invite.Endpoint {
		return invalidInvite()
	}
	token, err := base64.RawURLEncoding.DecodeString(invite.Token)
	if err != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != invite.Token {
		return invalidInvite()
	}
	if _, err := time.Parse(time.RFC3339, invite.ExpiresAt); err != nil {
		return invalidInvite()
	}
	if invite.PlatformKeySHA256 != "" {
		digest, err := hex.DecodeString(invite.PlatformKeySHA256)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != invite.PlatformKeySHA256 {
			return invalidInvite()
		}
	}
	return nil
}

func invalidInvite() error {
	// 错误不拼接原始 URI，否则 token 会进入终端/日志(§11 安全存储)。
	return errors.New("[§9.1 加入二维码] 加入码无效；请重新获取，不要复制或记录其原始内容")
}

// ReadInviteFile rejects links and bounds input before parsing it.
func ReadInviteFile(name string, stdin io.Reader) (Invite, error) {
	if name == "-" {
		body, err := io.ReadAll(io.LimitReader(stdin, maxInviteBytes+1))
		if err != nil || len(body) == 0 || len(body) > maxInviteBytes {
			return Invite{}, invalidInvite()
		}
		return ParseInvite(string(body))
	}
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() <= 0 || before.Size() > maxInviteBytes {
		return Invite{}, fmt.Errorf("[§9.1 加入二维码] 加入文件必须是小于 16 KiB 的非链接普通文件")
	}
	file, err := os.Open(name)
	if err != nil {
		return Invite{}, fmt.Errorf("读取加入文件失败")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		after.Size() <= 0 || after.Size() > maxInviteBytes {
		return Invite{}, fmt.Errorf("读取加入文件失败")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxInviteBytes+1))
	if err != nil || int64(len(body)) != after.Size() || len(body) > maxInviteBytes {
		return Invite{}, fmt.Errorf("读取加入文件失败")
	}
	return ParseInvite(string(body))
}

// Claim generates or reloads the device identity, then performs one idempotent
// claim attempt. Callers retry this function with the same StateDir and Invite
// while Configuration remains pending.
func Claim(ctx context.Context, client *http.Client, invite Invite, stateDir string, random io.Reader) (Response, error) {
	return ClaimWithServer(ctx, client, invite, stateDir, nil, random)
}

// ClaimWithServer uses the same identity transaction as Claim and adds only
// the public server facts prepared from the local Device config.
func ClaimWithServer(ctx context.Context, client *http.Client, invite Invite, stateDir string, server *ServerEnrollment, random io.Reader) (Response, error) {
	var zero Response
	if client == nil {
		return zero, errors.New("设备加入 HTTP 客户端为空")
	}
	if random == nil {
		random = rand.Reader
	}
	lock, err := lockStateDir(stateDir)
	if err != nil {
		return zero, err
	}
	defer unlockState(lock)
	meta, csrPEM, err := loadOrCreateIdentity(stateDir, invite.Endpoint, random)
	if err != nil {
		return zero, err
	}
	keyPEM, loadedMeta, err := loadIdentity(stateDir)
	if err != nil {
		return zero, err
	}
	if loadedMeta != meta {
		return zero, errors.New("[§4.3 设备绑定] 本机身份在加入事务中发生变化")
	}
	result, err := ClaimPrepared(ctx, client, invite, PreparedIdentity{
		Schema: Schema, Platform: Platform, Endpoint: meta.Endpoint, RequestID: meta.RequestID,
		PrivateKeyPEM: keyPEM, CSRPEM: csrPEM,
	}, server)
	if err != nil {
		return zero, err
	}
	stored, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return zero, err
	}
	stored = append(stored, '\n')
	if err := writePrivateAtomic(filepath.Join(stateDir, enrollmentFile), stored, 0o600); err != nil {
		return zero, fmt.Errorf("保存加入响应:%w", err)
	}
	return result, nil
}

func validateResponse(response Response, statusCode int) error {
	if response.Schema != Schema || strings.TrimSpace(response.ClientID) == "" {
		return errors.New("[§9.2 加入流程] 加入响应 schema/client_id 无效")
	}
	if _, err := time.Parse(time.RFC3339, response.ClaimedAt); err != nil {
		return errors.New("[§9.2 加入流程] 加入响应 claimed_at 无效")
	}
	switch response.Configuration {
	case "pending":
		if statusCode != http.StatusAccepted || response.Status != "provisioning" ||
			response.Next != "wait_for_configuration" || response.Bootstrap != nil {
			return errors.New("[§9.2 加入流程] pending 加入响应语义不一致")
		}
	case "ready":
		if statusCode != http.StatusOK || response.Status != "ready" || response.Next != "pull" || response.Bootstrap == nil {
			return errors.New("[§9.2 加入流程] ready 加入响应语义不一致")
		}
		if response.Bootstrap.NodeID != response.ClientID {
			return errors.New("[§4.3 设备绑定] ready 加入响应的 client_id 与 node_id 不一致")
		}
	default:
		return fmt.Errorf("[§4.5 fail closed] 不识别加入配置状态 %q", response.Configuration)
	}
	return nil
}

// InstallReady validates the complete bootstrap before changing any active
// path. Each file is individually atomic; enrollment.json is the durable
// retry record and no service is activated until the caller's signed pull.
func InstallReady(paths Paths, response Response) error {
	if response.Configuration != "ready" || response.Bootstrap == nil {
		return errors.New("[§10.3 原子安装] 没有完整 ready bootstrap，不安装")
	}
	if err := validateInstallPaths(paths); err != nil {
		return err
	}
	lock, err := lockStateDir(paths.StateDir)
	if err != nil {
		return err
	}
	defer unlockState(lock)
	keyPEM, meta, err := loadIdentity(paths.StateDir)
	if err != nil {
		return err
	}
	material, err := validateBootstrap(*response.Bootstrap, keyPEM)
	if err != nil {
		return err
	}
	if err := refuseIdentityReplacement(paths, material, keyPEM); err != nil {
		return err
	}
	files := []struct {
		path string
		body []byte
		mode os.FileMode
	}{
		{paths.PlatformPublicKey, material.platformPublicKey, 0o644},
		{paths.Secrets, []byte(response.Bootstrap.SecretsEnv), 0o600},
		{paths.CACert, []byte(response.Bootstrap.CACertPEM), 0o644},
		{paths.TLSKey, keyPEM, 0o600},
		{paths.TLSCert, []byte(response.Bootstrap.NodeCertPEM), 0o644},
		{paths.NodeID, []byte(response.Bootstrap.NodeID + "\n"), 0o644},
		{paths.ExpectedCurrent, material.releaseAuthority, 0o600},
	}
	for _, file := range files {
		if err := writePrivateAtomic(file.path, file.body, file.mode); err != nil {
			return fmt.Errorf("[§10.3 原子安装] 写 %s:%w", file.path, err)
		}
	}
	// Keep a non-secret link between the installed node identity and request.
	installed := struct {
		Schema    int    `json:"schema"`
		ClientID  string `json:"client_id"`
		NodeID    string `json:"node_id"`
		RequestID string `json:"request_id"`
		ClaimedAt string `json:"claimed_at"`
	}{Schema: Schema, ClientID: response.ClientID, NodeID: response.Bootstrap.NodeID, RequestID: meta.RequestID, ClaimedAt: response.ClaimedAt}
	body, err := json.MarshalIndent(installed, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateAtomic(filepath.Join(paths.StateDir, "installed.json"), append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("记录安装坐标:%w", err)
	}
	return nil
}

type validatedBootstrap struct {
	platformPublicKey []byte
	releaseAuthority  []byte
	nodeID            string
}

func validateBootstrap(bootstrap Bootstrap, keyPEM []byte) (validatedBootstrap, error) {
	var out validatedBootstrap
	if !model.ValidNodeID(bootstrap.NodeID) {
		return out, fmt.Errorf("[§10.2 渲染目标必须显式] bootstrap 节点 id %q 无效", bootstrap.NodeID)
	}
	if len(bootstrap.DistributionURLs) == 0 {
		return out, errors.New("[§14.2 节点自取] bootstrap 没有分发镜像")
	}
	seenURL := map[string]bool{}
	for _, raw := range bootstrap.DistributionURLs {
		u, err := url.ParseRequestURI(raw)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return out, fmt.Errorf("[§14.2 节点自取] bootstrap 分发镜像无效:%q", raw)
		}
		normalized := strings.TrimRight(raw, "/")
		if seenURL[normalized] {
			return out, fmt.Errorf("[§14.2 节点自取] bootstrap 分发镜像重复:%q", raw)
		}
		seenURL[normalized] = true
	}
	for _, dns := range bootstrap.DNS {
		if strings.TrimSpace(dns) == "" || strings.IndexFunc(dns, unicode.IsSpace) >= 0 || strings.IndexFunc(dns, unicode.IsControl) >= 0 {
			return out, errors.New("[§7.3.2 DNS] bootstrap DNS 坐标无效")
		}
	}
	if err := validateSecrets(bootstrap.SecretsEnv); err != nil {
		return out, err
	}
	pub, err := decodePlatformKey(bootstrap.PlatformPublicKey)
	if err != nil {
		return out, err
	}
	authority := []byte(bootstrap.ReleaseAuthority)
	current, err := publish.DecodeDeploymentCurrent(authority)
	if err != nil {
		return out, fmt.Errorf("[§4.3 签名高于传输信任] bootstrap release authority 无效:%w", err)
	}
	if err := current.Verify(pub); err != nil {
		return out, fmt.Errorf("[§4.3 签名高于传输信任] bootstrap release authority 验签失败:%w", err)
	}
	if _, err := current.Select(bootstrap.NodeID); err != nil {
		return out, fmt.Errorf("[§4.3 设备绑定] signed current 未授权本设备:%w", err)
	}
	privateKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		return out, err
	}
	if err := validateCertificates(bootstrap.CACertPEM, bootstrap.NodeCertPEM, bootstrap.NodeID, privateKey); err != nil {
		return out, err
	}
	out.platformPublicKey = append([]byte(base64.StdEncoding.EncodeToString(pub)), '\n')
	out.releaseAuthority = append(bytes.TrimSpace(authority), '\n')
	out.nodeID = bootstrap.NodeID
	return out, nil
}

func validateSecrets(body string) error {
	if strings.TrimSpace(body) == "" || len(body) > 1<<20 {
		return errors.New("[§4.2 配置与秘密分离] bootstrap 秘密层为空或过大")
	}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(body))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, _, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || seen[key] || strings.IndexFunc(key, unicode.IsSpace) >= 0 || strings.IndexFunc(key, unicode.IsControl) >= 0 {
			return fmt.Errorf("[§4.2 配置与秘密分离] bootstrap 秘密层第 %d 行无效", line)
		}
		seen[key] = true
	}
	if err := scanner.Err(); err != nil || len(seen) == 0 {
		return errors.New("[§4.2 配置与秘密分离] bootstrap 秘密层无有效条目")
	}
	return nil
}

func decodePlatformKey(body string) (ed25519.PublicKey, error) {
	raw := strings.TrimSpace(body)
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("[§4.3 签名高于传输信任] bootstrap 平台公钥无效")
	}
	return ed25519.PublicKey(key), nil
}

func validateCertificates(caPEM, certPEM, nodeID string, privateKey *ecdsa.PrivateKey) error {
	ca, err := parseOneCertificate(caPEM)
	if err != nil || !ca.IsCA {
		return errors.New("[§9.3 稳态认证] bootstrap CA 证书无效")
	}
	cert, err := parseOneCertificate(certPEM)
	if err != nil {
		return errors.New("[§9.3 稳态认证] bootstrap 节点证书无效")
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || publicKey.X.Cmp(privateKey.X) != 0 || publicKey.Y.Cmp(privateKey.Y) != 0 {
		return errors.New("[§4.3 设备绑定] 签发证书与本机私钥不匹配")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: nodeID + ".node.internal",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("[§9.3 稳态认证] 节点证书无法回溯到 bootstrap CA:%w", err)
	}
	return nil
}

func parseOneCertificate(body string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(body))
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("证书 PEM 必须只含一张证书")
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadOrCreateIdentity(stateDir, endpoint string, random io.Reader) (identityMeta, []byte, error) {
	metaPath := filepath.Join(stateDir, identityMetaFile)
	if _, err := os.Lstat(metaPath); err == nil {
		keyPEM, meta, err := loadIdentity(stateDir)
		_ = keyPEM
		if err != nil {
			return identityMeta{}, nil, err
		}
		if meta.Endpoint != endpoint || meta.Platform != Platform {
			return identityMeta{}, nil, errors.New("[§4.3 设备绑定] 已有设备身份绑定到另一控制中心；不会自动覆盖")
		}
		csr, err := readPrivateFile(filepath.Join(stateDir, identityCSRFile), 64<<10)
		return meta, csr, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return identityMeta{}, nil, err
	}
	key, keyPEM, err := loadOrCreatePrivateKey(filepath.Join(stateDir, identityKeyFile), random)
	if err != nil {
		return identityMeta{}, nil, err
	}
	requestID, err := randomUUID(random)
	if err != nil {
		return identityMeta{}, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(random, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: requestID},
	}, key)
	if err != nil {
		return identityMeta{}, nil, fmt.Errorf("生成 P-256 CSR:%w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return identityMeta{}, nil, err
	}
	meta := identityMeta{
		Schema: Schema, Platform: Platform, Endpoint: endpoint, RequestID: requestID,
		CSR: sha256Hex(csrPEM), PublicKey: sha256Hex(spki),
	}
	metaBody, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return identityMeta{}, nil, err
	}
	// meta 最后落盘，它是“这组 key/request_id/CSR 已提交准备好”的提交点。
	if err := writePrivateAtomic(filepath.Join(stateDir, identityCSRFile), csrPEM, 0o600); err != nil {
		return identityMeta{}, nil, err
	}
	if err := writePrivateAtomic(metaPath, append(metaBody, '\n'), 0o600); err != nil {
		return identityMeta{}, nil, err
	}
	_ = keyPEM
	return meta, csrPEM, nil
}

func loadOrCreatePrivateKey(path string, random io.Reader) (*ecdsa.PrivateKey, []byte, error) {
	if _, err := os.Lstat(path); err == nil {
		body, err := readPrivateFile(path, 64<<10)
		if err != nil {
			return nil, nil, err
		}
		key, err := parsePrivateKey(body)
		return key, body, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		return nil, nil, fmt.Errorf("生成设备 P-256 私钥:%w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writePrivateAtomic(path, body, 0o600); err != nil {
		return nil, nil, err
	}
	return key, body, nil
}

func loadIdentity(stateDir string) ([]byte, identityMeta, error) {
	var meta identityMeta
	metaBody, err := readPrivateFile(filepath.Join(stateDir, identityMetaFile), 64<<10)
	if err != nil {
		return nil, meta, err
	}
	dec := json.NewDecoder(bytes.NewReader(metaBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil || dec.Decode(&struct{}{}) != io.EOF || meta.Schema != Schema || meta.Platform != Platform || meta.RequestID == "" {
		return nil, identityMeta{}, errors.New("[§4.3 设备绑定] 本机 identity.json 无效")
	}
	keyPEM, err := readPrivateFile(filepath.Join(stateDir, identityKeyFile), 64<<10)
	if err != nil {
		return nil, identityMeta{}, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, identityMeta{}, err
	}
	csrPEM, err := readPrivateFile(filepath.Join(stateDir, identityCSRFile), 64<<10)
	if err != nil {
		return nil, identityMeta{}, err
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "" {
		return nil, identityMeta{}, errors.New("[§4.3 设备绑定] 本机 CSR 无效")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs) != 0 {
		return nil, identityMeta{}, errors.New("[§4.3 设备绑定] 本机 CSR 签名/SAN 无效")
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.X.Cmp(key.X) != 0 || publicKey.Y.Cmp(key.Y) != 0 || meta.CSR != sha256Hex(csrPEM) {
		return nil, identityMeta{}, errors.New("[§4.3 设备绑定] 本机 key/CSR/identity 不匹配")
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if meta.PublicKey != sha256Hex(spki) {
		return nil, identityMeta{}, errors.New("[§4.3 设备绑定] 本机公钥指纹不匹配")
	}
	return keyPEM, meta, nil
}

func parsePrivateKey(body []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("[§11 安全存储] 设备私钥必须是单个 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("[§11 安全存储] 设备私钥不是 P-256 PKCS#8")
	}
	return key, nil
}

func randomUUID(random io.Reader) (string, error) {
	body := make([]byte, 16)
	if _, err := io.ReadFull(random, body); err != nil {
		return "", err
	}
	body[6] = (body[6] & 0x0f) | 0x40
	body[8] = (body[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", body[:4], body[4:6], body[6:8], body[8:10], body[10:]), nil
}

func validateInstallPaths(paths Paths) error {
	ordered := []struct{ name, value string }{
		{"state-dir", paths.StateDir}, {"tls-key", paths.TLSKey}, {"tls-cert", paths.TLSCert},
		{"ca-cert", paths.CACert}, {"platform-pubkey", paths.PlatformPublicKey},
		{"secrets", paths.Secrets}, {"node-id", paths.NodeID}, {"expected-current", paths.ExpectedCurrent},
	}
	for _, item := range ordered {
		name, value := item.name, item.value
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("[§10.3 原子安装] %s 必须是绝对且已清理的路径:%q", name, value)
		}
	}
	return nil
}

func refuseIdentityReplacement(paths Paths, material validatedBootstrap, keyPEM []byte) error {
	checks := []struct {
		path string
		want []byte
		name string
	}{
		{paths.NodeID, []byte(material.nodeID + "\n"), "节点 id"},
		{paths.TLSKey, keyPEM, "设备私钥"},
		{paths.PlatformPublicKey, material.platformPublicKey, "平台信任根"},
	}
	for _, check := range checks {
		existing, err := readRegularFile(check.path, 1<<20, check.path == paths.TLSKey)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, check.want) {
			return fmt.Errorf("[§4.3 设备绑定] %s 已存在且与本次 bootstrap 不同；不会自动覆盖", check.name)
		}
	}
	return nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	return readRegularFile(path, limit, true)
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
