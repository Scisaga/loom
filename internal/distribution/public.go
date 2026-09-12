// Package distribution 固化公网静态分发边界；它不含 Enrollment 或控制 handler。
package distribution

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"loom/internal/wire"
)

var digestPath = regexp.MustCompile(`^/distribution/sha256/[0-9a-f]{64}$`)

type NginxInput struct {
	FQDN           string
	PublicPort     int
	Certificate    string
	CertificateKey string
	StaticRoot     string
}

// RenderNginx 只渲染 fake root 与内容寻址 GET/HEAD；所有其他路径直接 404。
func RenderNginx(input NginxInput) ([]byte, error) {
	if !wire.ValidFQDN(input.FQDN) || input.PublicPort < 1 || input.PublicPort > 65535 ||
		!safeAbsolutePath(input.Certificate) || !safeAbsolutePath(input.CertificateKey) || !safeAbsolutePath(input.StaticRoot) {
		return nil, errors.New("[D131 public surface] Nginx FQDN/port/path 无效")
	}
	config := fmt.Sprintf(`server {
    listen %d ssl;
    server_name %s;
    ssl_certificate %s;
    ssl_certificate_key %s;
    server_tokens off;
    access_log off;

    location = / {
        root %s;
        limit_except GET HEAD { deny all; }
        try_files /index.html =404;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    location ~ ^/distribution/sha256/[0-9a-f]{64}$ {
        root %s;
        disable_symlinks on from=$document_root;
        limit_except GET HEAD { deny all; }
        try_files $uri =404;
        default_type application/octet-stream;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    location / { return 404; }
}
`, input.PublicPort, input.FQDN, input.Certificate, input.CertificateKey, input.StaticRoot, input.StaticRoot)
	if err := ValidatePublicNginx([]byte(config)); err != nil {
		return nil, err
	}
	return []byte(config), nil
}

// ValidatePublicNginx 是部署前的静态兜底，拒绝动态 handler/反代和旧公开控制路径。
func ValidatePublicNginx(config []byte) error {
	lower := strings.ToLower(string(config))
	for _, forbidden := range []string{
		"proxy_pass", "fastcgi_pass", "grpc_pass", "uwsgi_pass", "scgi_pass",
		"/enroll", "/claim", "/control", "/config", "/report", "current.json",
		"return 30", "proxy_set_header", "auth_request", "cookie",
	} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("[D131 public surface] 公网 Nginx 含禁止能力 %q", forbidden)
		}
	}
	if !strings.Contains(lower, "limit_except get head") ||
		!strings.Contains(lower, "^/distribution/sha256/[0-9a-f]{64}$") ||
		!strings.Contains(lower, "disable_symlinks on") ||
		!strings.Contains(lower, "location / { return 404; }") {
		return errors.New("[D131 public surface] Nginx 未固定 GET/HEAD + immutable hash path + default 404")
	}
	return nil
}

// StaticHandler 让集成测试和不使用 Nginx 的部署共享同一公开 HTTP 语义。
func StaticHandler(root string) (http.Handler, error) {
	if !safeAbsolutePath(root) {
		return nil, errors.New("[D131 public surface] static root 必须是规范绝对路径")
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			response.Header().Set("Allow", "GET, HEAD")
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var file string
		switch {
		case request.URL.Path == "/" && request.URL.RawQuery == "":
			file = filepath.Join(root, "index.html")
			response.Header().Set("Cache-Control", "no-store")
		case digestPath.MatchString(request.URL.Path) && request.URL.RawQuery == "":
			file = filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(request.URL.Path, "/")))
			response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			response.Header().Set("Content-Type", "application/octet-stream")
		default:
			http.NotFound(response, request)
			return
		}
		response.Header().Set("X-Content-Type-Options", "nosniff")
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			http.NotFound(response, request)
			return
		}
		body, err := os.ReadFile(file)
		if err != nil {
			http.NotFound(response, request)
			return
		}
		// 公开路径同时承载 raw SHA-256 blob 与 domain-separated canonical
		// object。后者不能由无上下文的镜像自行重算；它只负责返回 immutable
		// bytes，最终消费者必须按已认证 ref 中的 domain/hash 重新验证。
		response.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		if request.Method == http.MethodGet {
			_, _ = response.Write(body)
		}
	}), nil
}

// PublishArtifact 以原始制品 SHA-256 命名并原子落盘；重复发布相同 bytes 幂等，
// 已存在但内容不同则视为镜像损坏，不能覆盖后继续服务（D131）。
func PublishArtifact(root string, body []byte) (string, error) {
	if !safeAbsolutePath(root) {
		return "", errors.New("[D131 distribution] static root 必须是规范绝对路径")
	}
	digest := sha256.Sum256(body)
	hexDigest := hex.EncodeToString(digest[:])
	return publishAtDigest(root, hexDigest, body)
}

// PublishCanonicalObject 发布由协议 domain 分隔的 exact canonical JSON。
// URL 使用 typed hash，而不是原始 bytes 的 SHA-256；这与 bootstrap/config
// reader 的 FetchCanonicalObject 契约一致（D104、D124、D131）。
func PublishCanonicalObject(root, domain string, body []byte) (string, string, error) {
	if !safeAbsolutePath(root) {
		return "", "", errors.New("[D131 distribution] static root 必须是规范绝对路径")
	}
	typedHash, hexDigest, err := canonicalObjectHash(domain, body)
	if err != nil {
		return "", "", err
	}
	path, err := publishAtDigest(root, hexDigest, body)
	if err != nil {
		return "", "", err
	}
	return typedHash, path, nil
}

func canonicalObjectHash(domain string, body []byte) (string, string, error) {
	if domain == "" || len(body) == 0 {
		return "", "", errors.New("[D104 distribution] canonical object domain/body 缺失")
	}
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return "", "", errors.New("[D104 distribution] object 不是 exact canonical JSON")
	}
	typedHash, err := wire.HashCanonical(domain, body)
	if err != nil {
		return "", "", err
	}
	digest, err := wire.ParseHash(typedHash)
	if err != nil {
		return "", "", err
	}
	return typedHash, hex.EncodeToString(digest), nil
}

// PublishDeviceConfigArtifact 把 renderer 产出的无秘密 canonical config 放到
// public immutable surface，并返回可直接进入 certified Device view 的 exact ref。
func PublishDeviceConfigArtifact(root, artifactID, platform, mediaType, renderContractID string,
	generation int64, body []byte,
) (wire.DeviceConfigArtifactRefV1, string, error) {
	if !safeAbsolutePath(root) {
		return wire.DeviceConfigArtifactRefV1{}, "", errors.New("[D131 distribution] static root 必须是规范绝对路径")
	}
	typedHash, hexDigest, err := canonicalObjectHash(wire.DomainDeviceConfigArtifact, body)
	if err != nil {
		return wire.DeviceConfigArtifactRefV1{}, "", err
	}
	ref := wire.DeviceConfigArtifactRefV1{
		ArtifactID: artifactID, Generation: generation, Platform: platform,
		MediaType: mediaType, RenderContractID: renderContractID,
		SizeBytes: int64(len(body)), ContentHash: typedHash,
	}
	if err := wire.ValidateDeviceConfigArtifactRef(&ref); err != nil {
		return wire.DeviceConfigArtifactRefV1{}, "", err
	}
	path, err := publishAtDigest(root, hexDigest, body)
	if err != nil {
		return wire.DeviceConfigArtifactRefV1{}, "", err
	}
	return ref, path, nil
}

func publishAtDigest(root, hexDigest string, body []byte) (string, error) {
	if !safeAbsolutePath(root) || len(hexDigest) != sha256.Size*2 {
		return "", errors.New("[D131 distribution] publish root/digest 无效")
	}
	if _, err := hex.DecodeString(hexDigest); err != nil {
		return "", errors.New("[D131 distribution] publish digest 无效")
	}
	directory := filepath.Join(root, "distribution", "sha256")
	path := filepath.Join(directory, hexDigest)
	if err := verifyExistingArtifact(path, body); err == nil {
		return "/distribution/sha256/" + hexDigest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(directory, ".artifact-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o644); err == nil {
		_, err = temporary.Write(body)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	// link(2) 的 no-replace 语义避免并发 publisher 越过上面的预检后覆盖
	// 已发布内容；竞争者只能接受 exact bytes，不能把冲突隐藏成成功。
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		if err := verifyExistingArtifact(path, body); err != nil {
			return "", err
		}
	}
	if err := os.Remove(temporaryPath); err != nil {
		return "", err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return "", err
	}
	err = directoryHandle.Sync()
	closeErr = directoryHandle.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return "/distribution/sha256/" + hexDigest, nil
}

func verifyExistingArtifact(path string, body []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("[D131 distribution] digest path 已被非普通文件占用")
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(existing, body) {
		return errors.New("[D131 distribution] digest path 已存在不同内容")
	}
	return nil
}

func safeAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\r\n{};")
}
