// Package distribution 固化公网静态分发边界；它不含 Enrollment 或控制 handler。
package distribution

import (
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
		response.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		if request.Method == http.MethodGet {
			_, _ = response.Write(body)
		}
	}), nil
}

func safeAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\r\n{};")
}
