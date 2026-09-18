package control

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"loom/internal/clientrelease"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	State       State
	ReleaseRoot string
	ReleaseKey  string
	mu          sync.Mutex
}

func (server *Server) Serve(ctx context.Context) error {
	if err := server.State.Validate(); err != nil {
		return err
	}
	certificate, err := tls.X509KeyPair([]byte(server.State.BrowserTLS.CertificateChainPEM), []byte(server.State.BrowserTLS.PrivateKeyPKCS8PEM))
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAnyClientCert}
	overlay, err := net.Listen("tcp", server.State.Listen)
	if err != nil {
		return fmt.Errorf("listen private control UI: %w", err)
	}
	defer overlay.Close()
	_, port, _ := net.SplitHostPort(server.State.Listen)
	loopbackAddress := net.JoinHostPort("127.0.0.1", port)
	loopback, err := net.Listen("tcp4", loopbackAddress)
	if err != nil {
		return fmt.Errorf("listen loopback control UI: %w", err)
	}
	defer loopback.Close()

	handler := server.Handler()
	servers := []*http.Server{
		{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
		{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
	}
	errorsOut := make(chan error, 2)
	go func() { errorsOut <- servers[0].Serve(tls.NewListener(overlay, tlsConfig.Clone())) }()
	go func() { errorsOut <- servers[1].Serve(tls.NewListener(loopback, tlsConfig.Clone())) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, service := range servers {
			_ = service.Shutdown(shutdown)
		}
		return nil
	case err := <-errorsOut:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", secureFiles(http.FileServer(http.FS(assets)))))
	mux.HandleFunc("GET /favicon.svg", func(writer http.ResponseWriter, request *http.Request) {
		serveEmbedded(writer, request, "favicon.svg", "image/svg+xml")
	})
	mux.HandleFunc("GET /api/control/ui", server.snapshot)
	mux.HandleFunc("GET /api/control/ui/snapshot", server.snapshot)
	mux.HandleFunc("GET /api/control/ui/events", server.events)
	mux.HandleFunc("GET /api/control/ui/releases/files/", server.download)
	mux.HandleFunc("/", server.page)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "same-origin")
		writer.Header().Set("Cache-Control", "no-store")
		if request.URL.RawPath != "" || path.Clean(request.URL.Path) != request.URL.Path || request.TLS == nil ||
			!request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 || !server.exactHost(request.Host) {
			http.NotFound(writer, request)
			return
		}
		if !server.authorized(request) {
			http.Error(writer, "control certificate required", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

func (server *Server) snapshot(writer http.ResponseWriter, request *http.Request) {
	projection := server.State.Projection
	catalog, err := server.catalog()
	if err != nil {
		projection.UIState.Warnings = append(projection.UIState.Warnings, "Verified release catalog is unavailable.")
	} else {
		projection.Releases = make([]Release, 0, len(catalog.Artifacts))
		for _, artifact := range catalog.Artifacts {
			projection.Releases = append(projection.Releases, Release{Path: artifact.Path, Name: artifact.Name,
				Title: artifact.Title, Platform: artifact.Platform, Arch: artifact.Arch, Variant: artifact.Variant,
				Version: artifact.Version, SourceCommit: artifact.SourceCommit, SHA256: artifact.SHA256,
				Size: artifact.Size, Signing: artifact.Signing, URL: "/api/control/ui/releases/files/" + artifact.Path})
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"capabilities": map[string]bool{"admin": server.admin(request)}, "projection": projection})
}

func (server *Server) events(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"events": server.State.Projection.Events})
}

func (server *Server) download(writer http.ResponseWriter, request *http.Request) {
	prefix := "/api/control/ui/releases/files/"
	relative := strings.TrimPrefix(request.URL.Path, prefix)
	if relative == request.URL.Path || relative == "" || strings.Contains(relative, "..") {
		http.NotFound(writer, request)
		return
	}
	catalog, err := server.catalog()
	if err != nil {
		http.Error(writer, "verified release catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	file, found := clientrelease.Find(catalog, relative)
	if !found {
		http.NotFound(writer, request)
		return
	}
	opened, err := clientrelease.OpenVerified(server.ReleaseRoot, file)
	if err != nil {
		http.Error(writer, "release bytes failed verification", http.StatusServiceUnavailable)
		return
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil {
		http.Error(writer, "release bytes unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", url.PathEscape(file.Name)))
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	writer.Header().Set("ETag", `"`+file.SHA256+`"`)
	http.ServeContent(writer, request, file.Name, info.ModTime(), opened)
}

func (server *Server) page(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.NotFound(writer, request)
		return
	}
	for _, prefix := range []string{"/api/", "/private/", "/loom-client/", "/device-dist/", "/act/"} {
		if strings.HasPrefix(request.URL.Path, prefix) {
			http.NotFound(writer, request)
			return
		}
	}
	allowed := map[string]bool{"/": true, "/devices": true, "/topology": true, "/routing": true,
		"/services": true, "/releases": true, "/events": true, "/ssot": true, "/settings": true}
	if !allowed[request.URL.Path] && !strings.HasPrefix(request.URL.Path, "/devices/") {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	serveEmbedded(writer, request, "index.html", "text/html; charset=utf-8")
}

func (server *Server) catalog() (clientrelease.Catalog, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	key, err := clientrelease.PublicKey(server.ReleaseKey)
	if err != nil {
		return clientrelease.Catalog{}, err
	}
	return clientrelease.Read(server.ReleaseRoot, key)
}

func (server *Server) exactHost(host string) bool {
	address, port, err := net.SplitHostPort(server.State.Listen)
	if err != nil {
		return false
	}
	return host == net.JoinHostPort(address, port) || host == net.JoinHostPort("127.0.0.1", port)
}

func (server *Server) admin(request *http.Request) bool {
	return exactCertificate(request, server.State.AdminCertDER)
}

func (server *Server) authorized(request *http.Request) bool {
	return exactCertificate(request, server.State.ReadCertDER)
}

func exactCertificate(request *http.Request, allowed []string) bool {
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
		return false
	}
	raw := request.TLS.PeerCertificates[0].Raw
	for _, encoded := range allowed {
		candidate, err := base64.RawURLEncoding.DecodeString(encoded)
		if err == nil && len(candidate) == len(raw) && subtle.ConstantTimeCompare(candidate, raw) == 1 {
			return true
		}
	}
	return false
}

func secureFiles(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(writer, request)
	})
}

func serveEmbedded(writer http.ResponseWriter, request *http.Request, name, contentType string) {
	body, err := staticFiles.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	if contentType == "" {
		contentType = mime.TypeByExtension(path.Ext(name))
	}
	writer.Header().Set("Content-Type", contentType)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(body)
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
