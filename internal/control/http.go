package control

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"loom/internal/clientrelease"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	Runtime     *Runtime
	Channel     *PrivateChannel
	Config      NodeConfig
	ReleaseRoot string
	ReleaseKey  string
	AdminSocket string
	Now         func() time.Time
	Endpoints   *EndpointRuntime
	Reports     *ObservationStore
	mu          sync.Mutex
}

func (server *Server) Serve(ctx context.Context, reportHandler http.Handler) error {
	if server.Runtime == nil || server.Channel == nil || reportHandler == nil || server.AdminSocket == "" {
		return errors.New("control runtime, private channel, report handler, and admin socket are required")
	}
	if err := server.Config.Validate(); err != nil {
		return err
	}
	defer server.Channel.Close()
	admin, err := net.Listen("unix", server.AdminSocket)
	if err != nil {
		return fmt.Errorf("listen local control admin socket: %w", err)
	}
	defer admin.Close()
	if err := os.Chmod(server.AdminSocket, 0o600); err != nil {
		return err
	}
	endpoints, err := NewEndpointRuntime(server.Runtime.Authority, server.Config.Node, func() time.Time { return server.now() })
	if err != nil {
		return err
	}
	server.Endpoints = endpoints
	defer endpoints.Close()

	handler := server.Handler()
	servers := []*http.Server{
		{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
		{Handler: reportHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
		{Handler: server.AdminHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
		{Handler: server.DeviceHandler(), ConnContext: endpointConnContext, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
	}
	errorsOut := make(chan error, 4)
	go func() { errorsOut <- servers[0].Serve(server.Channel.ControlListener()) }()
	go func() { errorsOut <- servers[1].Serve(server.Channel.ReportListener()) }()
	go func() { errorsOut <- servers[2].Serve(admin) }()
	go func() { errorsOut <- servers[3].Serve(endpoints) }()
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

type adminContextKey struct{}

func (server *Server) AdminHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/internal/") {
			http.NotFound(writer, request)
			return
		}
		server.Handler().ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), adminContextKey{}, true)))
	})
}

func localAdmin(request *http.Request) bool {
	value, _ := request.Context().Value(adminContextKey{}).(bool)
	return value
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
	mux.HandleFunc("POST /api/control/operations", server.operation)
	mux.HandleFunc("PUT /internal/materials/{digest}", server.internalMaterial)
	mux.HandleFunc("GET /internal/materials", server.internalMaterialIDs)
	mux.HandleFunc("POST /internal/head/sign", server.internalSign)
	mux.HandleFunc("PUT /internal/certified", server.internalCertified)
	mux.HandleFunc("POST /internal/submit", server.internalSubmit)
	mux.HandleFunc("/", server.page)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "same-origin")
		writer.Header().Set("Cache-Control", "no-store")
		local := localAdmin(request)
		if request.URL.RawPath != "" || path.Clean(request.URL.Path) != request.URL.Path || !local && (request.TLS == nil ||
			!request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 || !server.exactHost(request.Host)) {
			http.NotFound(writer, request)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/internal/") {
			mux.ServeHTTP(writer, request)
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
	_, _, certified := server.Runtime.Authority.Snapshot()
	projectionBody, err := canonical(certified.Projection.Web)
	if err != nil {
		http.Error(writer, "control projection unavailable", http.StatusServiceUnavailable)
		return
	}
	var projection WebProjection
	if err := json.Unmarshal(projectionBody, &projection); err != nil {
		http.Error(writer, "control projection unavailable", http.StatusServiceUnavailable)
		return
	}
	if server.Reports != nil {
		server.Reports.Project(&projection, certified.Projection, server.now())
	}
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
	response := map[string]any{"capabilities": map[string]bool{"admin": server.admin(request)}, "projection": projection}
	if server.Reports != nil {
		response["reports"] = server.Reports.Verified(certified.Projection)
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) events(writer http.ResponseWriter, _ *http.Request) {
	_, _, certified := server.Runtime.Authority.Snapshot()
	writeJSON(writer, http.StatusOK, map[string]any{"events": certified.Projection.Web.Events})
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
	for _, address := range server.Channel.ListenAddresses() {
		if host == address {
			return true
		}
	}
	return false
}

func (server *Server) admin(request *http.Request) bool {
	return localAdmin(request) || exactCertificate(request, server.Config.AdminCertDER)
}

func (server *Server) authorized(request *http.Request) bool {
	return localAdmin(request) || exactCertificate(request, server.Config.ReadCertDER)
}

type operationEnvelope struct {
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	RequestID string          `json:"request_id"`
	BaseHead  string          `json:"base_head"`
}

func (server *Server) operation(writer http.ResponseWriter, request *http.Request) {
	if !server.admin(request) {
		http.Error(writer, "administrator certificate required", http.StatusForbidden)
		return
	}
	if origin := request.Header.Get("Origin"); !localAdmin(request) && origin != "" && origin != "https://"+request.Host {
		http.Error(writer, "same-origin request required", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 8<<20))
	if err != nil {
		http.Error(writer, "invalid operation", http.StatusBadRequest)
		return
	}
	var envelope operationEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.RequestID == "" || envelope.BaseHead == "" {
		http.Error(writer, "invalid operation", http.StatusBadRequest)
		return
	}
	var result CertifiedState
	extra := map[string]any{}
	switch envelope.Kind {
	case "service.put":
		var service Service
		if err := decodeRawStrict(envelope.Payload, &service); err != nil {
			http.Error(writer, "invalid service", http.StatusBadRequest)
			return
		}
		sort.Strings(service.Matchers)
		material := Material{Schema: MaterialSchema, Kind: envelope.Kind, RequestID: envelope.RequestID, BaseHead: envelope.BaseHead, Service: &service}
		materialBody, _, err := EncodeMaterial(material)
		if err == nil {
			result, err = server.Runtime.Submit(request.Context(), materialBody)
		}
	case "members.replace":
		var payload struct {
			Members []Member `json:"members"`
		}
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid members", http.StatusBadRequest)
			return
		}
		result, err = server.Runtime.ReplaceMembers(request.Context(), envelope.RequestID, envelope.BaseHead, payload.Members)
	case "endpoint.put":
		var generation EndpointGeneration
		if err := decodeRawStrict(envelope.Payload, &generation); err != nil {
			http.Error(writer, "invalid endpoint generation", http.StatusBadRequest)
			return
		}
		result, err = server.putEndpoint(request.Context(), envelope.RequestID, envelope.BaseHead, generation)
	case "device.put":
		var payload deviceUpdatePayload
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid device update", http.StatusBadRequest)
			return
		}
		result, err = server.putDevice(request.Context(), envelope.RequestID, envelope.BaseHead, payload)
	case "enrollment.create":
		var payload enrollmentCreatePayload
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid enrollment", http.StatusBadRequest)
			return
		}
		var invite string
		result, invite, err = server.createEnrollment(request.Context(), envelope.RequestID, envelope.BaseHead, payload)
		if err == nil {
			extra["invite"] = invite
		}
	case "enrollment.approve":
		var payload struct {
			TransactionID string `json:"transaction_id"`
		}
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid enrollment approval", http.StatusBadRequest)
			return
		}
		result, err = server.approveEnrollment(request.Context(), envelope.RequestID, envelope.BaseHead, payload.TransactionID)
	default:
		http.Error(writer, "unknown operation", http.StatusBadRequest)
		return
	}
	if err != nil {
		status := http.StatusServiceUnavailable
		if strings.Contains(err.Error(), "stale") {
			status = http.StatusConflict
		}
		http.Error(writer, err.Error(), status)
		return
	}
	response := map[string]any{"head": result.Head, "projection": result.Projection.Web}
	for key, value := range extra {
		response[key] = value
	}
	writeJSON(writer, http.StatusOK, response)
}

func decodeRawStrict(body []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing content")
	}
	return nil
}

func (server *Server) internalBody(writer http.ResponseWriter, request *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(request.Body, 4<<20))
	if err != nil || !server.Runtime.verifyRequest(request, body) {
		http.Error(writer, "authenticated control member required", http.StatusForbidden)
		return nil, false
	}
	return body, true
}

func (server *Server) internalMaterial(writer http.ResponseWriter, request *http.Request) {
	body, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	id, err := server.Runtime.Authority.PutMaterial(body)
	if err != nil || strings.TrimPrefix(id, "sha256:") != request.PathValue("digest") {
		http.Error(writer, "material mismatch", http.StatusBadRequest)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"material_id": id})
}

func (server *Server) internalMaterialIDs(writer http.ResponseWriter, request *http.Request) {
	_, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	ids, err := server.Runtime.Authority.MaterialIDs()
	if err != nil {
		http.Error(writer, "material store unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, ids)
}

func (server *Server) internalSign(writer http.ResponseWriter, request *http.Request) {
	body, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	var head GovernanceHead
	if err := decodeRawStrict(body, &head); err != nil {
		http.Error(writer, "invalid head", http.StatusBadRequest)
		return
	}
	signature, err := server.Runtime.Authority.SignCandidate(server.Config, head)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(writer, http.StatusOK, signature)
}

func (server *Server) internalCertified(writer http.ResponseWriter, request *http.Request) {
	body, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	var head GovernanceHead
	if err := decodeRawStrict(body, &head); err != nil || server.Runtime.Authority.InstallCertified(head) != nil {
		http.Error(writer, "invalid certified head", http.StatusConflict)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]bool{"installed": true})
}

func (server *Server) internalSubmit(writer http.ResponseWriter, request *http.Request) {
	body, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	result, err := server.Runtime.SubmitForwarded(request.Context(), body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, result)
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
