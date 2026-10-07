package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

//go:embed static/*
var staticFiles embed.FS

const controlHTTPBodyLimit = 8 << 20

type Server struct {
	Runtime       *Runtime
	Channel       *PrivateChannel
	Config        NodeConfig
	AdminSocket   string
	Now           func() time.Time
	Endpoints     *EndpointRuntime
	Releases      ReleaseSource
	SSH           SSHExecutor
	mu            sync.Mutex
	endpointsMu   sync.RWMutex
	sshMu         sync.Mutex
	sshContext    context.Context
	sshExecutions map[string]SSHExecution
	sshWorkers    sync.WaitGroup
}

func (server *Server) Serve(ctx context.Context) (retErr error) {
	if server.Runtime == nil || server.Runtime.Reports == nil || server.AdminSocket == "" {
		return errors.New("control runtime, protected report history and admin socket are required")
	}
	if err := server.Config.Validate(); err != nil {
		return err
	}
	parent := filepath.Dir(server.AdminSocket)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("admin socket requires an owner-only parent directory")
	}
	admin, err := listenControlAdmin(ctx, server.AdminSocket)
	if err != nil {
		return fmt.Errorf("listen local control admin socket: %w", err)
	}
	defer func() {
		if err := admin.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = errors.Join(retErr, err)
		}
	}()
	stopSSH := server.startSSHWorkers(ctx)
	defer stopSSH()
	endpoint := server.endpointRuntime()
	if endpoint == nil {
		endpoint, err = NewEndpointRuntime(server.Runtime.Authority, server.Config.ControlID, server.now)
		if err != nil {
			return err
		}
		server.endpointsMu.Lock()
		server.Endpoints = endpoint
		server.endpointsMu.Unlock()
	}
	defer func() { retErr = errors.Join(retErr, endpoint.Close()) }()
	listeners := []net.Listener{admin}
	handlers := []http.Handler{server.AdminHandler()}
	if server.Channel != nil {
		listeners = append(listeners, server.Channel.ControlListener())
		handlers = append(handlers, server.Handler())
	}
	listeners = append(listeners, endpoint, endpoint.WebListener())
	handlers = append(handlers, server.DeviceHandler(), server.Handler())
	servers := make([]*http.Server, len(listeners))
	errorsOut := make(chan error, len(listeners))
	for i, listener := range listeners {
		service := &http.Server{Handler: handlers[i], ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return endpointConnContext(controlConnContext(ctx, conn), conn)
		},
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute}
		servers[i] = service
		go func() { errorsOut <- service.Serve(listener) }()
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, service := range servers {
			if err := service.Shutdown(shutdown); err != nil {
				retErr = errors.Join(retErr, err, service.Close())
			}
		}
	}()
	expiry := time.NewTimer(0)
	defer expiry.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-expiry.C:
			if server.Runtime.Writable() {
				check, cancel := context.WithTimeout(ctx, 5*time.Second)
				changed, err := server.Runtime.Authority.ExpireUnboundInvites(check, server.now(), server.Config)
				cancel()
				if changed > 0 && server.Runtime.Channel != nil {
					select {
					case server.Runtime.wake <- struct{}{}:
					default:
					}
				}
				if err != nil && ctx.Err() == nil {
					// Keep repair access and the original facts. Endpoint expiry
					// still refuses new claims; logs contain no invitation input.
					log.Print("control: could not persist expired invitation; will retry")
				}
			}
			expiry.Reset(5 * time.Second)
		case err := <-errorsOut:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		}
	}
}

func (server *Server) endpointRuntime() *EndpointRuntime {
	server.endpointsMu.RLock()
	defer server.endpointsMu.RUnlock()
	return server.Endpoints
}

type adminContextKey struct{}

func localAdmin(request *http.Request) bool {
	value, _ := request.Context().Value(adminContextKey{}).(bool)
	return value
}
func (server *Server) AdminHandler() http.Handler {
	handler := server.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/internal/") {
			http.NotFound(w, r)
			return
		}
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminContextKey{}, true)))
	})
}

func (server *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", secureFiles(http.FileServer(http.FS(assets)))))
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, r *http.Request) { serveEmbedded(w, r, "favicon.svg", "image/svg+xml") })
	mux.HandleFunc("GET /api/control/ui/snapshot", server.snapshot)
	mux.HandleFunc("GET /api/control/ui/path-history", server.pathHistory)
	mux.HandleFunc("GET /api/control/ui/live", server.live)
	mux.HandleFunc("POST /api/control/operations", server.operation)
	mux.HandleFunc("GET /api/control/ui/enrollment-options", server.enrollmentOptions)
	mux.HandleFunc("POST /api/control/ui/ssh/check", server.sshPreflight)
	mux.HandleFunc("POST /api/control/ui/invites/{transaction}/ssh", server.sshExecute)
	mux.HandleFunc("GET /api/control/ui/invites/{transaction}", server.inviteReadback)
	mux.HandleFunc("GET /api/control/ui/invites/{transaction}/qr.png", server.inviteQR)
	mux.HandleFunc("GET /api/control/ui/invites/{transaction}/download", server.inviteDownload)
	mux.HandleFunc("GET /api/control/releases/{catalog}/{artifact}/{file}", server.releaseDownload)
	mux.HandleFunc("GET /api/control/releases/inputs", server.releaseDeploymentInputs)
	mux.HandleFunc("GET /api/control/public-trust/{id}/certificate", server.websiteRootDownload)
	mux.HandleFunc("GET /internal/frontier", server.internalFrontier)
	mux.HandleFunc("GET /internal/material-conflicts", server.internalMaterialConflicts)
	mux.HandleFunc("GET /internal/materials", server.internalMaterialsAfter)
	mux.HandleFunc("GET /internal/materials/{digest}", server.internalMaterial)
	mux.HandleFunc("PUT /internal/materials/{digest}", server.internalMaterial)
	mux.HandleFunc("GET /internal/report-ranges", server.internalReportRanges)
	mux.HandleFunc("POST /internal/report-ids", server.internalReportIDs)
	mux.HandleFunc("POST /internal/reports", server.internalReports)
	mux.HandleFunc("/", server.page)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil {
			if state, ok := r.Context().Value(memberTLSContextKey{}).(tls.ConnectionState); ok {
				r = r.Clone(r.Context())
				r.TLS = &state
			}
		}
		if r.URL.RawPath != "" || path.Clean(r.URL.Path) != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		internal := strings.HasPrefix(r.URL.Path, "/internal/")
		if !localAdmin(r) {
			if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 {
				http.NotFound(w, r)
				return
			}
			if internal {
				if !server.memberRequest(r) {
					http.NotFound(w, r)
					return
				}
			} else if !server.exactHost(r.Host) {
				http.NotFound(w, r)
				return
			}
		}
		if internal {
			if localAdmin(r) {
				http.NotFound(w, r)
				return
			}
		} else if strings.HasPrefix(r.URL.Path, "/api/") && !server.admin(r) {
			http.Error(w, "administrator certificate required", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (server *Server) exactHost(host string) bool {
	if server.Channel != nil {
		for _, address := range server.Channel.ListenAddresses() {
			if host == address {
				return true
			}
		}
	}
	for _, endpoint := range server.Runtime.Authority.Snapshot().EndpointGenerations {
		if endpoint.OwnerControlID != server.Config.ControlID || endpoint.State != "serving" && endpoint.State != "prepared" || !containsString(endpoint.Modes, "web") {
			continue
		}
		expected := net.JoinHostPort(endpoint.ServerName, strconv.Itoa(endpoint.Port))
		if host == expected || endpoint.Port == 443 && host == endpoint.ServerName {
			return true
		}
	}
	return false
}
func (server *Server) memberRequest(r *http.Request) bool {
	if server.Runtime == nil || r.TLS == nil || r.TLS.NegotiatedProtocol != controlALPN || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	leaf := r.TLS.PeerCertificates[0]
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	for _, member := range server.Runtime.Authority.Snapshot().Config.Members {
		key, err := decodePublicKey(member.PublicKey)
		if err == nil && member.ControlID == leaf.Subject.CommonName && key.Equal(public) {
			return true
		}
	}
	return false
}
func (server *Server) admin(r *http.Request) bool {
	if localAdmin(r) {
		return true
	}
	if server.Runtime == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || !certificateChainsCurrent(r.TLS.VerifiedChains, server.now()) {
		return false
	}
	allowed := []string{}
	for _, certificate := range server.Runtime.Authority.Snapshot().AdminCertificates {
		allowed = append(allowed, certificate.CertificateDER)
	}
	return exactCertificate(r, allowed)
}
func (server *Server) authorized(r *http.Request) bool { return server.admin(r) }
func exactCertificate(r *http.Request, allowed []string) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	raw := r.TLS.PeerCertificates[0].Raw
	for _, encoded := range allowed {
		candidate, err := base64.RawURLEncoding.DecodeString(encoded)
		if err == nil && subtle.ConstantTimeCompare(candidate, raw) == 1 {
			return true
		}
	}
	return false
}

func (server *Server) snapshotValue(r *http.Request) (WebSnapshot, error) {
	if server.Runtime == nil || server.Runtime.Authority == nil {
		return WebSnapshot{}, errors.New("control projection unavailable")
	}
	projection := server.Runtime.Authority.Snapshot()
	releases := server.expectedReleaseSets(projection)
	snapshot := buildWebSnapshot(projection, server.admin(r), localAdmin(r), server.Runtime.Writable(), releases...)
	snapshot.WebsiteCertificates = WebsiteCertificateReadbacks(server.Runtime.Authority.root, server.Config.ControlID, projection, server.now())
	snapshot.PolicyInvites = projectWebPolicyInvites(projection, server.now())
	if server.Runtime.Reports != nil {
		latest, err := server.Runtime.Reports.Latest(r.Context())
		if err != nil {
			return WebSnapshot{}, err
		}
		projectWebLastReportTimes(&snapshot, latest, projection)
		reports := []DeviceReport{}
		for _, report := range latest {
			if verifyCurrentReport(report, projection, releases...) == nil {
				reports = append(reports, report)
			}
		}
		projectWebObservations(&snapshot, reports)
		snapshot.Events = snapshotEvents(projectReportHistory(reports))
	}
	if server.Releases != nil {
		if err := server.projectReleases(&snapshot); err != nil {
			snapshot.UIState.Warnings = append(snapshot.UIState.Warnings, WebWarning{Code: "release_catalog_unavailable", Message: "Signed release catalog or referenced artifacts could not be verified."})
		}
	}
	return snapshot, nil
}

func (server *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	value, err := server.snapshotValue(r)
	if err != nil {
		http.Error(w, "control projection unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (server *Server) live(w http.ResponseWriter, r *http.Request) {
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.Close(websocket.StatusNormalClosure, "")
	connection.SetReadLimit(1024)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	previous := []byte(nil)
	for {
		if !server.admin(r) {
			_ = connection.Close(websocket.StatusPolicyViolation, "administrator authorization removed")
			return
		}
		value, err := server.snapshotValue(r)
		if err != nil {
			_ = connection.Close(websocket.StatusInternalError, "control projection unavailable")
			return
		}
		body, err := json.Marshal(value)
		if err != nil {
			return
		}
		if !bytes.Equal(body, previous) {
			if err := wsjson.Write(r.Context(), connection, value); err != nil {
				return
			}
			previous = body
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
func boundedBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, controlHTTPBodyLimit))
}
func (server *Server) operation(w http.ResponseWriter, r *http.Request) {
	if !server.admin(r) {
		http.Error(w, "administrator certificate required", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); !localAdmin(r) && origin != "" && origin != "https://"+r.Host {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	body, err := boundedBody(w, r)
	if err != nil {
		http.Error(w, "operation exceeds entry-point bounds", http.StatusRequestEntityTooLarge)
		return
	}
	operation, err := DecodeOperation(body)
	if err != nil {
		http.Error(w, "invalid canonical operation", http.StatusBadRequest)
		return
	}
	result, extra, err := server.HandleOperation(r.Context(), operation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	snapshot := buildWebSnapshot(result.Projection, true, localAdmin(r), server.Runtime.Writable(), server.expectedReleaseSets(result.Projection)...)
	snapshot.WebsiteCertificates = WebsiteCertificateReadbacks(server.Runtime.Authority.root, server.Config.ControlID, result.Projection, server.now())
	snapshot.PolicyInvites = projectWebPolicyInvites(result.Projection, server.now())
	response := map[string]any{"material_id": result.MaterialID, "status": "accepted", "snapshot": snapshot}
	if extra != nil && extra.Invite != "" {
		response["invite"] = extra.Invite
	}
	writeJSON(w, http.StatusOK, response)
}

func (server *Server) internalFrontier(w http.ResponseWriter, r *http.Request) {
	body, err := CanonicalEncode(server.Runtime.Authority.Frontier())
	if err != nil {
		http.Error(w, "fact frontier unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
func (server *Server) internalMaterialsAfter(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if len(query) != 2 || len(query["key_id"]) != 1 || len(query["after"]) != 1 {
		http.Error(w, "invalid fact range", http.StatusBadRequest)
		return
	}
	keyID := query.Get("key_id")
	after, err := ParseU64(query.Get("after"))
	if err != nil || ValidateDigest(keyID) != nil {
		http.Error(w, "invalid fact range", http.StatusBadRequest)
		return
	}
	materials, err := server.Runtime.Authority.MaterialsAfter(keyID, after)
	if err != nil {
		http.Error(w, "fact range unavailable", http.StatusServiceUnavailable)
		return
	}
	body := []byte(`{"materials":[`)
	more := false
	for i, material := range materials {
		if len(body)+len(material)+32 > controlHTTPBodyLimit {
			if i == 0 {
				http.Error(w, "one fact exceeds this response boundary", http.StatusRequestEntityTooLarge)
				return
			}
			more = true
			break
		}
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, material...)
	}
	body = append(body, []byte(`],"more":`)...)
	if more {
		body = append(body, []byte("true}")...)
	} else {
		body = append(body, []byte("false}")...)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
func (server *Server) internalMaterial(w http.ResponseWriter, r *http.Request) {
	id := "sha256:" + r.PathValue("digest")
	if ValidateDigest(id) != nil {
		http.Error(w, "invalid fact ID", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		body, err := server.Runtime.Authority.Material(id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
		return
	}
	body, err := boundedBody(w, r)
	if err != nil {
		http.Error(w, "fact exceeds entry-point bounds", http.StatusRequestEntityTooLarge)
		return
	}
	_, actual, err := EncodeMaterialFromBytes(body)
	if err != nil || actual != id {
		http.Error(w, "fact does not match its ID", http.StatusBadRequest)
		return
	}
	if _, err := server.Runtime.Authority.PutMaterial(body); err != nil {
		http.Error(w, "fact rejected", http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		MaterialID string `json:"material_id"`
		Status     string `json:"status"`
	}{id, "accepted"})
}

func decodeRawStrict(body []byte, value any) error {
	return DecodeCanonical(body, value, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 64, MaxItems: 1 << 20})
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
		"/services": true, "/policies": true, "/releases": true, "/deployments": true, "/events": true, "/ssot": true, "/settings": true}
	devicePath := strings.TrimPrefix(request.URL.Path, "/devices/")
	validDevicePath := devicePath != request.URL.Path && devicePath != "" && !strings.Contains(devicePath, "/")
	if strings.HasPrefix(devicePath, "invites/") {
		transaction := strings.TrimPrefix(devicePath, "invites/")
		validDevicePath = transaction != "" && !strings.Contains(transaction, "/")
	}
	if !allowed[request.URL.Path] && !validDevicePath {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	serveEmbedded(writer, request, "index.html", "text/html; charset=utf-8")
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

func writeCanonical(w http.ResponseWriter, status int, value any) {
	body, err := CanonicalEncode(value)
	if err != nil {
		http.Error(w, "canonical response unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
