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

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"loom/internal/clientrelease"
	"loom/internal/publish"
)

var errPublisherProjectionUnavailable = errors.New("publisher observation projection is unavailable")

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	Runtime                  *Runtime
	Channel                  *PrivateChannel
	Config                   NodeConfig
	ReleaseRoot              string
	ReleaseKey               string
	PublisherObservationPath string
	AdminSocket              string
	Now                      func() time.Time
	Endpoints                *EndpointRuntime
	Reports                  *ObservationStore
	ReportSyncInterval       time.Duration
	PublisherSyncInterval    time.Duration
	mu                       sync.Mutex
	endpointsMu              sync.RWMutex
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
	server.endpointsMu.Lock()
	server.Endpoints = endpoints
	server.endpointsMu.Unlock()
	defer endpoints.Close()

	handler := server.Handler()
	servers := []*http.Server{
		{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
		{Handler: reportHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
		// A local operation may need two certified transitions (expire an old
		// enrollment, then open its replacement).  Cutting the response off at
		// the ordinary HTTP timeout left callers with EOF after both transitions
		// had committed.  The root-only socket has its own bounded operation
		// client and may wait long enough to return that authoritative result.
		{Handler: server.AdminHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute},
		{Handler: server.DeviceHandler(), ConnContext: endpointConnContext, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second},
	}
	errorsOut := make(chan error, 4)
	go func() { errorsOut <- servers[0].Serve(server.Channel.ControlListener()) }()
	go func() { errorsOut <- servers[1].Serve(server.Channel.ReportListener()) }()
	go func() { errorsOut <- servers[2].Serve(admin) }()
	go func() { errorsOut <- servers[3].Serve(endpoints) }()
	if server.Reports != nil {
		go server.syncReports(ctx)
	}
	server.startPublisherSync(ctx)
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

func (server *Server) endpointRuntime() *EndpointRuntime {
	server.endpointsMu.RLock()
	defer server.endpointsMu.RUnlock()
	return server.Endpoints
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
	mux.HandleFunc("GET /api/control/ui/snapshot", server.snapshot)
	mux.HandleFunc("GET /api/control/ui/live", server.live)
	mux.HandleFunc("GET /api/control/ui/enrollment-options", server.enrollmentOptions)
	mux.HandleFunc("GET /api/control/ui/invites/{transaction}", server.inviteReadback)
	mux.HandleFunc("GET /api/control/ui/invites/{transaction}/qr.png", server.inviteQR)
	mux.HandleFunc("GET /api/control/ui/invites/{transaction}/download", server.inviteDownload)
	mux.HandleFunc("GET /api/control/ui/releases/files/", server.download)
	mux.HandleFunc("GET /api/control/publisher-input", server.publisherInput)
	mux.HandleFunc("POST /api/control/operations", server.operation)
	mux.HandleFunc("PUT /internal/materials/{digest}", server.internalMaterial)
	mux.HandleFunc("GET /internal/materials", server.internalMaterialIDs)
	mux.HandleFunc("POST /internal/head/sign", server.internalSign)
	mux.HandleFunc("PUT /internal/certified", server.internalCertified)
	mux.HandleFunc("POST /internal/submit", server.internalSubmit)
	mux.HandleFunc("POST /internal/members/replace", server.internalReplaceMembers)
	mux.HandleFunc("GET /internal/quorum-writable", server.internalQuorumWritable)
	mux.HandleFunc("PUT /internal/reports", server.internalReports)
	mux.HandleFunc("POST /internal/report-ids", server.internalReportIDs)
	server.registerPublisherRoutes(mux)
	mux.HandleFunc("/", server.page)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "same-origin")
		writer.Header().Set("Cache-Control", "no-store")
		local := localAdmin(request)
		internal := strings.HasPrefix(request.URL.Path, "/internal/")
		exactHost := false
		if !local {
			exactHost = server.exactHost(request.Host) || internal && request.Host == server.Config.Node
		}
		if request.URL.RawPath != "" || path.Clean(request.URL.Path) != request.URL.Path || !local && (request.TLS == nil ||
			!request.TLS.HandshakeComplete || request.TLS.Version != tls.VersionTLS13 || !exactHost) {
			http.NotFound(writer, request)
			return
		}
		if internal {
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

func (server *Server) publisherInput(writer http.ResponseWriter, request *http.Request) {
	if !localAdmin(request) {
		http.NotFound(writer, request)
		return
	}
	_, _, certified := server.Runtime.Authority.Snapshot()
	input, err := certifiedPublisherInput(certified.Projection, certified.Head)
	if err != nil {
		http.Error(writer, "certified publisher input unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := canonical(input)
	if err != nil {
		http.Error(writer, "certified publisher input unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body)
}

func certifiedPublisherInput(projection Projection, head GovernanceHead) (publish.CertifiedPublisherInput, error) {
	if projection.NetworkIntent == nil {
		return publish.CertifiedPublisherInput{}, errors.New("certified network intent is unavailable")
	}
	input := publish.CertifiedPublisherInput{Schema: publish.CertifiedPublisherInputSchema,
		Head: HeadID(head), Index: head.Index, ProjectionDigest: head.ProjectionDigest,
		DistributionURLs: []string{}, Devices: []publish.CertifiedPublisherDevice{}}
	distributionURLs := map[string]bool{}
	for _, node := range projection.NetworkIntent.Nodes {
		for _, value := range node.DistributionURLs {
			distributionURLs[value] = true
		}
		components := append([]ComponentExpectation(nil), projection.NetworkIntent.Components...)
		for _, override := range node.Components {
			index := sort.Search(len(components), func(index int) bool { return components[index].Name >= override.Name })
			if index < len(components) && components[index].Name == override.Name {
				components[index] = override
			} else {
				components = append(components, ComponentExpectation{})
				copy(components[index+1:], components[index:])
				components[index] = override
			}
		}
		device := publish.CertifiedPublisherDevice{ID: node.ID, Platform: node.Platform,
			Roles: append([]string(nil), node.Roles...), Components: make([]publish.CertifiedPublisherComponent, 0, len(components))}
		for _, component := range components {
			device.Components = append(device.Components, publish.CertifiedPublisherComponent{
				Name: component.Name, Version: component.Version, Digest: component.Digest})
		}
		input.Devices = append(input.Devices, device)
	}
	for value := range distributionURLs {
		input.DistributionURLs = append(input.DistributionURLs, value)
	}
	sort.Strings(input.DistributionURLs)
	if err := input.Validate(); err != nil {
		return publish.CertifiedPublisherInput{}, err
	}
	return input, nil
}

func (server *Server) snapshot(writer http.ResponseWriter, request *http.Request) {
	if localAdmin(request) && server.Runtime != nil && server.Runtime.Raft != nil {
		_, leaderID := server.Runtime.Raft.LeaderWithID()
		writer.Header().Set("X-Loom-Raft-State", server.Runtime.Raft.State().String())
		writer.Header().Set("X-Loom-Raft-Leader", string(leaderID))
	}
	response, err := server.snapshotValue(request)
	if err != nil {
		http.Error(writer, "control projection unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (server *Server) snapshotValue(request *http.Request) (WebSnapshotV2, error) {
	_, _, certified := server.Runtime.Authority.Snapshot()
	projectionBody, err := canonical(certified.Projection.Web)
	if err != nil {
		return WebSnapshotV2{}, err
	}
	var projection WebProjection
	if err := json.Unmarshal(projectionBody, &projection); err != nil {
		return WebSnapshotV2{}, err
	}
	if initial, err := server.Runtime.Authority.initialWebProjection(); err == nil {
		projection.UIState.Warnings = append(projection.UIState.Warnings,
			restoreReservedDeviceCollisions(&projection, certified.Projection, initial)...)
	}
	hideRevokedDevices(&projection)
	verifiedReports := []DeviceReport{}
	historicalReports := []DeviceReport{}
	if server.Reports != nil {
		server.Reports.Project(&projection, certified.Projection, server.now())
		verifiedReports = server.Reports.Verified(certified.Projection)
		if authorities, historyErr := server.Runtime.Authority.HistoricalReportAuthorities(); historyErr == nil {
			historicalReports = server.Reports.VerifiedHistory(authorities, server.now())
		} else {
			projection.UIState.Warnings = append(projection.UIState.Warnings, "Authenticated event history is unavailable.")
		}
	}
	projectEnrollmentReadiness(&projection, certified.Projection, verifiedReports, server.now())
	if err := server.projectDeployments(&projection, verifiedReports); err != nil {
		projection.UIState.Warnings = append(projection.UIState.Warnings, "Authenticated deployment readback is unavailable.")
	}
	projection.Events = projectCurrentEvents(projection, verifiedReports, historicalReports, server.now())
	catalog, err := server.catalog()
	if err != nil {
		projection.UIState.Warnings = append(projection.UIState.Warnings, "Verified release catalog is unavailable.")
	} else {
		projection.Releases = make([]Release, 0, len(catalog.Artifacts))
		for _, artifact := range catalog.Artifacts {
			release := Release{Path: artifact.Path, Name: artifact.Name,
				Title: artifact.Title, Platform: artifact.Platform, Arch: artifact.Arch, Variant: artifact.Variant,
				Version: artifact.Version, SourceCommit: artifact.SourceCommit, SHA256: artifact.SHA256,
				Size: artifact.Size, Signing: artifact.Signing, URL: "/api/control/ui/releases/files/" + artifact.Path,
				Checksum: releaseFileProjection(artifact.Checksum), Signature: releaseFileProjection(artifact.Signature)}
			if artifact.SBOM != nil {
				release.SBOM = releaseFileProjection(*artifact.SBOM)
			}
			projection.Releases = append(projection.Releases, release)
		}
	}
	return buildWebSnapshot(projection, certified.Projection, certified.Head, server.admin(request), localAdmin(request),
		server.Runtime.QuorumWritable(request.Context())), nil
}

func releaseFileProjection(file clientrelease.File) *ReleaseFile {
	return &ReleaseFile{Name: file.Name, SHA256: file.SHA256, Size: file.Size,
		URL: "/api/control/ui/releases/files/" + file.Path}
}

func (server *Server) internalQuorumWritable(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.internalBody(writer, request); !ok {
		return
	}
	context, cancel := context.WithTimeout(request.Context(), 750*time.Millisecond)
	defer cancel()
	writeJSON(writer, http.StatusOK, quorumStatus{Writable: server.Runtime.verifyLocalLeader(context)})
}

func (server *Server) live(writer http.ResponseWriter, request *http.Request) {
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.Close(websocket.StatusNormalClosure, "")
	connection.SetReadLimit(1024)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	previous := ""
	for {
		response, err := server.snapshotValue(request)
		if err != nil {
			_ = connection.Close(websocket.StatusInternalError, "control projection unavailable")
			return
		}
		body, err := canonical(response)
		if err != nil {
			return
		}
		if string(body) != previous {
			if err := wsjson.Write(request.Context(), connection, response); err != nil {
				return
			}
			previous = string(body)
		}
		select {
		case <-request.Context().Done():
			return
		case <-ticker.C:
		}
	}
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
		"/services": true, "/releases": true, "/deployments": true, "/events": true, "/ssot": true, "/settings": true}
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
	Schema    int             `json:"schema"`
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
	if err := decoder.Decode(&envelope); err != nil || envelope.Schema != 2 || envelope.RequestID == "" || envelope.BaseHead == "" {
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
		var materialBody []byte
		materialBody, _, err = EncodeMaterial(material)
		if err == nil {
			result, err = server.Runtime.Submit(request.Context(), materialBody)
		}
	case "service.delete":
		var payload ServiceDelete
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid service deletion", http.StatusBadRequest)
			return
		}
		material := Material{Schema: MaterialSchema, Kind: envelope.Kind, RequestID: envelope.RequestID,
			BaseHead: envelope.BaseHead, ServiceDelete: &payload}
		materialBody, _, encodeErr := EncodeMaterial(material)
		if encodeErr == nil {
			result, encodeErr = server.Runtime.Submit(request.Context(), materialBody)
		}
		err = encodeErr
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
	case "device.revoke":
		var payload struct {
			DeviceID string `json:"device_id"`
		}
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid device revocation", http.StatusBadRequest)
			return
		}
		result, err = server.revokeDevice(request.Context(), envelope.RequestID, envelope.BaseHead, payload.DeviceID)
	case "enrollment.create":
		var payload productEnrollmentCreatePayload
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid enrollment", http.StatusBadRequest)
			return
		}
		var invite string
		result, invite, err = server.createEnrollment(request.Context(), envelope.RequestID, envelope.BaseHead, payload.internal())
		if err == nil {
			extra["invite"] = invite
			if decoded, decodeErr := DecodeInvite(invite); decodeErr == nil {
				extra["transaction_id"] = decoded.Capability.TransactionID
			}
		}
	case "existing-node.rejoin":
		if !localAdmin(request) {
			http.Error(writer, "existing-node rejoin requires the local admin socket", http.StatusForbidden)
			return
		}
		var payload existingNodeRejoinPayload
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid existing-node rejoin", http.StatusBadRequest)
			return
		}
		var invite string
		result, invite, err = server.createExistingNodeRejoin(request.Context(), envelope.RequestID, envelope.BaseHead, payload)
		if err == nil {
			extra["invite"] = invite
			if decoded, decodeErr := DecodeInvite(invite); decodeErr == nil {
				extra["transaction_id"] = decoded.Capability.TransactionID
			}
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
	case "network.import":
		if !localAdmin(request) {
			http.Error(writer, "network import requires the local admin socket", http.StatusForbidden)
			return
		}
		var payload NetworkImport
		if err := decodeRawStrict(envelope.Payload, &payload); err != nil {
			http.Error(writer, "invalid network import", http.StatusBadRequest)
			return
		}
		recoveryBody, encodeErr := canonical(server.Config.Recovery)
		if encodeErr != nil || subtle.ConstantTimeCompare([]byte(payload.RecoveryEvidenceHash),
			[]byte("sha256:"+SHA256(recoveryBody))) != 1 {
			http.Error(writer, "network import recovery evidence does not match this control node", http.StatusUnprocessableEntity)
			return
		}
		_, _, currentCertified := server.Runtime.Authority.Snapshot()
		if currentCertified.Projection.NetworkIntent != nil {
			existingBody, existingErr := canonical(currentCertified.Projection.NetworkIntent)
			incomingBody, incomingErr := canonical(payload.Intent)
			if existingErr == nil && incomingErr == nil && bytes.Equal(existingBody, incomingBody) {
				result = currentCertified
				break
			}
		}
		material := Material{Schema: MaterialSchema, Kind: envelope.Kind, RequestID: envelope.RequestID,
			BaseHead: envelope.BaseHead, NetworkImport: &payload}
		materialBody, _, encodeErr := EncodeMaterial(material)
		if encodeErr == nil {
			result, encodeErr = server.Runtime.Submit(request.Context(), materialBody)
		}
		err = encodeErr
	default:
		http.Error(writer, "unknown operation", http.StatusBadRequest)
		return
	}
	if err != nil {
		status := http.StatusServiceUnavailable
		if strings.Contains(err.Error(), "stale") || strings.Contains(err.Error(), "already bound") ||
			strings.Contains(err.Error(), "another operation") || strings.Contains(err.Error(), "another identity") {
			status = http.StatusConflict
		} else if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "unknown") ||
			strings.Contains(err.Error(), "unavailable") || strings.Contains(err.Error(), "required") {
			status = http.StatusUnprocessableEntity
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

func (server *Server) internalReplaceMembers(writer http.ResponseWriter, request *http.Request) {
	body, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	var replacement memberReplacementRequest
	if err := decodeRawStrict(body, &replacement); err != nil || replacement.RequestID == "" || replacement.BaseHead == "" {
		http.Error(writer, "invalid member replacement", http.StatusBadRequest)
		return
	}
	result, err := server.Runtime.ReplaceMembers(request.Context(), replacement.RequestID, replacement.BaseHead, replacement.Members)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (server *Server) internalReports(writer http.ResponseWriter, request *http.Request) {
	body, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	if server.Reports == nil {
		http.Error(writer, "observation store unavailable", http.StatusServiceUnavailable)
		return
	}
	var records []reportRecord
	if err := decodeRawStrict(body, &records); err != nil {
		http.Error(writer, "invalid device reports", http.StatusBadRequest)
		return
	}
	authorities, err := server.Runtime.Authority.HistoricalReportAuthorities()
	if err != nil {
		http.Error(writer, "certified report history unavailable", http.StatusServiceUnavailable)
		return
	}
	merged, err := server.Reports.mergeRecords(records, authorities)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]int{"merged": merged})
}

func (server *Server) internalReportIDs(writer http.ResponseWriter, request *http.Request) {
	body, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	if server.Reports == nil {
		http.Error(writer, "observation store unavailable", http.StatusServiceUnavailable)
		return
	}
	var page struct {
		After string `json:"after"`
		Limit int    `json:"limit"`
	}
	if decodeRawStrict(body, &page) != nil {
		http.Error(writer, "invalid report content ID page", http.StatusBadRequest)
		return
	}
	ids, next, err := server.Reports.IDPage(page.After, page.Limit)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"ids": ids, "next": next})
}

func (server *Server) syncReports(ctx context.Context) {
	interval := server.ReportSyncInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			server.syncReportsOnce(ctx)
		}
	}
}

func (server *Server) syncReportsOnce(ctx context.Context) {
	if server.Reports == nil || server.Runtime == nil || server.Runtime.Channel == nil {
		return
	}
	_, _, certified := server.Runtime.Authority.Snapshot()
	authorities, authorityErr := server.Runtime.Authority.HistoricalReportAuthorities()
	if authorityErr != nil {
		return
	}
	for _, member := range uniqueMembers(certified.Projection.Config) {
		if member.ID == server.Config.MemberID {
			continue
		}
		known, after, failed := []string{}, "", false
		for {
			requestBody, _ := canonical(map[string]any{"after": after, "limit": 4096})
			var page struct {
				IDs  []string `json:"ids"`
				Next string   `json:"next"`
			}
			peerContext, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := server.Runtime.peerJSON(peerContext, member, http.MethodPost, "/internal/report-ids", requestBody, &page)
			cancel()
			if err != nil || page.Next != "" && (len(page.IDs) == 0 || page.Next <= after) {
				failed = true
				break
			}
			known = append(known, page.IDs...)
			if page.Next == "" {
				break
			}
			after = page.Next
		}
		if failed {
			continue
		}
		records, recordErr := server.Reports.missingRecords(known, authorities)
		if recordErr != nil {
			continue
		}
		for start := 0; start < len(records); start += 128 {
			end := min(start+128, len(records))
			body, encodeErr := canonical(records[start:end])
			if encodeErr != nil {
				break
			}
			batchContext, batchCancel := context.WithTimeout(ctx, 5*time.Second)
			putErr := server.Runtime.peerJSON(batchContext, member, http.MethodPut, "/internal/reports", body, nil)
			batchCancel()
			if putErr != nil {
				break
			}
		}
	}
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
