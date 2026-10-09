package control

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// These rows describe existing local handoffs, never a renewal lifecycle.
type WebsiteRequestSummary struct {
	EndpointID string `json:"endpoint_id"`
	Generation U64    `json:"generation"`
	Available  bool   `json:"available"`
}

func (server *Server) websiteSnapshot(snapshot *WebSnapshot, r *http.Request, projection Projection) {
	snapshot.WebsiteGenerations = []EndpointGeneration{}
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.WebsiteTrustID != "" {
			snapshot.WebsiteGenerations = append(snapshot.WebsiteGenerations, endpoint)
		}
	}
	if !server.admin(r) {
		return
	}
	var err error
	snapshot.WebsiteRequests, err = localWebsiteRequests(server.Runtime.Authority.root, server.Config, projection)
	if err != nil {
		snapshot.UIState.Warnings = append(snapshot.UIState.Warnings, WebWarning{Code: "website_request_unavailable", Message: "Some original website signing requests cannot be verified on this control. Inspect protected local material; no key was regenerated."})
	}
	if endpoint, ok := server.websiteConnection(r, projection); ok {
		snapshot.WebsiteConnection = &endpoint
	}
}

func (server *Server) websiteConnection(r *http.Request, projection Projection) (EndpointGeneration, bool) {
	identity, ok := r.Context().Value(tunnelIdentityKey{}).(tunnelIdentity)
	if !ok || identity.Mode != "web" {
		return EndpointGeneration{}, false
	}
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.ID == identity.EndpointID && endpoint.Generation == identity.Generation &&
			endpoint.OwnerControlID == server.Config.ControlID && endpoint.WebsiteTrustID != "" && endpoint.State == "serving" {
			if !endpointOwnerActive(projection, endpoint.OwnerControlID) {
				return EndpointGeneration{}, false
			}
			inputs, err := loadEndpointInputs(server.Runtime.Authority.root, endpoint)
			if err != nil {
				return EndpointGeneration{}, false
			}
			if _, err := loadAuthorizedEndpointCertificate(projection, endpoint, inputs, server.now()); err != nil {
				return EndpointGeneration{}, false
			}
			return endpoint, true
		}
	}
	return EndpointGeneration{}, false
}

func (server *Server) websiteAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !server.admin(r) {
		http.Error(w, "administrator certificate required", http.StatusForbidden)
		return false
	}
	if r.Method != http.MethodGet {
		if origin := r.Header.Get("Origin"); !localAdmin(r) && origin != "" && origin != "https://"+r.Host {
			http.Error(w, "same-origin request required", http.StatusForbidden)
			return false
		}
		if !server.Runtime.Writable() {
			http.Error(w, "local control is not writable", http.StatusConflict)
			return false
		}
	}
	return true
}

func websiteCoordinates(r *http.Request) (string, U64, error) {
	id, raw := r.PathValue("id"), r.PathValue("generation")
	generation, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != raw || ValidateID(id) != nil {
		return "", 0, errors.New("invalid website entry coordinates")
	}
	return id, U64(generation), nil
}

func (server *Server) websiteRequest(w http.ResponseWriter, r *http.Request) {
	if !server.websiteAdmin(w, r) {
		return
	}
	id, generation, err := websiteCoordinates(r)
	var request WebsiteRequest
	if err == nil {
		if r.Method == http.MethodPost {
			// No client-supplied key, member proof or server filesystem path.
			body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
			if readErr != nil || len(body) != 0 {
				http.Error(w, "request body must be empty", http.StatusBadRequest)
				return
			}
			request, err = PrepareWebsiteRequest(server.Runtime.Authority.root, id, generation)
		} else {
			request, err = localWebsiteRequest(server.Runtime.Authority.root, server.Config, server.Runtime.Authority.Snapshot(), id, generation)
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	body, err := CanonicalEncode(request)
	if err != nil {
		http.Error(w, "request encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="website-request.json"`)
	w.Write(body)
}

type websiteInstallInput struct {
	EndpointID     string `json:"endpoint_id"`
	Generation     U64    `json:"generation"`
	WebsiteTrustID string `json:"website_trust_id"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Listen         string `json:"listen"`
	CertificatePEM string `json:"certificate_pem"`
}

// Accept a leaf or the leaf followed by exactly the independently selected root.
func websiteReturnedLeaf(encoded string, trust PublicTrust) ([]byte, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || !bytes.HasPrefix(bytes.TrimSpace([]byte(encoded)), []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, errors.New("select a public leaf certificate or its exact authorized chain")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		root, tail := pem.Decode(rest)
		der, err := base64.RawURLEncoding.DecodeString(trust.CertificateDER)
		if root == nil || root.Type != "CERTIFICATE" || len(root.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 || err != nil || !bytes.Equal(root.Bytes, der) || !bytes.HasPrefix(bytes.TrimSpace(rest), []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("returned chain must contain only the leaf and the selected authorized root")
		}
	}
	return block.Bytes, nil
}

func (server *Server) websiteInstall(w http.ResponseWriter, r *http.Request) {
	if !server.websiteAdmin(w, r) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	var input websiteInstallInput
	if err != nil || DecodeCanonical(body, &input, ContractDecodeLimits{MaxBytes: 128 << 10, MaxDepth: 8, MaxItems: 64}) != nil {
		http.Error(w, "invalid canonical public certificate input", http.StatusBadRequest)
		return
	}
	endpoint, err := installWebsiteCertificate(server.Runtime.Authority.root, server.Config, server.Runtime.Authority.Snapshot(), input, server.now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, http.StatusOK, endpoint)
}

func (server *Server) websiteCertificateDownload(w http.ResponseWriter, r *http.Request) {
	if !server.websiteAdmin(w, r) {
		return
	}
	id, generation, err := websiteCoordinates(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.ID != id || endpoint.Generation != generation {
			continue
		}
		if endpoint.OwnerControlID != server.Config.ControlID || endpoint.WebsiteTrustID == "" {
			http.Error(w, "inspect the owning website control", http.StatusConflict)
			return
		}
		inputs, err := loadEndpointInputs(server.Runtime.Authority.root, endpoint)
		if err != nil {
			http.Error(w, "local public certificate unavailable", http.StatusConflict)
			return
		}
		certificate, err := loadAuthorizedEndpointCertificate(projection, endpoint, inputs, server.now())
		if err != nil {
			http.Error(w, "local certificate verification failed", http.StatusConflict)
			return
		}
		body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Leaf.Raw})
		switch r.PathValue("kind") {
		case "chain":
			trust, err := endpointWebsiteTrust(projection, endpoint)
			if err != nil {
				http.Error(w, "website root unavailable", http.StatusConflict)
				return
			}
			der, _ := base64.RawURLEncoding.DecodeString(trust.CertificateDER)
			body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		case "leaf":
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="website-`+r.PathValue("kind")+`.pem"`)
		w.Write(body)
		return
	}
	http.NotFound(w, r)
}

func (server *Server) websiteRetirePrevious(w http.ResponseWriter, r *http.Request) {
	if !server.websiteAdmin(w, r) {
		return
	}
	body, err := boundedBody(w, r)
	operation, decodeErr := DecodeOperation(body)
	if err != nil || decodeErr != nil || operation.Operation != "endpoint.put" {
		http.Error(w, "expected an endpoint operation", http.StatusBadRequest)
		return
	}
	previous := operation.Payload.(EndpointGeneration)
	current, ok := server.websiteConnection(r, server.Runtime.Authority.Snapshot())
	if !ok || current.ID != previous.ID || current.Generation <= previous.Generation ||
		(previous.State != "draining" && previous.State != "retired") {
		http.Error(w, "verify the newer serving generation through its authenticated website before retiring the previous generation", http.StatusConflict)
		return
	}
	result, _, err := server.HandleOperation(r.Context(), operation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "material_id": result.MaterialID})
}
