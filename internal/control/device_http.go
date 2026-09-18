package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"
)

type enrollmentCreatePayload struct {
	TransactionID string           `json:"transaction_id"`
	ExpiresAt     string           `json:"expires_at"`
	DeviceID      string           `json:"device_id"`
	Name          string           `json:"name"`
	Platform      string           `json:"platform"`
	Roles         []string         `json:"roles"`
	Routes        []RouteCandidate `json:"routes"`
}

type tunnelIdentityKey struct{}

type tunnelIdentity struct {
	Mode          string
	TransactionID string
	DeviceID      string
	EndpointID    string
	Generation    uint64
}

func (server *Server) now() time.Time {
	if server.Now != nil {
		return server.Now().UTC()
	}
	return time.Now().UTC()
}

func (authority *Authority) EnrollmentOpen(transactionID string) (EnrollmentOpen, error) {
	consensus, _, _ := authority.Snapshot()
	for _, entry := range consensus.Entries {
		body, err := authority.Material(entry.MaterialID)
		if err != nil {
			return EnrollmentOpen{}, err
		}
		material, err := DecodeMaterial(body)
		if err != nil {
			return EnrollmentOpen{}, err
		}
		if material.EnrollmentOpen != nil && material.EnrollmentOpen.TransactionID == transactionID {
			return *material.EnrollmentOpen, nil
		}
	}
	return EnrollmentOpen{}, errors.New("enrollment capability not found")
}

func servingEndpointReferences(projection Projection) []EndpointReference {
	result := []EndpointReference{}
	for _, generation := range projection.EndpointGenerations {
		if generation.State == "serving" {
			result = append(result, generation.Reference())
		}
	}
	sort.Slice(result, func(i, j int) bool { return endpointReferenceLess(result[i], result[j]) })
	return result
}

func (server *Server) createEnrollment(ctx context.Context, requestID, baseHead string, payload enrollmentCreatePayload) (CertifiedState, string, error) {
	_, projection, certified := server.Runtime.Authority.Snapshot()
	if _, transaction := findEnrollment(&projection, payload.TransactionID); transaction != nil {
		open, err := server.Runtime.Authority.EnrollmentOpen(payload.TransactionID)
		if err != nil {
			return CertifiedState{}, "", err
		}
		intent := EnrollmentIntent{DeviceID: payload.DeviceID, Name: payload.Name, Platform: payload.Platform,
			Roles: payload.Roles, Routes: payload.Routes}
		if !equalEnrollmentIntent(open.Intent, intent) || open.Capability.ExpiresAt != payload.ExpiresAt {
			return CertifiedState{}, "", errors.New("enrollment transaction ID is already bound to different intent")
		}
		invite, err := EncodeInvite(BootstrapInvite{Schema: enrollmentSchema, Capability: open.Capability})
		return certified, invite, err
	}
	if baseHead != HeadID(certified.Head) {
		return CertifiedState{}, "", errors.New("base head is stale")
	}
	expires, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil || payload.ExpiresAt != expires.UTC().Format(time.RFC3339) || !expires.After(server.now()) {
		return CertifiedState{}, "", errors.New("enrollment expiry is invalid")
	}
	intent := EnrollmentIntent{DeviceID: payload.DeviceID, Name: payload.Name, Platform: payload.Platform,
		Roles: append([]string(nil), payload.Roles...), Routes: append([]RouteCandidate(nil), payload.Routes...)}
	if err := intent.Validate(); err != nil {
		return CertifiedState{}, "", err
	}
	endpoints := servingEndpointReferences(projection)
	if len(endpoints) == 0 {
		return CertifiedState{}, "", errors.New("no serving bootstrap endpoint generation")
	}
	constraint, _ := intentDigest(intent)
	capability := BootstrapCapability{Schema: enrollmentSchema, TransactionID: payload.TransactionID,
		IssuedHead: HeadID(certified.Head), ConfigMaterial: projection.ConfigMaterial, ControlConfig: projection.Config,
		ExpiresAt: expires.UTC().Format(time.RFC3339), Actions: []string{"claim", "resume"}, Endpoints: endpoints,
		ConstraintDigest: constraint, IssuerMemberID: server.Config.MemberID}
	capability, err = SignBootstrapCapability(capability, server.Config)
	if err != nil {
		return CertifiedState{}, "", err
	}
	open := EnrollmentOpen{TransactionID: payload.TransactionID, Intent: intent, Capability: capability}
	material := Material{Schema: MaterialSchema, Kind: "enrollment.open", RequestID: requestID, BaseHead: baseHead, EnrollmentOpen: &open}
	body, _, err := EncodeMaterial(material)
	if err != nil {
		return CertifiedState{}, "", err
	}
	result, err := server.Runtime.Submit(ctx, body)
	if err != nil {
		return CertifiedState{}, "", err
	}
	invite, err := EncodeInvite(BootstrapInvite{Schema: enrollmentSchema, Capability: capability})
	return result, invite, err
}

func equalEnrollmentIntent(left, right EnrollmentIntent) bool {
	a, _ := canonical(left)
	b, _ := canonical(right)
	return bytes.Equal(a, b)
}

func cloneProjection(projection Projection) (Projection, error) {
	body, err := canonical(projection)
	if err != nil {
		return Projection{}, err
	}
	var clone Projection
	if err := json.Unmarshal(body, &clone); err != nil {
		return Projection{}, err
	}
	return clone, nil
}

func (server *Server) approveEnrollment(ctx context.Context, requestID, baseHead, transactionID string) (CertifiedState, error) {
	if !validName(transactionID) {
		return CertifiedState{}, errors.New("enrollment transaction ID is invalid")
	}
	_, projection, certified := server.Runtime.Authority.Snapshot()
	_, transaction := findEnrollment(&projection, transactionID)
	if transaction == nil {
		return CertifiedState{}, errors.New("enrollment transaction does not exist")
	}
	if transaction.State == "completed" {
		return certified, nil
	}
	if transaction.State == "bound" {
		if baseHead != HeadID(certified.Head) {
			return CertifiedState{}, errors.New("base head is stale")
		}
		approve := EnrollmentApprove{TransactionID: transactionID}
		material := Material{Schema: MaterialSchema, Kind: "enrollment.approve", RequestID: requestID + ":approve",
			BaseHead: baseHead, EnrollmentApprove: &approve}
		body, _, err := EncodeMaterial(material)
		if err != nil {
			return CertifiedState{}, err
		}
		if _, err := server.Runtime.Submit(ctx, body); err != nil {
			return CertifiedState{}, err
		}
		_, projection, certified = server.Runtime.Authority.Snapshot()
		_, transaction = findEnrollment(&projection, transactionID)
	}
	if transaction == nil || transaction.State != "approved" {
		return CertifiedState{}, errors.New("enrollment transaction is not bound or approved")
	}
	authorization := DeviceAuthorization{Schema: enrollmentSchema, DeviceID: transaction.Intent.DeviceID,
		Name: transaction.Intent.Name, Platform: transaction.Intent.Platform, Roles: append([]string(nil), transaction.Intent.Roles...),
		Routes: append([]RouteCandidate(nil), transaction.Intent.Routes...), DevicePublicKey: transaction.DevicePublicKey,
		Floor: certified.Head.Index + 1}
	projected, err := cloneProjection(projection)
	if err != nil {
		return CertifiedState{}, err
	}
	index := sort.Search(len(projected.DeviceAuthorizations), func(index int) bool {
		return projected.DeviceAuthorizations[index].DeviceID >= authorization.DeviceID
	})
	projected.DeviceAuthorizations = append(projected.DeviceAuthorizations, DeviceAuthorization{})
	copy(projected.DeviceAuthorizations[index+1:], projected.DeviceAuthorizations[index:])
	projected.DeviceAuthorizations[index] = authorization
	view, found := projectDeviceView(projected, authorization.DeviceID)
	if !found {
		return CertifiedState{}, errors.New("device view projection failed")
	}
	digest, _ := DeviceViewDigest(view)
	complete := EnrollmentComplete{TransactionID: transactionID, Authorization: authorization, ResultDigest: digest}
	material := Material{Schema: MaterialSchema, Kind: "enrollment.complete", RequestID: requestID + ":complete",
		BaseHead: HeadID(certified.Head), EnrollmentComplete: &complete}
	body, _, err := EncodeMaterial(material)
	if err != nil {
		return CertifiedState{}, err
	}
	return server.Runtime.Submit(ctx, body)
}

func (server *Server) putEndpoint(ctx context.Context, requestID, baseHead string, generation EndpointGeneration) (CertifiedState, error) {
	if err := generation.Validate(); err != nil {
		return CertifiedState{}, err
	}
	_, projection, certified := server.Runtime.Authority.Snapshot()
	if baseHead != HeadID(certified.Head) {
		return CertifiedState{}, errors.New("base head is stale")
	}
	var previous *EndpointGeneration
	for index := range projection.EndpointGenerations {
		current := &projection.EndpointGenerations[index]
		if current.EndpointID == generation.EndpointID && current.Generation == generation.Generation {
			previous = current
			break
		}
	}
	if previous != nil && previous.State == "prepared" && generation.State == "serving" {
		if server.Endpoints == nil || generation.Node != server.Config.Node || !server.Endpoints.Ready(generation) {
			return CertifiedState{}, errors.New("endpoint generation is not locally ready")
		}
	}
	if previous != nil && previous.State == "serving" && generation.State == "draining" {
		ready := false
		for _, candidate := range projection.EndpointGenerations {
			if candidate.EndpointID == generation.EndpointID && candidate.Generation != generation.Generation &&
				candidate.State == "serving" && candidate.Preference < generation.Preference && server.Endpoints != nil && server.Endpoints.Successes(candidate) > 0 {
				ready = true
			}
		}
		if !ready {
			return CertifiedState{}, errors.New("endpoint generation has no successful preferred replacement")
		}
		for _, transaction := range projection.Enrollments {
			if transaction.State == "completed" || transaction.State == "rejected" || transaction.State == "expired" || transaction.State == "cancelled" ||
				transaction.State == "open" && !server.now().Before(mustTime(transaction.ExpiresAt)) {
				continue
			}
			open, err := server.Runtime.Authority.EnrollmentOpen(transaction.ID)
			if err != nil {
				return CertifiedState{}, err
			}
			for _, endpoint := range open.Capability.Endpoints {
				if endpoint.EndpointID == generation.EndpointID && endpoint.Generation == generation.Generation {
					return CertifiedState{}, errors.New("endpoint generation still protects an active enrollment")
				}
			}
		}
	}
	if previous != nil && previous.State == "draining" && generation.State == "retired" &&
		(server.Endpoints == nil || server.Endpoints.Active(generation) != 0) {
		return CertifiedState{}, errors.New("endpoint generation still has protected sessions")
	}
	material := Material{Schema: MaterialSchema, Kind: "endpoint.put", RequestID: requestID, BaseHead: baseHead, EndpointGeneration: &generation}
	body, _, err := EncodeMaterial(material)
	if err != nil {
		return CertifiedState{}, err
	}
	return server.Runtime.Submit(ctx, body)
}

func (server *Server) enrollmentResponse(transactionID string) (EnrollmentResponse, error) {
	_, projection, certified := server.Runtime.Authority.Snapshot()
	_, transaction := findEnrollment(&projection, transactionID)
	if transaction == nil {
		return EnrollmentResponse{}, errors.New("enrollment transaction does not exist")
	}
	response := EnrollmentResponse{Schema: enrollmentSchema, Transaction: *transaction}
	if transaction.State == "completed" {
		envelope, err := DeviceViewFor(certified.Projection, certified.Head, transaction.Intent.DeviceID)
		if err != nil {
			return EnrollmentResponse{}, err
		}
		response.DeviceView = &envelope
	}
	return response, nil
}

func (server *Server) DeviceHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/enrollment/claim", server.claim)
	mux.HandleFunc("POST /v2/enrollment/resume", server.resume)
	mux.HandleFunc("POST /v2/device/config", server.deviceConfig)
	mux.HandleFunc("POST /v2/device/report", server.deviceReport)
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) { http.NotFound(writer, request) })
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(writer, request)
	})
}

func readDeviceJSON(writer http.ResponseWriter, request *http.Request, value any) bool {
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	if err != nil || decodeRawStrict(body, value) != nil {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func tunnelAuth(request *http.Request) (tunnelIdentity, bool) {
	identity, ok := request.Context().Value(tunnelIdentityKey{}).(tunnelIdentity)
	return identity, ok
}

func (server *Server) claim(writer http.ResponseWriter, request *http.Request) {
	identity, ok := tunnelAuth(request)
	if !ok || identity.Mode != "bootstrap" {
		http.Error(writer, "bootstrap tunnel required", http.StatusForbidden)
		return
	}
	var claim EnrollmentClaimRequest
	if !readDeviceJSON(writer, request, &claim) || claim.Validate() != nil || identity.TransactionID != claim.Capability.TransactionID {
		http.Error(writer, "invalid enrollment claim", http.StatusBadRequest)
		return
	}
	_, projection, certified := server.Runtime.Authority.Snapshot()
	if projection.ConfigMaterial != claim.Capability.ConfigMaterial || !sameControlConfig(projection.Config, claim.Capability.ControlConfig) {
		http.Error(writer, "enrollment capability control boundary changed", http.StatusConflict)
		return
	}
	_, transaction := findEnrollment(&projection, claim.Capability.TransactionID)
	digest, _ := capabilityDigest(claim.Capability)
	if transaction == nil || transaction.CapabilityDigest != digest {
		http.Error(writer, "enrollment capability rejected", http.StatusForbidden)
		return
	}
	if transaction.State == "open" {
		if !server.now().Before(mustTime(claim.Capability.ExpiresAt)) {
			http.Error(writer, "enrollment capability expired", http.StatusGone)
			return
		}
		bind := EnrollmentBind{TransactionID: transaction.ID, ClaimRequestID: claim.RequestID,
			DevicePublicKey: claim.DevicePublicKey, ClaimedAt: server.now().Format(time.RFC3339)}
		material := Material{Schema: MaterialSchema, Kind: "enrollment.bind",
			RequestID: "enrollment-bind:" + transaction.ID + ":" + claim.DevicePublicKey,
			BaseHead:  HeadID(certified.Head), EnrollmentBind: &bind}
		body, _, err := EncodeMaterial(material)
		if err == nil {
			_, err = server.Runtime.Submit(request.Context(), body)
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else if transaction.DevicePublicKey != claim.DevicePublicKey || transaction.ClaimRequestID != claim.RequestID {
		http.Error(writer, "enrollment transaction is bound to another identity", http.StatusConflict)
		return
	}
	response, err := server.enrollmentResponse(transaction.ID)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusServiceUnavailable)
		return
	}
	status := http.StatusAccepted
	if response.Transaction.State == "completed" {
		status = http.StatusOK
	}
	writeJSON(writer, status, response)
}

func (server *Server) resume(writer http.ResponseWriter, request *http.Request) {
	identity, ok := tunnelAuth(request)
	if !ok || identity.Mode != "bootstrap" && identity.Mode != "device" {
		http.Error(writer, "authenticated tunnel required", http.StatusForbidden)
		return
	}
	var resume EnrollmentResumeRequest
	if !readDeviceJSON(writer, request, &resume) || resume.Validate() != nil ||
		identity.Mode == "bootstrap" && identity.TransactionID != resume.TransactionID {
		http.Error(writer, "invalid enrollment resume", http.StatusBadRequest)
		return
	}
	response, err := server.enrollmentResponse(resume.TransactionID)
	if err != nil || response.Transaction.DevicePublicKey != resume.DevicePublicKey ||
		identity.Mode == "device" && identity.DeviceID != response.Transaction.Intent.DeviceID {
		http.Error(writer, "enrollment resume rejected", http.StatusForbidden)
		return
	}
	status := http.StatusAccepted
	if response.Transaction.State == "completed" {
		status = http.StatusOK
	}
	writeJSON(writer, status, response)
}

func (server *Server) deviceConfig(writer http.ResponseWriter, request *http.Request) {
	identity, ok := tunnelAuth(request)
	if !ok || identity.Mode != "device" {
		http.Error(writer, "device tunnel required", http.StatusForbidden)
		return
	}
	_, _, certified := server.Runtime.Authority.Snapshot()
	envelope, err := DeviceViewFor(certified.Projection, certified.Head, identity.DeviceID)
	if err != nil {
		http.Error(writer, "device configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, envelope)
}

func (server *Server) deviceReport(writer http.ResponseWriter, request *http.Request) {
	identity, ok := tunnelAuth(request)
	if !ok || identity.Mode != "device" || server.Reports == nil {
		http.Error(writer, "device report channel unavailable", http.StatusForbidden)
		return
	}
	var report DeviceReport
	if !readDeviceJSON(writer, request, &report) || report.DeviceID != identity.DeviceID {
		http.Error(writer, "invalid device report", http.StatusBadRequest)
		return
	}
	_, projection, _ := server.Runtime.Authority.Snapshot()
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= report.DeviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != report.DeviceID ||
		report.Verify(projection.DeviceAuthorizations[index].DevicePublicKey) != nil {
		http.Error(writer, "device report signature rejected", http.StatusForbidden)
		return
	}
	view, _ := projectDeviceView(projection, report.DeviceID)
	digest, _ := DeviceViewDigest(view)
	if report.ViewDigest != digest {
		http.Error(writer, "device report view is stale", http.StatusConflict)
		return
	}
	if err := server.Reports.Put(report, projection.DeviceAuthorizations[index].DevicePublicKey); err != nil {
		http.Error(writer, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"device_id": report.DeviceID, "reported_at": report.ReportedAt})
}

func mustTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}
