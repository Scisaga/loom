package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"time"
)

type tunnelIdentityKey struct{}
type tunnelIdentity struct {
	Mode          string
	TransactionID string
	DeviceID      string
	EndpointID    string
	Generation    U64
}

type OperationExtra struct {
	Invite string `json:"invite,omitempty"`
}

func (server *Server) now() time.Time {
	if server.Now != nil {
		return server.Now().UTC()
	}
	return time.Now().UTC()
}

// HandleOperation accepts the public operation. Identity binding and the first
// RuntimeKey can only be produced by the authenticated enrollment handler.
func (server *Server) HandleOperation(ctx context.Context, operation Operation) (Submission, *OperationExtra, error) {
	if operation.Operation == "invite.bind" || operation.Operation == "device.join" || operation.Operation == "invite.expire" {
		return Submission{}, nil, errors.New("operation belongs to the authenticated enrollment entry")
	}
	body, err := EncodeOperation(operation)
	if err != nil {
		return Submission{}, nil, err
	}
	_, _, priorErr := server.Runtime.Authority.MaterialForRequest(operation.RequestID)
	if priorErr != nil && !errors.Is(priorErr, os.ErrNotExist) {
		return Submission{}, nil, priorErr
	}
	if operation.Operation == "admin_certificate.put" && errors.Is(priorErr, os.ErrNotExist) {
		if err := server.verifyAdminGrant(operation.Payload.(AdminCertificate)); err != nil {
			return Submission{}, nil, err
		}
	}
	if operation.Operation == "expected_component.put" && errors.Is(priorErr, os.ErrNotExist) {
		value := operation.Payload.(ExpectedComponent)
		if server.Releases == nil {
			return Submission{}, nil, errExpectedRelease
		}
		set, err := server.Releases.ReadCatalog(value.CatalogDigest)
		if err != nil {
			return Submission{}, nil, errExpectedRelease
		}
		if _, err := resolveExpectedComponent(value, []ReleaseSet{set}); err != nil {
			return Submission{}, nil, err
		}
	}
	if operation.Operation == "endpoint.put" && errors.Is(priorErr, os.ErrNotExist) {
		value := operation.Payload.(EndpointGeneration)
		if value.OwnerControlID != server.Runtime.Config.ControlID {
			return Submission{}, nil, errors.New("endpoint can only be written by its local owner")
		}
		endpoint := server.endpointRuntime()
		if value.State == "serving" && (endpoint == nil || !endpoint.Ready(value)) {
			return Submission{}, nil, errors.New("endpoint serving requires verified advertised TLS readiness")
		}
		if value.State == "draining" && value.DrainUntil <= server.now().UnixMilli() {
			return Submission{}, nil, errors.New("draining requires an explicit future termination time")
		}
		if value.State == "draining" || value.State == "retired" {
			for _, invite := range server.Runtime.Authority.Snapshot().Invites {
				if invite.Endpoint.ID != value.ID || invite.Endpoint.Generation != value.Generation {
					continue
				}
				state, err := server.Runtime.Authority.EnrollmentState(invite.ID)
				if err != nil || state == "bound" || state == "open" {
					return Submission{}, nil, errors.New("endpoint still protects an unterminated enrollment")
				}
			}
		}
		if value.State == "retired" && (endpoint == nil || endpoint.Active(value) != 0) {
			return Submission{}, nil, errors.New("endpoint retirement requires verified zero active sessions")
		}
	}
	if operation.Operation == "invite.issue" {
		invite, ok := operation.Payload.(Invite)
		if !ok {
			return Submission{}, nil, errors.New("invite payload is invalid")
		}
		if errors.Is(priorErr, os.ErrNotExist) {
			if invite.SSHTarget != "" {
				inspection, err := server.checkNewSSHTarget(ctx, invite.SSHTarget)
				if err != nil {
					return Submission{}, nil, errors.New(sshErrorCode(err))
				}
				if inspection.Installation.Identity != nil {
					return Submission{}, nil, errors.New("existing_device_identity")
				}
				if !inspection.Installation.CanInstall {
					return Submission{}, nil, errors.New("existing_installation_unverified")
				}
			}
			endpoint := server.endpointRuntime()
			if endpoint == nil || !endpoint.Ready(invite.Endpoint) {
				return Submission{}, nil, errors.New("invite endpoint has not been verified ready locally")
			}
			expires, err := endpoint.ExpiresAt(invite.Endpoint)
			if err != nil || !server.now().Before(time.UnixMilli(invite.ExpiresAt)) || time.UnixMilli(invite.ExpiresAt).After(expires) {
				return Submission{}, nil, errors.New("invite expiry is outside the ready endpoint certificate validity")
			}
		}
	}
	result, err := server.Runtime.Submit(ctx, body)
	if err != nil {
		return Submission{}, nil, err
	}
	if operation.Operation != "invite.issue" {
		return result, nil, nil
	}
	invite, err := server.bootstrapInvite(operation.TargetID)
	if err != nil {
		return Submission{}, nil, err
	}
	encoded, err := EncodeInvite(invite)
	if err != nil {
		return Submission{}, nil, err
	}
	return result, &OperationExtra{Invite: encoded}, nil
}

func (a *Authority) materialValueLocked(id string) (Material, bool) {
	for _, material := range a.materials {
		actual, err := MaterialID(material)
		if err == nil && actual == id {
			return material, true
		}
	}
	return Material{}, false
}
func cloneMaterialValue(material Material) (Material, error) {
	body, _, err := EncodeMaterial(material)
	if err != nil {
		return Material{}, err
	}
	return DecodeMaterial(body)
}
func (a *Authority) MaterialForRequest(requestID string) (string, Material, error) {
	config, err := LoadNodeConfig(a.root)
	if err != nil {
		return "", Material{}, err
	}
	member, err := config.Member()
	if err != nil {
		return "", Material{}, err
	}
	keyID, err := KeyID(member.PublicKey)
	if err != nil {
		return "", Material{}, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	var found Material
	id := ""
	for _, material := range a.materials {
		if material.IssuerKeyID != keyID || material.RequestID != requestID {
			continue
		}
		if id != "" {
			return "", Material{}, errors.New("request has conflicting signed facts")
		}
		id, err = MaterialID(material)
		if err != nil {
			return "", Material{}, err
		}
		found = material
	}
	if id == "" {
		return "", Material{}, os.ErrNotExist
	}
	copy, err := cloneMaterialValue(found)
	return id, copy, err
}
func (a *Authority) inviteLocked(transactionID string) (Material, error) {
	state, ok := a.projection.CurrentTarget("invite", transactionID)
	if !ok {
		return Material{}, os.ErrNotExist
	}
	if state.Conflicted {
		return Material{}, errors.New("invite is conflicted")
	}
	var found Material
	count := 0
	for _, material := range a.materials {
		if material.Operation == "invite.issue" && material.TargetID == transactionID {
			found = material
			count++
		}
	}
	if count != 1 {
		return Material{}, errors.New("invite origin is not unique")
	}
	return found, nil
}
func (a *Authority) Invite(transactionID string) (Material, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	material, err := a.inviteLocked(transactionID)
	if err != nil {
		return Material{}, err
	}
	return cloneMaterialValue(material)
}
func (a *Authority) bindingLocked(transactionID string) (Material, bool, error) {
	var found Material
	count := 0
	for _, value := range a.projection.Bindings {
		if value.TransactionID != transactionID {
			continue
		}
		for _, material := range a.materials {
			binding, ok := material.Payload.(EnrollmentBind)
			if ok && material.Operation == "invite.bind" && binding == value {
				found = material
				count++
			}
		}
	}
	if count > 1 {
		return Material{}, false, errors.New("enrollment binding is not unique")
	}
	return found, count == 1, nil
}
func (a *Authority) Binding(transactionID string) (EnrollmentBind, bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	material, found, err := a.bindingLocked(transactionID)
	if err != nil || !found {
		return EnrollmentBind{}, false, err
	}
	return material.Payload.(EnrollmentBind), true, nil
}
func (a *Authority) enrollmentStateLocked(transactionID string) (string, error) {
	if _, err := a.inviteLocked(transactionID); err != nil {
		return "", err
	}
	target, _ := a.projection.CurrentTarget("invite", transactionID)
	if len(target.MaterialIDs) != 1 {
		return "", errors.New("invite has no unique current fact")
	}
	material, ok := a.materialValueLocked(target.MaterialIDs[0])
	if !ok {
		return "", errors.New("invite current fact is unavailable")
	}
	switch material.Operation {
	case "invite.cancel":
		return "cancelled", nil
	case "invite.expire":
		return "expired", nil
	}
	for _, authorization := range a.projection.DeviceAuthorizations {
		if authorization.TransactionID == transactionID {
			return "completed", nil
		}
	}
	// A revoked/deleted authorization is not a new open enrollment. Remember
	// completion from the original immutable join without granting access.
	for _, item := range a.materials {
		if authorization, ok := item.Payload.(DeviceAuthorization); ok && item.Operation == "device.join" && authorization.TransactionID == transactionID {
			return "completed", nil
		}
	}
	if material.Operation == "invite.bind" {
		return "bound", nil
	}
	if material.Operation == "invite.issue" {
		return "open", nil
	}
	return "", errors.New("invite current fact has no enrollment state")
}
func (a *Authority) EnrollmentState(transactionID string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enrollmentStateLocked(transactionID)
}
func (server *Server) bootstrapInvite(transactionID string) (BootstrapInvite, error) {
	material, err := server.Runtime.Authority.Invite(transactionID)
	if err != nil {
		return BootstrapInvite{}, err
	}
	genesis, err := server.Runtime.Authority.Genesis()
	if err != nil {
		return BootstrapInvite{}, err
	}
	result := BootstrapInvite{Schema: 3, NetworkID: server.Runtime.Config.NetworkID, GenesisDigest: server.Runtime.Config.GenesisID,
		ControlProof: ControlProof{Genesis: genesis, Successors: []ControlCertificate{}}, Material: material}
	return result, result.Validate()
}

func enrollmentRequestID(operation, transactionID string) string {
	value := sha256.Sum256([]byte(transactionID))
	return operation + ":" + hex.EncodeToString(value[:])
}
func sortedUniqueDependencies(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

// CompleteEnrollment owns the same writer lock used by ordinary operations.
// Its two facts are independently durable; retry after either write recovers
// the original binding and key from those facts alone.
func (a *Authority) CompleteEnrollment(ctx context.Context, request EnrollmentClaimRequest, resume bool, identity tunnelIdentity, now time.Time, local NodeConfig) (Submission, error) {
	var err error
	if resume {
		err = EnrollmentResumeRequest(request).Validate()
	} else {
		err = request.Validate()
	}
	if err != nil {
		return Submission{}, err
	}
	lock, err := lockAuthority(ctx, a.root)
	if err != nil {
		return Submission{}, err
	}
	defer lock.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.reloadLocked(); err != nil {
		return Submission{}, err
	}
	if request.NetworkID != local.NetworkID || request.GenesisDigest != local.GenesisID {
		return Submission{}, errors.New("enrollment request changed its fixed network anchor")
	}
	original, err := a.inviteLocked(request.TransactionID)
	if err != nil {
		return Submission{}, err
	}
	originalID, _ := MaterialID(original)
	invite := original.Payload.(Invite)
	if originalID != request.InviteMaterialID || invite.IssuerControlID != local.ControlID {
		return Submission{}, errors.New("enrollment must reach its original issuer with the exact invite")
	}
	if _, err := activeLocalMember(local, a.projection.Config); err != nil {
		return Submission{}, err
	}
	if identity.Mode == "bootstrap" {
		if identity.TransactionID != invite.ID || identity.EndpointID != invite.Endpoint.ID || identity.Generation != invite.Endpoint.Generation {
			return Submission{}, errors.New("enrollment tunnel does not match the frozen invite entry")
		}
	} else if identity.Mode != "device" || !resume || identity.DeviceID != invite.DeviceID {
		return Submission{}, errors.New("authenticated enrollment tunnel is required")
	}
	if request.Platform != "linux" && (len(invite.Responsibilities) != 1 || invite.Responsibilities[0] != "access") {
		return Submission{}, errors.New("platform cannot execute the requested responsibilities")
	}
	bindingMaterial, bound, err := a.bindingLocked(invite.ID)
	if err != nil {
		return Submission{}, err
	}
	binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: originalID, ClaimRequestID: request.RequestID, DevicePublicKey: request.DevicePublicKey, Platform: request.Platform}
	if bound && bindingMaterial.Payload.(EnrollmentBind) != binding {
		return Submission{}, errors.New("enrollment is bound to another request or device identity")
	}
	state, err := a.enrollmentStateLocked(invite.ID)
	if err != nil {
		return Submission{}, err
	}
	if state == "cancelled" || state == "expired" {
		return Submission{}, errors.New("enrollment is terminated")
	}
	if state == "completed" {
		if !bound {
			return Submission{}, errors.New("completed enrollment lost its verified binding")
		}
		for _, authorization := range a.projection.DeviceAuthorizations {
			if authorization.TransactionID == invite.ID {
				target, ok := a.projection.CurrentTarget("device", authorization.ID)
				if ok && !target.Conflicted && !target.Deleted && len(target.MaterialIDs) == 1 {
					return Submission{MaterialID: target.MaterialIDs[0], Projection: cloneAuthorityProjection(a.projection)}, nil
				}
			}
		}
		return Submission{}, errors.New("completed device is no longer authorized")
	}
	if resume && !bound {
		return Submission{}, errors.New("resume requires an existing durable binding")
	}
	if !bound && !now.Before(time.UnixMilli(invite.ExpiresAt)) {
		_, err := a.expireUnboundInviteLocked(ctx, invite.ID, now, local)
		if err != nil {
			return Submission{}, err
		}
		return Submission{}, errors.New("enrollment expired")
	}
	policyDependencies := []string{originalID}
	for _, policyID := range invite.PolicyIDs {
		target, ok := a.projection.CurrentTarget("policy", policyID)
		if !ok || target.Conflicted || target.Deleted {
			return Submission{}, errors.New("invited policy is no longer available")
		}
		policyDependencies = append(policyDependencies, target.MaterialIDs...)
		for _, policy := range a.projection.NetworkIntent.Policies {
			if policy.ID == policyID {
				if service, ok := a.projection.CurrentTarget("service", policy.ServiceID); ok {
					policyDependencies = append(policyDependencies, service.MaterialIDs...)
				}
			}
		}
	}
	if !bound {
		result, err := a.submitOperationLocked(ctx, Operation{Schema: 3, RequestID: enrollmentRequestID("bind", invite.ID), Operation: "invite.bind", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(policyDependencies), Payload: binding}, local)
		if err != nil {
			return Submission{}, err
		}
		bindingMaterial, _ = a.materialValueLocked(result.MaterialID)
	}
	bindingID, _ := MaterialID(bindingMaterial)
	if _, exists := a.projection.CurrentTarget("device", invite.DeviceID); exists {
		return Submission{}, errors.New("device identity already has authorization history")
	}
	dependencies := append(policyDependencies, bindingID)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return Submission{}, err
	}
	responsibilities := []string{}
	for _, value := range invite.Responsibilities {
		if value != "control" {
			responsibilities = append(responsibilities, value)
		}
	}
	authorization := DeviceAuthorization{ID: invite.DeviceID, Name: invite.Name, Platform: binding.Platform, DevicePublicKey: binding.DevicePublicKey,
		Responsibilities: responsibilities, PolicyIDs: append([]string{}, invite.PolicyIDs...), DistributionURLs: []string{}, DNSServers: append([]string(nil), invite.DNSServers...), RuntimeKey: base64.RawURLEncoding.EncodeToString(key),
		TransactionID: invite.ID, InviteMaterialID: originalID, BindingMaterialID: bindingID}
	return a.submitOperationLocked(ctx, Operation{Schema: 3, RequestID: enrollmentRequestID("join", invite.ID), Operation: "device.join", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: sortedUniqueDependencies(dependencies), Payload: authorization}, local)
}

func (server *Server) deviceEnvelope(deviceID string) (DeviceViewEnvelope, error) {
	projection := server.Runtime.Authority.Snapshot()
	member, err := activeLocalMember(server.Runtime.Config, projection.Config)
	if err != nil {
		return DeviceViewEnvelope{}, err
	}
	view, err := ProjectDeviceView(projection, deviceID, server.expectedReleaseSets(projection)...)
	if err != nil {
		return DeviceViewEnvelope{}, err
	}
	genesis, err := server.Runtime.Authority.Genesis()
	if err != nil {
		return DeviceViewEnvelope{}, err
	}
	keyID, err := KeyID(member.PublicKey)
	if err != nil {
		return DeviceViewEnvelope{}, err
	}
	key, err := server.Runtime.Config.PrivateKey()
	if err != nil {
		return DeviceViewEnvelope{}, err
	}
	return SignDeviceViewEnvelope(DeviceViewEnvelope{Schema: 3, NetworkID: projection.NetworkID, GenesisDigest: server.Runtime.Config.GenesisID,
		IssuerControlID: member.ControlID, IssuerKeyID: keyID, ControlProof: ControlProof{Genesis: genesis, Successors: []ControlCertificate{}}, FactFrontier: projection.Frontier, View: view}, key)
}
func (server *Server) EnrollmentResponse(transactionID string) (EnrollmentResponse, error) {
	state, err := server.Runtime.Authority.EnrollmentState(transactionID)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	response := EnrollmentResponse{Schema: 3, TransactionID: transactionID, State: state}
	if state == "completed" {
		material, err := server.Runtime.Authority.Invite(transactionID)
		if err != nil {
			return EnrollmentResponse{}, err
		}
		view, err := server.deviceEnvelope(material.Payload.(Invite).DeviceID)
		if err != nil {
			return EnrollmentResponse{}, err
		}
		response.DeviceView = &view
	}
	return response, response.Validate()
}
func (server *Server) DeviceHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enrollment/claim", server.claim)
	mux.HandleFunc("POST /enrollment/resume", server.resume)
	mux.HandleFunc("POST /device/config", server.deviceConfig)
	mux.HandleFunc("POST /device/report", server.deviceReport)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}
func readDeviceJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, controlHTTPBodyLimit+1))
	if err != nil || DecodeCanonical(body, value, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 128, MaxItems: 1 << 20}) != nil {
		http.Error(w, "invalid canonical device request", http.StatusBadRequest)
		return false
	}
	return true
}
func tunnelAuth(request *http.Request) (tunnelIdentity, bool) {
	value, ok := request.Context().Value(tunnelIdentityKey{}).(tunnelIdentity)
	return value, ok
}
func (server *Server) claim(w http.ResponseWriter, r *http.Request) {
	identity, ok := tunnelAuth(r)
	if !ok || identity.Mode != "bootstrap" {
		http.Error(w, "bootstrap tunnel required", http.StatusForbidden)
		return
	}
	var request EnrollmentClaimRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	server.finishEnrollment(w, r, request, false, identity)
}
func (server *Server) resume(w http.ResponseWriter, r *http.Request) {
	identity, ok := tunnelAuth(r)
	if !ok || identity.Mode != "bootstrap" && identity.Mode != "device" {
		http.Error(w, "authenticated tunnel required", http.StatusForbidden)
		return
	}
	var request EnrollmentResumeRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	server.finishEnrollment(w, r, EnrollmentClaimRequest(request), true, identity)
}
func (server *Server) finishEnrollment(w http.ResponseWriter, r *http.Request, request EnrollmentClaimRequest, resume bool, identity tunnelIdentity) {
	if _, err := server.Runtime.Authority.CompleteEnrollment(r.Context(), request, resume, identity, server.now(), server.Runtime.Config); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	response, err := server.EnrollmentResponse(request.TransactionID)
	if err != nil {
		http.Error(w, "enrollment view unavailable", http.StatusServiceUnavailable)
		return
	}
	writeCanonical(w, http.StatusOK, response)
}
func (server *Server) deviceConfig(w http.ResponseWriter, r *http.Request) {
	identity, ok := tunnelAuth(r)
	if !ok || identity.Mode != "device" {
		http.Error(w, "device tunnel required", http.StatusForbidden)
		return
	}
	view, err := server.deviceEnvelope(identity.DeviceID)
	if err != nil {
		http.Error(w, "device configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	writeCanonical(w, http.StatusOK, view)
}
func (server *Server) deviceReport(w http.ResponseWriter, r *http.Request) {
	identity, ok := tunnelAuth(r)
	if !ok || identity.Mode != "device" || server.Reports == nil {
		http.Error(w, "device report channel unavailable", http.StatusForbidden)
		return
	}
	var report DeviceReport
	if !readDeviceJSON(w, r, &report) {
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	if report.DeviceID != identity.DeviceID || report.NetworkID != projection.NetworkID {
		http.Error(w, "device report identity rejected", http.StatusForbidden)
		return
	}
	authorization, ok := authorizationFor(projection, identity.DeviceID)
	if !ok || server.Reports.Put(report, authorization.DevicePublicKey) != nil {
		http.Error(w, "device report rejected", http.StatusConflict)
		return
	}
	writeCanonical(w, http.StatusOK, DeviceReportResponse{Schema: 3, ReportSequence: report.ReportSequence, Status: "accepted"})
}
