package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"loom/internal/clientmodel"
)

type enrollmentCreatePayload struct {
	Schema            int              `json:"schema,omitempty"`
	TransactionID     string           `json:"transaction_id"`
	ExpiresAt         string           `json:"expires_at"`
	DeviceID          string           `json:"device_id"`
	Name              string           `json:"name"`
	Platform          string           `json:"platform"`
	Roles             []string         `json:"roles"`
	Routes            []RouteCandidate `json:"routes"`
	Runtime           *RuntimeProfile  `json:"runtime_profile,omitempty"`
	Responsibilities  []string         `json:"responsibilities,omitempty"`
	DestinationGrants []string         `json:"destination_grants,omitempty"`
	Direction         string           `json:"direction,omitempty"`
}

// productEnrollmentCreatePayload is the complete browser-facing enrollment
// request. Identity, expiry, roles, routes and runtime are authority-derived
// and deliberately cannot be represented by this wire type.
type productEnrollmentCreatePayload struct {
	Name              string   `json:"name"`
	Platform          string   `json:"platform"`
	Responsibilities  []string `json:"responsibilities"`
	DestinationGrants []string `json:"destination_grants"`
	Direction         string   `json:"direction,omitempty"`
}

func (payload productEnrollmentCreatePayload) internal() enrollmentCreatePayload {
	return enrollmentCreatePayload{Schema: enrollmentSchemaV2, Name: payload.Name, Platform: payload.Platform,
		Responsibilities: payload.Responsibilities, DestinationGrants: payload.DestinationGrants, Direction: payload.Direction}
}

type deviceUpdatePayload struct {
	DeviceID string           `json:"device_id"`
	Routes   []RouteCandidate `json:"routes"`
	Runtime  *RuntimeProfile  `json:"runtime_profile"`
}

type existingNodeRejoinPayload struct {
	DeviceID          string   `json:"device_id"`
	DestinationGrants []string `json:"destination_grants,omitempty"`
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

func (authority *Authority) EnrollmentOpenByRequestID(requestID string) (EnrollmentOpen, bool, error) {
	consensus, _, _ := authority.Snapshot()
	for _, entry := range consensus.Entries {
		body, err := authority.Material(entry.MaterialID)
		if err != nil {
			return EnrollmentOpen{}, false, err
		}
		material, err := DecodeMaterial(body)
		if err != nil {
			return EnrollmentOpen{}, false, err
		}
		if material.RequestID == requestID {
			if material.EnrollmentOpen == nil {
				return EnrollmentOpen{}, false, errors.New("request ID is already used by another operation")
			}
			return *material.EnrollmentOpen, true, nil
		}
	}
	return EnrollmentOpen{}, false, nil
}

func randomEnrollmentID(prefix string, bytes int) (string, error) {
	body := make([]byte, bytes)
	if _, err := rand.Read(body); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(body), nil
}

func productEnrollmentIntent(payload enrollmentCreatePayload) (EnrollmentIntent, error) {
	if payload.Schema != enrollmentSchemaV2 || !validName(payload.Name) {
		return EnrollmentIntent{}, errors.New("schema-2 enrollment request is incomplete")
	}
	if payload.TransactionID != "" || payload.ExpiresAt != "" || payload.DeviceID != "" || len(payload.Roles) != 0 ||
		len(payload.Routes) != 0 || payload.Runtime != nil {
		return EnrollmentIntent{}, errors.New("schema-2 enrollment request contains server-derived fields")
	}
	if payload.Platform != "android" && payload.Platform != "linux" && payload.Platform != "windows" {
		return EnrollmentIntent{}, errors.New("schema-2 enrollment platform is invalid")
	}
	if err := validateSortedNames(payload.Responsibilities, "enrollment responsibilities"); err != nil {
		return EnrollmentIntent{}, err
	}
	if err := validateSortedNames(payload.DestinationGrants, "enrollment grants"); err != nil {
		return EnrollmentIntent{}, errors.New("schema-2 enrollment grants are invalid")
	}
	roles := []string{}
	egress := false
	for _, responsibility := range payload.Responsibilities {
		switch responsibility {
		case "forward":
			roles = append(roles, "server")
		case "internet_egress":
			roles = append(roles, "server")
			egress = true
		case "use_loom":
			roles = append(roles, "access")
		default:
			return EnrollmentIntent{}, errors.New("schema-2 enrollment responsibility is invalid")
		}
	}
	sort.Strings(roles)
	roles = compactStrings(roles)
	if len(roles) == 0 || (payload.Platform == "android" || payload.Platform == "windows") && !contains(roles, "access") {
		return EnrollmentIntent{}, errors.New("platform responsibilities are invalid")
	}
	hasAccess, hasServer := contains(roles, "access"), contains(roles, "server")
	if hasAccess && len(payload.DestinationGrants) == 0 || !hasAccess && egress && len(payload.DestinationGrants) == 0 ||
		!hasAccess && !egress && len(payload.DestinationGrants) != 0 {
		return EnrollmentIntent{}, errors.New("responsibilities and destination grants disagree")
	}
	intent := EnrollmentIntent{Schema: enrollmentSchemaV2, Name: payload.Name, Platform: payload.Platform,
		Roles: roles, DestinationGrants: append([]string(nil), payload.DestinationGrants...)}
	if hasServer {
		if payload.Direction == "" {
			return EnrollmentIntent{}, errors.New("server enrollment direction is required")
		}
		intent.Server = &ServerIntent{Direction: payload.Direction, PublicDataIngress: payload.Direction != "reverse_only",
			EgressCapable: egress}
	} else if payload.Direction != "" {
		return EnrollmentIntent{}, errors.New("access-only enrollment cannot set server direction")
	}
	// DeviceID is authority-generated after this product request has been
	// validated. Full domain validation therefore belongs after that binding;
	// calling it here would reject every browser-created schema-2 enrollment
	// because the browser is deliberately unable to submit an identity.
	return intent, nil
}

func compactStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
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
	if payload.Schema == enrollmentSchemaV2 {
		if open, found, err := server.Runtime.Authority.EnrollmentOpenByRequestID(requestID); err != nil {
			return CertifiedState{}, "", err
		} else if found {
			requested, intentErr := productEnrollmentIntent(payload)
			if intentErr != nil {
				return CertifiedState{}, "", intentErr
			}
			requested.DeviceID = open.Intent.DeviceID
			if intentErr = requested.Validate(); intentErr != nil {
				return CertifiedState{}, "", intentErr
			}
			if !equalEnrollmentIntent(open.Intent, requested) {
				return CertifiedState{}, "", errors.New("request ID is already bound to different enrollment intent")
			}
			invite, encodeErr := EncodeInvite(BootstrapInvite{Schema: enrollmentSchema, Capability: open.Capability})
			return certified, invite, encodeErr
		}
		if baseHead != HeadID(certified.Head) {
			return CertifiedState{}, "", errors.New("base head is stale")
		}
		intent, err := productEnrollmentIntent(payload)
		if err != nil {
			return CertifiedState{}, "", err
		}
		for _, grant := range intent.DestinationGrants {
			if _, found := networkPolicy(projection.NetworkIntent, grant); !found {
				return CertifiedState{}, "", errors.New("enrollment grant is unavailable")
			}
		}
		intent.DeviceID, err = randomEnrollmentID("d-", 5)
		if err != nil {
			return CertifiedState{}, "", err
		}
		if err := intent.Validate(); err != nil {
			return CertifiedState{}, "", err
		}
		if err := validateNewEnrollmentIdentity(certified.Projection, intent.DeviceID); err != nil {
			return CertifiedState{}, "", err
		}
		transactionID, err := randomEnrollmentID("tx-", 16)
		if err != nil {
			return CertifiedState{}, "", err
		}
		expires := server.now().Add(15 * time.Minute).Truncate(time.Second)
		endpoints := servingEndpointReferences(projection)
		if len(endpoints) == 0 {
			return CertifiedState{}, "", errors.New("no serving bootstrap endpoint generation")
		}
		constraint, _ := intentDigest(intent)
		capability := BootstrapCapability{Schema: enrollmentSchema, TransactionID: transactionID,
			IssuedHead: HeadID(certified.Head), ConfigMaterial: projection.ConfigMaterial, ControlConfig: projection.Config,
			ExpiresAt: expires.Format(time.RFC3339), Actions: []string{"claim", "resume"}, Endpoints: endpoints,
			ConstraintDigest: constraint, IssuerMemberID: server.Config.MemberID}
		capability, err = SignBootstrapCapability(capability, server.Config)
		if err != nil {
			return CertifiedState{}, "", err
		}
		open := EnrollmentOpen{TransactionID: transactionID, Intent: intent, Capability: capability}
		material := Material{Schema: MaterialSchema, Kind: "enrollment.open", RequestID: requestID,
			BaseHead: baseHead, EnrollmentOpen: &open}
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
	if payload.Platform == "linux" && payload.Runtime == nil {
		return CertifiedState{}, "", errors.New("Linux enrollment requires a certified runtime profile")
	}
	if payload.Runtime != nil {
		canonical, canonicalErr := clientmodel.CanonicalizeRuntimeConfig([]byte(payload.Runtime.Config))
		if canonicalErr != nil {
			return CertifiedState{}, "", canonicalErr
		}
		if payload.Platform == "windows" && canonical != payload.Runtime.Config {
			return CertifiedState{}, "", errors.New("Windows runtime profile config is not canonical")
		}
		payload.Runtime.Config = canonical
	}
	if _, transaction := findEnrollment(&projection, payload.TransactionID); transaction != nil {
		open, err := server.Runtime.Authority.EnrollmentOpen(payload.TransactionID)
		if err != nil {
			return CertifiedState{}, "", err
		}
		intent := EnrollmentIntent{DeviceID: payload.DeviceID, Name: payload.Name, Platform: payload.Platform,
			Roles: payload.Roles, Routes: payload.Routes, Runtime: payload.Runtime}
		if !equalEnrollmentIntent(open.Intent, intent) || open.Capability.ExpiresAt != payload.ExpiresAt {
			return CertifiedState{}, "", errors.New("enrollment transaction ID is already bound to different intent")
		}
		invite, err := EncodeInvite(BootstrapInvite{Schema: enrollmentSchema, Capability: open.Capability})
		return certified, invite, err
	}
	if baseHead != HeadID(certified.Head) {
		return CertifiedState{}, "", errors.New("base head is stale")
	}
	if err := validateNewEnrollmentIdentity(certified.Projection, payload.DeviceID); err != nil {
		return CertifiedState{}, "", err
	}
	expires, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil || payload.ExpiresAt != expires.UTC().Format(time.RFC3339) || !expires.After(server.now()) {
		return CertifiedState{}, "", errors.New("enrollment expiry is invalid")
	}
	intent := EnrollmentIntent{DeviceID: payload.DeviceID, Name: payload.Name, Platform: payload.Platform,
		Roles: append([]string(nil), payload.Roles...), Routes: append([]RouteCandidate(nil), payload.Routes...),
		Runtime: cloneRuntimeProfile(payload.Runtime)}
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

func (server *Server) createExistingNodeRejoin(ctx context.Context, requestID, baseHead string,
	payload existingNodeRejoinPayload) (CertifiedState, string, error) {
	if !validName(payload.DeviceID) || validateSortedNames(payload.DestinationGrants, "existing-node rejoin grants") != nil {
		return CertifiedState{}, "", errors.New("existing-node rejoin request is invalid")
	}
	_, projection, certified := server.Runtime.Authority.Snapshot()
	if open, found, err := server.Runtime.Authority.EnrollmentOpenByRequestID(requestID); err != nil {
		return CertifiedState{}, "", err
	} else if found {
		if open.Intent.Schema != enrollmentSchemaV2 || open.Intent.DeviceID != payload.DeviceID ||
			!equalStrings(open.Intent.DestinationGrants, payload.DestinationGrants) {
			return CertifiedState{}, "", errors.New("request ID is already bound to different existing-node rejoin intent")
		}
		invite, encodeErr := EncodeInvite(BootstrapInvite{Schema: enrollmentSchema, Capability: open.Capability})
		return certified, invite, encodeErr
	}
	if baseHead != HeadID(certified.Head) {
		return CertifiedState{}, "", errors.New("base head is stale")
	}
	node, found := networkNode(projection.NetworkIntent, payload.DeviceID)
	if !found || node.Platform == "" {
		return CertifiedState{}, "", errors.New("existing-node rejoin target is not in certified network intent")
	}
	for _, authorization := range projection.DeviceAuthorizations {
		if authorization.DeviceID == payload.DeviceID {
			return CertifiedState{}, "", errors.New("existing-node rejoin target already has a device authorization")
		}
	}
	for _, grant := range payload.DestinationGrants {
		if _, found := networkPolicy(projection.NetworkIntent, grant); !found {
			return CertifiedState{}, "", errors.New("existing-node rejoin grant is unavailable")
		}
	}
	intent := EnrollmentIntent{Schema: enrollmentSchemaV2, DeviceID: node.ID, Name: node.Name,
		Platform: node.Platform, Roles: append([]string(nil), node.Roles...),
		DestinationGrants: append([]string(nil), payload.DestinationGrants...)}
	if node.Server != nil {
		intent.Server = &ServerIntent{Direction: node.Server.Direction, PublicDataIngress: node.Server.PublicDataIngress,
			EgressCapable: node.Server.EgressCapable}
	}
	if node.Server != nil && node.Server.EgressCapable && len(payload.DestinationGrants) == 0 {
		return CertifiedState{}, "", errors.New("existing egress rejoin requires at least one policy grant")
	}
	if err := intent.Validate(); err != nil {
		return CertifiedState{}, "", err
	}
	transactionID, err := randomEnrollmentID("tx-", 16)
	if err != nil {
		return CertifiedState{}, "", err
	}
	expires := server.now().Add(15 * time.Minute).Truncate(time.Second)
	endpoints := servingEndpointReferences(projection)
	if len(endpoints) == 0 {
		return CertifiedState{}, "", errors.New("no serving bootstrap endpoint generation")
	}
	constraint, _ := intentDigest(intent)
	capability := BootstrapCapability{Schema: enrollmentSchema, TransactionID: transactionID,
		IssuedHead: HeadID(certified.Head), ConfigMaterial: projection.ConfigMaterial, ControlConfig: projection.Config,
		ExpiresAt: expires.Format(time.RFC3339), Actions: []string{"claim", "resume"}, Endpoints: endpoints,
		ConstraintDigest: constraint, IssuerMemberID: server.Config.MemberID}
	capability, err = SignBootstrapCapability(capability, server.Config)
	if err != nil {
		return CertifiedState{}, "", err
	}
	open := EnrollmentOpen{TransactionID: transactionID, Intent: intent, Capability: capability}
	material := Material{Schema: MaterialSchema, Kind: "enrollment.open", RequestID: requestID,
		BaseHead: baseHead, EnrollmentOpen: &open}
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
	if transaction.State == "bound" && transaction.Intent.Schema != enrollmentSchemaV2 {
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
	if transaction == nil || transaction.State != "approved" && (transaction.State != "bound" || transaction.Intent.Schema != enrollmentSchemaV2) {
		return CertifiedState{}, errors.New("enrollment transaction is not bound or approved")
	}
	authorization := DeviceAuthorization{Schema: enrollmentSchema, DeviceID: transaction.Intent.DeviceID,
		Name: transaction.Intent.Name, Platform: transaction.Intent.Platform, Roles: append([]string(nil), transaction.Intent.Roles...),
		Routes: append([]RouteCandidate(nil), transaction.Intent.Routes...), Runtime: cloneRuntimeProfile(transaction.Intent.Runtime),
		DevicePublicKey: transaction.DevicePublicKey,
		Floor:           certified.Head.Index + 1}
	requestMaterialID := requestID + ":complete"
	if transaction.Intent.Schema == enrollmentSchemaV2 {
		runtimeKey := make([]byte, 32)
		if _, err := rand.Read(runtimeKey); err != nil {
			return CertifiedState{}, err
		}
		authorization.Schema = enrollmentSchemaV2
		authorization.Name = ""
		authorization.Platform = ""
		authorization.Roles = nil
		authorization.Routes = nil
		authorization.Runtime = nil
		authorization.DestinationGrants = append([]string(nil), transaction.Intent.DestinationGrants...)
		authorization.Server = nil
		authorization.RuntimeKey = base64.RawURLEncoding.EncodeToString(runtimeKey)
		requestMaterialID = requestID
	}
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
	if transaction.Intent.Schema == enrollmentSchemaV2 {
		claimedServer, claimErr := serverIntentFromClaim(transaction.Intent.Server, transaction.ClaimedServer)
		if transaction.Intent.Server == nil {
			claimedServer, claimErr = nil, nil
		}
		if claimErr != nil {
			return CertifiedState{}, claimErr
		}
		if err := integrateEnrollmentNetworkIntent(&projected, transaction.Intent, claimedServer); err != nil {
			return CertifiedState{}, err
		}
	}
	view, found := projectDeviceView(projected, authorization.DeviceID)
	if !found {
		return CertifiedState{}, errors.New("device view projection failed")
	}
	digest, _ := DeviceViewDigest(view)
	complete := EnrollmentComplete{TransactionID: transactionID, Authorization: authorization, ResultDigest: digest}
	material := Material{Schema: MaterialSchema, Kind: "enrollment.complete", RequestID: requestMaterialID,
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
		endpoints := server.endpointRuntime()
		if endpoints == nil || generation.Node != server.Config.Node || !endpoints.Ready(generation) {
			return CertifiedState{}, errors.New("endpoint generation is not locally ready")
		}
	}
	if previous != nil && previous.State == "serving" && generation.State == "draining" {
		endpoints := server.endpointRuntime()
		ready := false
		for _, candidate := range projection.EndpointGenerations {
			if candidate.EndpointID == generation.EndpointID && candidate.Generation != generation.Generation &&
				candidate.State == "serving" && candidate.Preference < generation.Preference && endpoints != nil && endpoints.Successes(candidate) > 0 {
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
	endpoints := server.endpointRuntime()
	if previous != nil && previous.State == "draining" && generation.State == "retired" &&
		(endpoints == nil || endpoints.Active(generation) != 0) {
		return CertifiedState{}, errors.New("endpoint generation still has protected sessions")
	}
	material := Material{Schema: MaterialSchema, Kind: "endpoint.put", RequestID: requestID, BaseHead: baseHead, EndpointGeneration: &generation}
	body, _, err := EncodeMaterial(material)
	if err != nil {
		return CertifiedState{}, err
	}
	return server.Runtime.Submit(ctx, body)
}

func (server *Server) putDevice(ctx context.Context, requestID, baseHead string, payload deviceUpdatePayload) (CertifiedState, error) {
	_, projection, certified := server.Runtime.Authority.Snapshot()
	if baseHead != HeadID(certified.Head) {
		return CertifiedState{}, errors.New("base head is stale")
	}
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= payload.DeviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != payload.DeviceID {
		return CertifiedState{}, errors.New("device authorization does not exist")
	}
	if payload.Runtime == nil {
		return CertifiedState{}, errors.New("device runtime profile is required")
	}
	canonicalConfig, err := clientmodel.CanonicalizeRuntimeConfig([]byte(payload.Runtime.Config))
	if err != nil {
		return CertifiedState{}, err
	}
	authorization := projection.DeviceAuthorizations[index]
	if authorization.Schema == enrollmentSchemaV2 {
		return CertifiedState{}, errors.New("schema-2 device runtime is derived from certified network intent")
	}
	if authorization.Platform == "windows" && canonicalConfig != payload.Runtime.Config {
		return CertifiedState{}, errors.New("Windows runtime profile config is not canonical")
	}
	payload.Runtime.Config = canonicalConfig
	authorization.Routes = append([]RouteCandidate(nil), payload.Routes...)
	authorization.Runtime = cloneRuntimeProfile(payload.Runtime)
	authorization.Floor = certified.Head.Index + 1
	material := Material{Schema: MaterialSchema, Kind: "device.put", RequestID: requestID, BaseHead: baseHead,
		DeviceAuthorization: &authorization}
	body, _, err := EncodeMaterial(material)
	if err != nil {
		return CertifiedState{}, err
	}
	return server.Runtime.Submit(ctx, body)
}

func (server *Server) revokeDevice(ctx context.Context, requestID, baseHead, deviceID string) (CertifiedState, error) {
	if !validName(deviceID) {
		return CertifiedState{}, errors.New("device ID is invalid")
	}
	_, projection, certified := server.Runtime.Authority.Snapshot()
	if baseHead != HeadID(certified.Head) {
		return CertifiedState{}, errors.New("base head is stale")
	}
	if _, found := authorizationFor(projection, deviceID); !found {
		return CertifiedState{}, errors.New("device authorization does not exist")
	}
	revoke := DeviceRevoke{DeviceID: deviceID}
	material := Material{Schema: MaterialSchema, Kind: "device.revoke", RequestID: requestID, BaseHead: baseHead,
		DeviceRevoke: &revoke}
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
	response := EnrollmentResponse{Schema: enrollmentWireSchema(transaction.Intent), Transaction: *transaction}
	if transaction.State == "completed" {
		envelope, err := DeviceViewFor(certified.Projection, certified.Head, transaction.Intent.DeviceID)
		if err != nil {
			return EnrollmentResponse{}, err
		}
		response.DeviceView = &envelope
	}
	return response, nil
}

// The deployed enrollment intent predates an explicit schema field: its
// canonical historical value is zero while its claim/resume wire protocol is
// schema 1. Schema-2 intent and wire values are both explicit. Keep this
// translation at the protocol boundary rather than rewriting replayed intent.
func enrollmentWireSchema(intent EnrollmentIntent) int {
	if intent.Schema == enrollmentSchemaV2 {
		return enrollmentSchemaV2
	}
	return enrollmentSchema
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
	if claim.Schema != enrollmentWireSchema(transaction.Intent) {
		http.Error(writer, "enrollment claim schema does not match product intent", http.StatusUnprocessableEntity)
		return
	}
	claimedServer := claim.Server
	if transaction.Intent.Schema == enrollmentSchemaV2 {
		requiresServer := transaction.Intent.Server != nil
		if requiresServer != (claimedServer != nil) || requiresServer && transaction.Intent.Platform != "linux" {
			http.Error(writer, "enrollment server claim does not match product intent", http.StatusUnprocessableEntity)
			return
		}
		if claimedServer != nil {
			if claimedServer.Validate() != nil {
				http.Error(writer, "enrollment server facts are invalid", http.StatusUnprocessableEntity)
				return
			}
		}
	}
	if transaction.State == "open" {
		if !server.now().Before(mustTime(claim.Capability.ExpiresAt)) {
			http.Error(writer, "enrollment capability expired", http.StatusGone)
			return
		}
		bind := EnrollmentBind{TransactionID: transaction.ID, ClaimRequestID: claim.RequestID,
			DevicePublicKey: claim.DevicePublicKey, ClaimedAt: server.now().Format(time.RFC3339), Server: claimedServer}
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
	} else {
		left, _ := canonical(transaction.ClaimedServer)
		right, _ := canonical(claimedServer)
		if transaction.DevicePublicKey != claim.DevicePublicKey || transaction.ClaimRequestID != claim.RequestID || !bytes.Equal(left, right) {
			http.Error(writer, "enrollment transaction is bound to another identity", http.StatusConflict)
			return
		}
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
	if resume.Schema != enrollmentWireSchema(response.Transaction.Intent) {
		http.Error(writer, "enrollment resume schema does not match product intent", http.StatusUnprocessableEntity)
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
	reportedAt, parseErr := time.Parse(time.RFC3339, report.ReportedAt)
	if parseErr != nil || reportedAt.After(server.now().Add(2*time.Minute)) || reportedAt.Before(server.now().Add(-30*24*time.Hour)) {
		http.Error(writer, "device report time is outside the accepted window", http.StatusUnprocessableEntity)
		return
	}
	_, _, certified := server.Runtime.Authority.Snapshot()
	projection := certified.Projection
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= report.DeviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != report.DeviceID {
		http.Error(writer, "device report signature rejected", http.StatusForbidden)
		return
	}
	if err := verifyCurrentReport(report, projection); err != nil {
		status := http.StatusForbidden
		if err.Error() == "device report view is stale" {
			status = http.StatusConflict
		}
		http.Error(writer, err.Error(), status)
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
