package loomcore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

// Shared measurement snapshots use the existing private response/cache bound.
const androidMeasurementSnapshotLimit = control.MeasurementDeliveryLimit

// This is a disposable Android host projection, never a second authority wire.
type androidProfile struct {
	ExecutionDigest               string                        `json:"execution_digest"`
	Services                      []control.Service             `json:"services"`
	Policies                      []control.NetworkPolicy       `json:"policies"`
	Scopes                        []string                      `json:"scopes"`
	PossiblePermissionRestoration bool                          `json:"possible_permission_restoration"`
	HasWebsite                    bool                          `json:"has_website"`
	Schema                        int                           `json:"schema"`
	NodeID                        string                        `json:"node_id"`
	Name                          string                        `json:"name"`
	ViewDigest                    string                        `json:"view_digest"`
	FactFrontier                  []control.FactFrontier        `json:"fact_frontier"`
	Config                        string                        `json:"config"`
	Routes                        []clientmodel.RouteCandidate  `json:"routes"`
	RecordID                      string                        `json:"record_id"`
	DNS                           []string                      `json:"dns"`
	BusinessProbeTargets          []control.ServiceProbeTargets `json:"business_probe_targets"`
	ResourceCacheIdentity         string                        `json:"resource_cache_identity"`
}

func decodeState(body []byte) (deviceclient.State, error) {
	return androidStateReads.decode(body, decodeAndroidIdentity)
}

func decodeAndroidIdentity(body []byte) (deviceclient.State, error) {
	state, err := deviceclient.DecodeIdentityState(body)
	if err == nil && state.Platform != "android" {
		err = errors.New("identity belongs to another platform")
	}
	return state, err
}
func NewAndroidDeviceState(raw string) ([]byte, error) {
	invite, err := control.DecodeInvite(raw)
	if err != nil {
		return nil, err
	}
	if invite.Medium != "qr" {
		return nil, errors.New("Android supports access invitations")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	request := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, request); err != nil {
		return nil, err
	}
	state, err := deviceclient.NewPendingIdentityState(invite, "android", private, hex.EncodeToString(request))
	if err != nil {
		return nil, err
	}
	return deviceclient.EncodeIdentityState(state)
}
func ValidateAndroidDeviceState(body []byte) error { _, err := decodeState(body); return err }
func CheckAndroidDeviceStateAdvance(nextBody, previousBody []byte) error {
	next, err := decodeState(nextBody)
	if err != nil {
		return err
	}
	previous, err := decodeState(previousBody)
	if err != nil {
		return err
	}
	return deviceclient.CheckIdentityStateAdvance(next, previous)
}

// This review contains public object IDs and change kinds, never credentials.
// The host requests it before atomically replacing its one encrypted LKG.
func AndroidMemberReview(nextBody, previousBody []byte) ([]byte, error) {
	next, err := decodeState(nextBody)
	if err != nil {
		return nil, err
	}
	previous, err := decodeState(previousBody)
	if err != nil {
		return nil, err
	}
	if err = deviceclient.CheckIdentityStateAdvance(next, previous); err != nil {
		return nil, err
	}
	return json.Marshal(deviceclient.ReviewMemberTransition(next, previous))
}
func AndroidEnrollmentState(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	value := struct {
		PossiblePermissionRestoration bool                   `json:"possible_permission_restoration"`
		Schema                        int                    `json:"schema"`
		TransactionID                 string                 `json:"transaction_id"`
		Claimed                       bool                   `json:"claimed"`
		Ready                         bool                   `json:"ready"`
		NodeID                        string                 `json:"node_id"`
		ViewDigest                    string                 `json:"view_digest"`
		FactFrontier                  []control.FactFrontier `json:"fact_frontier"`
	}{PossiblePermissionRestoration: deviceclient.PossiblePermissionRestoration(state), Schema: 3, TransactionID: state.TransactionID(), Claimed: state.LKG != nil, Ready: state.LKG != nil, FactFrontier: []control.FactFrontier{}}
	if state.LKG != nil {
		value.NodeID = state.LKG.View.DeviceID
		value.ViewDigest = state.LKG.ViewDigest
		value.FactFrontier = state.LKG.FactFrontier
	}
	return json.Marshal(value)
}
func AndroidDeviceProfile(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	return androidDeviceProfile(state)
}

// PrepareAndroidDeviceProfile is the operational entry before VPN capture.
// UI reads use AndroidDeviceProfile and remain pure; only this entry resolves
// certified website underlay names through the protected Android sockets.
func PrepareAndroidDeviceProfile(body, interfaceAddresses []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil {
		return nil, errors.New("device has no accepted LKG")
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 15*time.Second)
	defer cancel()
	addresses, err := deviceclient.WebsiteAddresses(ctx, state.LKG.View.WebEndpoints, state.LKG.View.DNSServers)
	if err != nil {
		return nil, err
	}
	website, err := clientadapter.WebsiteAccessFor(state.LKG.View, addresses)
	if err != nil {
		return nil, err
	}
	body, err = androidDeviceProfile(state, website)
	if err != nil {
		return nil, err
	}
	var profile androidProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, err
	}
	connected, _ := androidConnectedIPv4Prefixes(interfaceAddresses)
	profile.Config, err = clientadapter.WithLocalNetworkBoundary(profile.Config, connected)
	if err != nil {
		return nil, err
	}
	return json.Marshal(profile)
}

func androidDeviceProfile(state deviceclient.State, websites ...clientadapter.WebsiteAccess) ([]byte, error) {
	if state.LKG == nil {
		return nil, errors.New("device has no accepted LKG")
	}
	view := state.LKG.View
	// A local management secret is not a Service credential and never travels
	// in DeviceView. It has a separate purpose and is bound to this device key.
	secret := androidLocalRuntimeSecret(state)
	routes, raw, err := clientadapter.AccessRuntimeProjection(view, clientmodel.MeasurementPolicies(androidPreference(state)), secret, websites...)
	if err != nil {
		return nil, err
	}
	config, err := androidHostConfig(view, raw, secret, websites...)
	if err != nil {
		return nil, err
	}
	identity, err := clientadapter.ResourceCacheIdentity(*state.LKG)
	if err != nil {
		return nil, err
	}
	services, policies := clientmodel.PolicyOptions(view)
	execution, err := control.RuntimeExecutionDigest(view)
	if err != nil {
		return nil, err
	}
	return json.Marshal(androidProfile{ExecutionDigest: execution, Services: services, Policies: policies, Scopes: clientmodel.SelectorScopes(view), PossiblePermissionRestoration: deviceclient.PossiblePermissionRestoration(state), HasWebsite: len(view.WebEndpoints) > 0, Schema: 3, NodeID: view.DeviceID, Name: view.Name, ViewDigest: state.LKG.ViewDigest, FactFrontier: state.LKG.FactFrontier, Config: config, Routes: routes, RecordID: state.LKG.ViewDigest, DNS: append([]string{}, view.DNSServers...), BusinessProbeTargets: serviceProbeTargets(view), ResourceCacheIdentity: identity})
}
func androidLocalRuntimeSecret(state deviceclient.State) string {
	key, _ := base64.RawURLEncoding.DecodeString(state.PrivateKey)
	sum := sha256.Sum256(append([]byte("loom-android-local-selector-v3\x00"), key...))
	clear(key)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func androidRuntimeConfig(view control.DeviceView, secret string, websites ...clientadapter.WebsiteAccess) (string, error) {
	raw, err := clientadapter.ManagedRuntimeConfig(view, secret, websites...)
	if err != nil {
		return "", err
	}
	return androidHostConfig(view, raw, secret, websites...)
}

func androidHostConfig(view control.DeviceView, raw, secret string, websites ...clientadapter.WebsiteAccess) (string, error) {
	var err error
	raw, err = clientadapter.WithBlockedSelectors(raw)
	if err != nil {
		return "", err
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return "", err
	}
	exclusions := map[string]bool{}
	if len(websites) == 1 {
		prefixes, err := websites[0].Exclusions()
		if err != nil {
			return "", err
		}
		for _, prefix := range prefixes {
			exclusions[prefix] = true
		}
	}
	for _, endpoint := range view.Endpoints {
		address, err := netip.ParseAddr(endpoint.Host)
		if err != nil {
			if len(view.DNSServers) == 0 {
				return "", errors.New("Android capture requires authenticated endpoint address resolution")
			}
			// Go private-service sockets and their DNS queries use the active
			// VpnService protect callback, including after DNS addresses change.
			continue
		}
		exclusions[netip.PrefixFrom(address, address.BitLen()).String()] = true
	}
	prefixes := make([]string, 0, len(exclusions))
	for prefix := range exclusions {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	document["inbounds"] = []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"192.0.2.1/30", "2001:db8::1/126"}, "mtu": 1500, "auto_route": true, "stack": "gvisor", "route_exclude_address": prefixes}}
	route := document["route"].(map[string]any)
	// On Android this enables the existing VpnService.protect callback for
	// libbox TCP/UDP sockets. It changes neither the signed ACL nor its grants.
	route["auto_detect_interface"] = true
	rules := route["rules"].([]any)
	// Sniff only supplies absent metadata. Literal IP targets remain IP targets;
	// TUN DNS restores its own domain requests separately before transport.
	sniff := map[string]any{"type": "logical", "mode": "and", "rules": []any{map[string]any{"inbound": []string{"tun-in"}}, map[string]any{"domain_regex": []string{".+"}, "invert": true}, map[string]any{"port": []int{53}, "invert": true}}, "action": "sniff"}
	route["rules"] = append([]any{sniff}, rules...)
	body, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	captured, err := clientadapter.WithTUNDomainDNS(string(body))
	if err != nil {
		return "", err
	}
	captured, err = clientadapter.WithTUNCapture(captured)
	if err != nil {
		return "", err
	}
	return captured, nil
}

// The temporary adapter has no storage and performs no execution. Kotlin owns
// the one protected identity record and commits the returned value before use.
type androidIdentity struct{ state deviceclient.State }

func (store *androidIdentity) Invite() control.BootstrapInvite {
	if store.state.Invite == nil {
		return control.BootstrapInvite{}
	}
	return *store.state.Invite
}
func (store *androidIdentity) Reference() (control.InvitationReference, error) {
	return store.state.Reference()
}
func (store *androidIdentity) SaveEnrollmentProof(proof control.BootstrapInvite) error {
	next, err := deviceclient.AcceptEnrollmentProof(store.state, proof)
	if err == nil {
		store.state = next
	}
	return err
}
func (store *androidIdentity) Platform() string  { return store.state.Platform }
func (store *androidIdentity) PublicKey() string { return store.state.PublicKey }
func (store *androidIdentity) PrivateKey() ed25519.PrivateKey {
	key, _ := base64.RawURLEncoding.DecodeString(store.state.PrivateKey)
	return ed25519.PrivateKey(key)
}
func (store *androidIdentity) ClaimRequestID() string           { return store.state.ClaimRequestID }
func (store *androidIdentity) LKG() *control.DeviceViewEnvelope { return store.state.LKG }
func (store *androidIdentity) SaveLKG(view control.DeviceViewEnvelope) error {
	next, err := deviceclient.AcceptLKG(store.state, view)
	if err == nil {
		store.state = next
	}
	return err
}
func (*androidIdentity) ReserveReportSequence() (control.U64, error) {
	return 0, errors.New("Android report reservation must be committed by the protected host store")
}

// NewAndroidLinkObservationRequest owns one private batch fetch, independently
// cancellable from local first-hop exploration and report uploads.
func NewAndroidLinkObservationRequest(body, previousBody []byte) (*AndroidDeviceRequest, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil {
		return nil, errors.New("shared observations require an accepted configuration")
	}
	var previous *control.DeviceLinkObservations
	if len(previousBody) > 0 {
		var cache control.DeviceLinkObservations
		if err := control.DecodeCanonical(previousBody, &cache, control.ContractDecodeLimits{MaxBytes: androidMeasurementSnapshotLimit, MaxDepth: 32, MaxItems: 1 << 20}); err == nil && cache.Reset && cache.ValidateForView(state.LKG.View) == nil {
			previous = &cache
		}
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 3*time.Second)
	return &AndroidDeviceRequest{ctx: ctx, cancel: cancel, run: func(ctx context.Context) ([]byte, error) {
		value, err := deviceclient.FetchLinkObservations(ctx, &androidIdentity{state: state}, previous)
		if err != nil {
			return nil, err
		}
		return encodeAndroidMeasurementSnapshot(ctx, value)
	}}, nil
}

// The host commits these complete canonical bytes together with their cursor.
// Fetch/Merge already checked scope and delta semantics; encoding must still
// respect the same total bound and the original request's cancellation.
func encodeAndroidMeasurementSnapshot(ctx context.Context, value control.DeviceLinkObservations) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body, err := control.CanonicalEncode(value)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(body) > androidMeasurementSnapshotLimit {
		return nil, errors.New("merged measurement snapshot exceeds its byte bound")
	}
	return body, nil
}
func ReserveAndroidReportSequence(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	next, _, err := deviceclient.AdvanceReportSequence(state)
	if err != nil {
		return nil, err
	}
	return deviceclient.EncodeIdentityState(next)
}

type androidObservation struct {
	CandidateID       string `json:"candidate_id"`
	NetworkGeneration string `json:"network_generation"`
	Scope             string `json:"scope"`
	Result            string `json:"result"`
	Action            string `json:"action"`
	Target            string `json:"target"`
	ObservedAt        string `json:"observed_at"`
	ValidUntil        string `json:"valid_until"`
	MetricMillis      *int64 `json:"metric_millis,omitempty"`
}
type androidSelection struct {
	Targets     map[string]string `json:"targets"`
	Scope       string            `json:"scope"`
	CandidateID string            `json:"candidate_id"`
}

const androidReportTimeLayout = "2006-01-02T15:04:05.000Z"

func androidReport(state deviceclient.State, preferenceBody, resourceBody, observationsBody, selectionsBody, runtimeBody, componentsBody, interfaceAddresses []byte, generation, reportedAt string) (control.DeviceReport, error) {
	if state.LKG == nil || state.ReportSequence == 0 {
		return control.DeviceReport{}, errors.New("Android report sequence has not been reserved")
	}
	if state.Preference == nil {
		return control.DeviceReport{}, errors.New("Android report has no durable current Policy preference")
	}
	preference := *state.Preference
	if len(preferenceBody) > 0 {
		var projected clientmodel.Preference
		if err := control.DecodeCanonical(preferenceBody, &projected, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 1024}); err != nil {
			return control.DeviceReport{}, err
		}
		if !projected.Equal(preference) {
			return control.DeviceReport{}, errors.New("Android report preference differs from its durable identity")
		}
	}
	reportedPreference, err := clientadapter.ReportedPolicyID(state.LKG.View, preference)
	if err != nil {
		return control.DeviceReport{}, err
	}
	lanChoices, err := clientadapter.ReportedLANPolicyIDs(state.LKG.View, preference)
	if err != nil {
		return control.DeviceReport{}, err
	}
	var observations []androidObservation
	var selections []androidSelection
	var runtime control.RuntimeReadback
	var components []control.ComponentReadback
	if err := decodeStrictJSON(observationsBody, 1<<20, &observations); err != nil {
		return control.DeviceReport{}, err
	}
	if err := decodeStrictJSON(selectionsBody, 1<<20, &selections); err != nil {
		return control.DeviceReport{}, err
	}
	if err := decodeStrictJSON(runtimeBody, 1<<20, &runtime); err != nil {
		return control.DeviceReport{}, err
	}
	if err := decodeStrictJSON(componentsBody, 1<<20, &components); err != nil {
		return control.DeviceReport{}, err
	}
	fullyApplied := runtime.State == "running" && runtime.AppliedViewDigest == state.LKG.ViewDigest
	if len(observations) > 0 && !fullyApplied {
		return control.DeviceReport{}, errors.New("business samples require fully confirmed Android execution")
	}
	// Kotlin supplies only the scopes with a complete current native readback.
	// Their confirmed subset does not assert whole-runtime application; intent
	// and candidate qualification are still checked below by ReportSelections.
	partialScopes := runtime.State == "unknown" && runtime.AppliedViewDigest == "" && runtime.PermissionViewDigest == state.LKG.ViewDigest
	if len(selections) > 0 && !fullyApplied && !partialScopes {
		return control.DeviceReport{}, errors.New("actual selections require confirmed current Android execution or permissions")
	}
	for _, component := range components {
		if (component.ComponentID != "agent" && component.ComponentID != "sing-box") || component.Platform != androidComponentPlatform() {
			return control.DeviceReport{}, errors.New("Android component is outside the executing platform")
		}
	}
	now, err := time.Parse(androidReportTimeLayout, reportedAt)
	if err != nil || now.UTC().Format(androidReportTimeLayout) != reportedAt {
		return control.DeviceReport{}, errors.New("Android report time is not canonical")
	}
	report := control.DeviceReport{Schema: 3, NetworkID: state.Invite.NetworkID, DeviceID: state.LKG.View.DeviceID, ReportSequence: state.ReportSequence, ViewDigest: state.LKG.ViewDigest, NetworkGeneration: generation, ReportedAt: now.UnixMilli(), PolicyID: reportedPreference, LANPolicyIDs: lanChoices, Selections: []control.ReportSelection{}, Observations: []control.Observation{}, Runtime: runtime, Components: components}
	if len(resourceBody) > 0 {
		if !runtime.HasCurrentPermissions(state.LKG.ViewDigest) {
			return control.DeviceReport{}, errors.New("resource samples require confirmed current Android permissions")
		}
		values, err := clientadapter.DecodeResourceObservations(resourceBody, *state.LKG, generation, clientmodel.MeasurementPolicies(preference))
		if err != nil {
			return control.DeviceReport{}, err
		}
		report.Observations = append(report.Observations, values...)
	}
	executionProjection, err := control.ProjectDeviceCandidates(state.LKG.View, clientmodel.MeasurementPolicies(preference))
	if err != nil {
		return control.DeviceReport{}, err
	}
	routes := map[string]control.RouteCandidate{}
	targets := map[string]map[string]bool{}
	for _, route := range executionProjection.Routes {
		routes[route.ID] = route
	}
	for _, group := range executionProjection.BusinessProbeTargets {
		targets[group.ServiceID] = map[string]bool{}
		for _, target := range group.Targets {
			targets[group.ServiceID][target] = true
		}
	}
	actualSelections := []clientadapter.SelectionStatus{}
	for _, selection := range selections {
		actualSelections = append(actualSelections, clientadapter.SelectionStatus{Scope: selection.Scope, CandidateID: selection.CandidateID, Targets: selection.Targets})
	}
	report.Selections, err = clientadapter.ReportSelections(state.LKG.View, preference, actualSelections)
	if err != nil {
		return control.DeviceReport{}, err
	}

	for _, observation := range observations {
		route, ok := routes[observation.CandidateID]
		if !ok || observation.Scope != control.AccessSelectorScope || !targets[route.ServiceID][observation.Target] || observation.Action != "https_request" || observation.NetworkGeneration != generation {
			return control.DeviceReport{}, errors.New("reported business observation is outside its authenticated Service")
		}
		observed, e1 := time.Parse(time.RFC3339, observation.ObservedAt)
		until, e2 := time.Parse(time.RFC3339, observation.ValidUntil)
		if e1 != nil || e2 != nil || observed.UTC().Format(time.RFC3339) != observation.ObservedAt || until.UTC().Format(time.RFC3339) != observation.ValidUntil {
			return control.DeviceReport{}, errors.New("reported observation time is not canonical")
		}
		report.Observations = append(report.Observations, control.Observation{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, Target: observation.Target, Action: observation.Action, SpecDigest: route.SpecDigest, NetworkGeneration: generation, Result: observation.Result, ObservedAt: observed.UnixMilli(), ValidUntil: until.UnixMilli(), DurationMS: observation.MetricMillis})
	}
	sort.Slice(report.Observations, func(i, j int) bool {
		a, b := report.Observations[i], report.Observations[j]
		return strings.Join([]string{a.Level, a.ServiceID, a.CandidateID, a.ResourceID, a.LinkID, a.Target, a.Action, a.SpecDigest}, "\x00") < strings.Join([]string{b.Level, b.ServiceID, b.CandidateID, b.ResourceID, b.LinkID, b.Target, b.Action, b.SpecDigest}, "\x00")
	})
	report.Observations, err = clientadapter.CurrentReportObservations(report.Observations, generation, report.ReportedAt)
	if err != nil {
		return control.DeviceReport{}, err
	}
	if runtime.State == "running" && runtime.AppliedViewDigest != state.LKG.ViewDigest {
		return control.DeviceReport{}, errors.New("running report is not the actual accepted configuration")
	}
	connected, _ := androidConnectedIPv4Prefixes(interfaceAddresses)
	report.LocalNetworks = clientadapter.UnderlayNetworkReport(connected)
	return control.SignDeviceReport(report, (&androidIdentity{state: state}).PrivateKey())
}

// Kotlin commits ReserveAndroidReportSequence before creating this call. Its
// cancellation burns that sequence; it never writes identity or retries a number.
func NewAndroidReportRequest(stateBody, preferenceBody, resourceBody, observationsBody, selectionsBody, runtimeBody, componentsBody, interfaceAddresses []byte, networkGeneration, reportedAt string) (*AndroidDeviceRequest, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	report, err := androidReport(state, preferenceBody, resourceBody, observationsBody, selectionsBody, runtimeBody, componentsBody, interfaceAddresses, networkGeneration, reportedAt)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 30*time.Second)
	return &AndroidDeviceRequest{ctx: ctx, cancel: cancel, run: func(ctx context.Context) ([]byte, error) {
		if report.Runtime.State == "running" && report.Runtime.AppliedViewDigest == report.ViewDigest {
			diagnostic, diagnosticErr := clientadapter.NativeDiagnosticContext(ctx, androidLocalRuntimeSecret(state), nil)
			if diagnosticErr == nil {
				report.WireGuardCounters, _ = clientadapter.ObserveWireGuardCounters(diagnostic, state.LKG.View, time.Now)
			}
		}
		identity := &androidIdentity{state: state}
		report.Observations, err = deviceclient.UnreportedObservations(report, identity.PublicKey())
		if err != nil {
			return nil, err
		}
		report, err = control.SignDeviceReport(report, identity.PrivateKey())
		if err != nil {
			return nil, err
		}
		return nil, deviceclient.PostSignedReport(ctx, identity, report)
	}}, nil
}

func androidComponentPlatform() string { return "android-" + runtime.GOARCH }

func serviceProbeTargets(view control.DeviceView) []control.ServiceProbeTargets {
	values := []control.ServiceProbeTargets{}
	for _, service := range view.Services {
		values = append(values, control.ServiceProbeTargets{ServiceID: service.ID, Targets: append([]string{}, service.ProbeURLs...)})
	}
	return values
}

func androidPreference(state deviceclient.State) clientmodel.Preference {
	if state.Preference == nil {
		return clientmodel.EmptyPreference()
	}
	return *state.Preference
}
