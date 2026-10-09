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

// This is a disposable Android host projection, never a second authority wire.
type androidProfile struct {
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
}

func decodeState(body []byte) (deviceclient.State, error) {
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
	value := invite.Material.Payload.(control.Invite)
	if len(value.Responsibilities) != 1 || value.Responsibilities[0] != "access" {
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
	state, err := deviceclient.NewIdentityState(invite, "android", private, hex.EncodeToString(request))
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
	}{PossiblePermissionRestoration: deviceclient.PossiblePermissionRestoration(state), Schema: 3, TransactionID: state.Invite.Material.Payload.(control.Invite).ID, Claimed: state.LKG != nil, Ready: state.LKG != nil, FactFrontier: []control.FactFrontier{}}
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
	connected, _ := androidConnectedIPv4Prefixes(interfaceAddresses, state.LKG.View.Resources...)
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
	routes, _, err := clientadapter.AccessProjection(view)
	if err != nil {
		return nil, err
	}
	// A local management secret is not a Service credential and never travels
	// in DeviceView. It has a separate purpose and is bound to this device key.
	config, err := androidRuntimeConfig(view, androidLocalRuntimeSecret(state), websites...)
	if err != nil {
		return nil, err
	}
	return json.Marshal(androidProfile{PossiblePermissionRestoration: deviceclient.PossiblePermissionRestoration(state), HasWebsite: len(view.WebEndpoints) > 0, Schema: 3, NodeID: view.DeviceID, Name: view.Name, ViewDigest: state.LKG.ViewDigest, FactFrontier: state.LKG.FactFrontier, Config: config, Routes: routes, RecordID: state.LKG.ViewDigest, DNS: append([]string{}, view.DNSServers...), BusinessProbeTargets: append([]control.ServiceProbeTargets{}, view.BusinessProbeTargets...)})
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
	document["inbounds"] = []any{map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"192.0.2.1/30", "2001:db8::1/126"}, "mtu": 1500, "auto_route": true, "stack": "system", "route_exclude_address": prefixes}}
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
	return clientadapter.WithNativeProbe(captured, secret)
}

// The temporary adapter has no storage and performs no execution. Kotlin owns
// the one protected identity record and commits the returned value before use.
type androidIdentity struct{ state deviceclient.State }

func (store *androidIdentity) Invite() control.BootstrapInvite { return store.state.Invite }
func (store *androidIdentity) Platform() string                { return store.state.Platform }
func (store *androidIdentity) PublicKey() string               { return store.state.PublicKey }
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
func AdvanceAndroidEnrollment(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	store := &androidIdentity{state: state}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 30*time.Second)
	defer cancel()
	if state.LKG == nil {
		_, err = deviceclient.Claim(ctx, store)
	} else {
		_, err = deviceclient.Resume(ctx, store)
	}
	if err != nil {
		return nil, err
	}
	return deviceclient.EncodeIdentityState(store.state)
}
func SyncAndroidDevice(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	store := &androidIdentity{state: state}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 30*time.Second)
	defer cancel()
	if _, err := deviceclient.Sync(ctx, store); err != nil {
		return nil, err
	}
	return deviceclient.EncodeIdentityState(store.state)
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
	Scope       string `json:"scope"`
	CandidateID string `json:"candidate_id"`
}

func androidReport(state deviceclient.State, preferenceBody, resourceBody, observationsBody, selectionsBody, runtimeBody, componentsBody, interfaceAddresses []byte, generation, reportedAt string) (control.DeviceReport, error) {
	if state.LKG == nil || state.ReportSequence == 0 {
		return control.DeviceReport{}, errors.New("Android report sequence has not been reserved")
	}
	preference := clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}
	if len(preferenceBody) > 0 {
		if err := control.DecodeCanonical(preferenceBody, &preference, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 1024}); err != nil {
			return control.DeviceReport{}, err
		}
	}
	reportedPreference, err := clientadapter.ReportedPreference(state.LKG.View, preference)
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
	for _, component := range components {
		if (component.ComponentID != "agent" && component.ComponentID != "sing-box") || component.Platform != androidComponentPlatform() {
			return control.DeviceReport{}, errors.New("Android component is outside the executing platform")
		}
	}
	now, err := time.Parse(time.RFC3339, reportedAt)
	if err != nil || now.UTC().Format(time.RFC3339) != reportedAt {
		return control.DeviceReport{}, errors.New("Android report time is not canonical")
	}
	report := control.DeviceReport{Schema: 3, NetworkID: state.Invite.NetworkID, DeviceID: state.LKG.View.DeviceID, ReportSequence: state.ReportSequence, ViewDigest: state.LKG.ViewDigest, NetworkGeneration: generation, ReportedAt: now.UnixMilli(), Preference: reportedPreference, Selections: []control.ReportSelection{}, Observations: []control.Observation{}, Runtime: runtime, Components: components}
	if len(resourceBody) > 0 {
		if runtime.State != "running" || runtime.AppliedViewDigest != state.LKG.ViewDigest {
			return control.DeviceReport{}, errors.New("resource samples require the actual accepted Android runtime")
		}
		values, err := clientadapter.DecodeResourceObservations(resourceBody, *state.LKG, generation)
		if err != nil {
			return control.DeviceReport{}, err
		}
		for _, value := range values {
			if value.ObservedAt <= report.ReportedAt && report.ReportedAt < value.ValidUntil {
				report.Observations = append(report.Observations, value)
			}
		}
	}
	routes := map[string]control.RouteCandidate{}
	targets := map[string]map[string]bool{}
	for _, route := range state.LKG.View.Routes {
		routes[route.ID] = route
	}
	for _, group := range state.LKG.View.BusinessProbeTargets {
		targets[group.ServiceID] = map[string]bool{}
		for _, target := range group.Targets {
			targets[group.ServiceID][target] = true
		}
	}
	for _, selection := range selections {
		route, ok := routes[selection.CandidateID]
		if !ok || route.Scope != selection.Scope {
			return control.DeviceReport{}, errors.New("reported selector is not authorized")
		}
		report.Selections = append(report.Selections, control.ReportSelection{ServiceID: route.ServiceID, CandidateID: route.ID})
	}
	sort.Slice(report.Selections, func(i, j int) bool { return report.Selections[i].ServiceID < report.Selections[j].ServiceID })
	for _, observation := range observations {
		route, ok := routes[observation.CandidateID]
		if !ok || route.Scope != observation.Scope || !targets[route.ServiceID][observation.Target] || observation.Action != "https_request" || observation.NetworkGeneration != generation {
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
	if runtime.State == "running" && runtime.AppliedViewDigest != state.LKG.ViewDigest {
		return control.DeviceReport{}, errors.New("running report is not the actual accepted configuration")
	}
	connected, _ := androidConnectedIPv4Prefixes(interfaceAddresses, state.LKG.View.Resources...)
	report.LocalNetworks = clientadapter.UnderlayNetworkReport(connected)
	return control.SignDeviceReport(report, (&androidIdentity{state: state}).PrivateKey())
}

// Kotlin commits ReserveAndroidReportSequence before invoking this function.
func PostAndroidDeviceReport(stateBody, preferenceBody, resourceBody, observationsBody, selectionsBody, runtimeBody, componentsBody, interfaceAddresses []byte, networkGeneration, reportedAt string) error {
	state, err := decodeState(stateBody)
	if err != nil {
		return err
	}
	report, err := androidReport(state, preferenceBody, resourceBody, observationsBody, selectionsBody, runtimeBody, componentsBody, interfaceAddresses, networkGeneration, reportedAt)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 30*time.Second)
	defer cancel()
	return deviceclient.PostSignedReport(ctx, &androidIdentity{state: state}, report)
}

func androidComponentPlatform() string { return "android-" + runtime.GOARCH }
