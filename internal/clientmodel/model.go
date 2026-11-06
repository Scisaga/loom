// Package clientmodel implements the I/O-free client runtime model shared by
// Android, Linux, and Windows. Platform adapters apply its choice and report readback;
// this package never performs network, clock, storage, or selector I/O.
package clientmodel

import (
	"encoding/json"
	"errors"
	"maps"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"loom/internal/control"
	"loom/protocol"
)

type RouteCandidate struct {
	Transport        string             `json:"transport"`
	GraphUnavailable bool               `json:"graph_unavailable,omitempty"`
	ID               string             `json:"id"`
	PolicyID         string             `json:"policy_id"`
	FixedExit        bool               `json:"fixed_exit"`
	SourceNode       string             `json:"source_node"`
	EntryNodeID      string             `json:"entry_node_id"`
	FirstResourceID  string             `json:"first_resource_id"`
	FinalExit        string             `json:"final_exit"`
	Chain            []string           `json:"chain"`
	Scope            string             `json:"scope"`
	FirstHop         *ResourceSampleRef `json:"first_hop,omitempty"`
	RelayLinks       []LinkSampleRef    `json:"relay_links,omitempty"`
}

// LinkSampleRef binds a projected relay segment to the original reporter.
type LinkSampleRef struct {
	LinkID     string `json:"link_id"`
	DeviceID   string `json:"device_id"`
	ResourceID string `json:"resource_id"`
	SpecDigest string `json:"spec_digest"`
	Target     string `json:"target"`
	Action     string `json:"action"`
}

// ResourceSampleRef is a public execution projection from the accepted View.
// It has no authority or storage of its own and never contains a credential.
type ResourceSampleRef struct {
	ResourceID string `json:"resource_id"`
	SpecDigest string `json:"spec_digest"`
	Target     string `json:"target"`
	Action     string `json:"action"`
}

type RuntimeProfile struct {
	Kind   string `json:"kind"`
	Config string `json:"config"`
}

// RuntimeCandidate is the deterministic executable projection of one
// authorized RouteCandidate through a certified RuntimeProfile. It contains no
// host state and is rebuilt rather than persisted.
type RuntimeCandidate struct {
	ID        string   `json:"id"`
	PolicyID  string   `json:"policy_id"`
	FinalExit string   `json:"final_exit"`
	Chain     []string `json:"chain"`
	Scope     string   `json:"scope"`
	Transport string   `json:"transport"`
}

type Observation struct {
	CandidateID       string `json:"candidate_id"`
	Target            string `json:"target,omitempty"`
	NetworkGeneration string `json:"network_generation"`
	Scope             string `json:"scope"`
	Result            string `json:"result"`
	Action            string `json:"action"`
	ObservedAt        string `json:"observed_at"`
	ValidUntil        string `json:"valid_until"`
	MetricMillis      int64  `json:"metric_millis,omitempty"`
}

type Preference struct {
	Schema       int               `json:"schema"`
	PolicyID     string            `json:"policy_id,omitempty"`
	LANPolicyIDs map[string]string `json:"lan_policy_ids,omitempty"`
}

func (preference Preference) Equal(other Preference) bool {
	return preference.Schema == other.Schema && preference.PolicyID == other.PolicyID && maps.Equal(preference.LANPolicyIDs, other.LANPolicyIDs)
}

type Selection struct {
	PolicyID    string                          `json:"policy_id"`
	Choices     map[string]protocol.RouteChoice `json:"choices"`
	Revision    string                          `json:"revision"`
	CandidateID string                          `json:"candidate_id"`
	Scope       string                          `json:"scope"`
	Targets     map[string]string               `json:"targets"`
}

func validName(value string) bool {
	return value != "" && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (candidate RouteCandidate) Validate() error {
	if !validName(candidate.ID) || control.ValidateID(candidate.PolicyID) != nil || !validName(candidate.FinalExit) || !validName(candidate.Scope) {
		return errors.New("route candidate is incomplete")
	}
	seen := map[string]bool{}
	for _, node := range candidate.Chain {
		if !validName(node) || seen[node] {
			return errors.New("route candidate chain is invalid")
		}
		seen[node] = true
	}
	if len(candidate.Chain) > 0 && candidate.Chain[len(candidate.Chain)-1] != candidate.FinalExit {
		return errors.New("route candidate final exit does not match its chain")
	}
	if strings.HasPrefix(candidate.Scope, "local_network:") && (candidate.Scope == "local_network:" || candidate.FinalExit == "direct") {
		return errors.New("local network candidate requires its fixed gateway")
	}
	if ref := candidate.FirstHop; ref != nil && (len(candidate.Chain) == 0 || control.ValidateID(ref.ResourceID) != nil ||
		control.ValidateDigest(ref.SpecDigest) != nil || !validName(ref.Target) || ref.Action != "hysteria2_echo" && ref.Action != "wireguard_echo") {
		return errors.New("candidate first-hop evidence reference is invalid")
	}
	seenLinks := map[string]bool{}
	for _, ref := range candidate.RelayLinks {
		if control.ValidateID(ref.LinkID) != nil || control.ValidateID(ref.DeviceID) != nil || control.ValidateID(ref.ResourceID) != nil || control.ValidateDigest(ref.SpecDigest) != nil || !validName(ref.Target) || ref.Action != "wireguard_echo" && ref.Action != "hysteria2_echo" || seenLinks[ref.LinkID] {
			return errors.New("candidate relay evidence reference is invalid")
		}
		seenLinks[ref.LinkID] = true
	}

	return nil
}

func (observation Observation) Validate() error {
	if !validName(observation.CandidateID) || !validName(observation.NetworkGeneration) ||
		!validName(observation.Scope) || !validName(observation.Action) || observation.MetricMillis < 0 {
		return errors.New("observation is incomplete")
	}
	native := observation.Action == "tcp_connect" || observation.Action == "tcp_calibration"
	if native {
		if observation.Scope != control.AccessSelectorScope || control.ValidateConnectionTarget(observation.Target) != nil {
			return errors.New("invalid native TCP observation")
		}
	} else if observation.Target != "" && control.ValidateHTTPSURL(observation.Target) != nil {
		return errors.New("invalid business observation target")
	}
	switch observation.Result {
	case "available", "unavailable", "unknown":
	default:
		return errors.New("observation result is invalid")
	}
	observed, err := time.Parse(time.RFC3339, observation.ObservedAt)
	format := time.RFC3339
	if native {
		format = time.RFC3339Nano
	}
	if err != nil || observation.ObservedAt != observed.UTC().Format(format) || native && (!observed.Equal(observed.Truncate(time.Millisecond)) || observed.UnixMilli() <= observation.MetricMillis) {
		return errors.New("observation time is not canonical")
	}
	until, err := time.Parse(time.RFC3339, observation.ValidUntil)
	if err != nil || observation.ValidUntil != until.UTC().Format(format) || !until.After(observed) || native && !until.Equal(until.Truncate(time.Millisecond)) {
		return errors.New("observation validity is invalid")
	}
	return nil
}

func (preference Preference) Validate() error {
	if preference.Schema != 3 {
		return errors.New("preference schema is invalid")
	}
	if preference.PolicyID != "" && control.ValidateID(preference.PolicyID) != nil {
		return errors.New("invalid Internet Policy choice")
	}
	if preference.LANPolicyIDs != nil && len(preference.LANPolicyIDs) == 0 {
		return errors.New("empty LAN choices must be omitted")
	}
	for service, policy := range preference.LANPolicyIDs {
		if control.ValidateID(service) != nil || control.ValidateID(policy) != nil {
			return errors.New("invalid LAN Policy choice")
		}
	}
	return nil
}
func (preference Preference) Clone() Preference {
	preference.LANPolicyIDs = maps.Clone(preference.LANPolicyIDs)
	return preference
}
func ValidSelectorScope(scope string) bool {
	return scope == control.AccessSelectorScope || strings.HasPrefix(scope, "local_network:") && control.ValidateID(strings.TrimPrefix(scope, "local_network:")) == nil
}
func (preference Preference) PolicyForScope(scope string) string {
	if scope == control.AccessSelectorScope {
		return preference.PolicyID
	}
	return preference.LANPolicyIDs[strings.TrimPrefix(scope, "local_network:")]
}
func CandidateSelectorScope(candidate RouteCandidate) string {
	if strings.HasPrefix(candidate.Scope, "local_network:") {
		return candidate.Scope
	}
	return control.AccessSelectorScope
}

// ErrNoUsableCandidate distinguishes a current selection limit from invalid
// inputs or a failed runtime operation. It does not revoke authorization.
var ErrNoUsableCandidate = errors.New("no authorized route candidate is usable")

// Select returns one candidate for one selector scope. Missing, expired, and
// other-generation observations remain unknown. Known unavailable candidates
// are excluded; a current candidate is retained when evidence does not prove a
// strictly better comparable result.
func Select(routes []RouteCandidate, observations []Observation, resources []control.Observation, preference Preference, current,
	networkGeneration string, now time.Time, targets ...string) (Selection, error) {
	return SelectWithLinks(routes, observations, resources, nil, preference, current, networkGeneration, now, targets...)
}

// SelectWithLinks consumes TLS-authenticated scoped remote report projections;
// remote network generations belong to their source, never the local underlay.
func SelectWithLinks(routes []RouteCandidate, observations []Observation, resources []control.Observation, links []control.DeviceLinkObservation, preference Preference, current,
	networkGeneration string, now time.Time, targets ...string) (Selection, error) {
	evaluation, err := evaluateRouting(routes, observations, resources, links, preference, current, networkGeneration, now, targets)
	if err != nil {
		return Selection{}, err
	}
	return evaluation.selection, nil
}

type runtimeExecutionSource struct {
	PolicyID    string `json:"policy_id"`
	OriginID    string `json:"origin_id,omitempty"`
	FinalExitID string `json:"final_exit_id,omitempty"`
	LocalNodeID string `json:"local_node_id,omitempty"`
}
type runtimeHop struct {
	Policy      protocol.HopPolicy  `json:"policy"`
	NodeID      string              `json:"node_id"`
	Nodes       map[string]string   `json:"nodes"`
	ExitChoices map[string][]string `json:"exit_choices"`
}
type runtimeDocument struct {
	Inbounds []struct {
		Type      string `json:"type"`
		Tag       string `json:"tag"`
		AutoRoute bool   `json:"auto_route"`
	} `json:"inbounds"`
	Outbounds []struct {
		Type              string                  `json:"type"`
		Hop               *runtimeHop             `json:"hop,omitempty"`
		ExecutionSource   *runtimeExecutionSource `json:"execution_source,omitempty"`
		CandidatePolicies *map[string]string      `json:"candidate_policies,omitempty"`
		Detour            string                  `json:"detour"`
		Tag               string                  `json:"tag"`
		Outbounds         []string                `json:"outbounds,omitempty"`
		Default           string                  `json:"default"`
	} `json:"outbounds"`
	Endpoints []struct {
		Type string `json:"type"`
		Tag  string `json:"tag"`
	} `json:"endpoints"`
	Experimental struct {
		ClashAPI struct {
			ExternalController string `json:"external_controller"`
			Secret             string `json:"secret"`
		} `json:"clash_api"`
	} `json:"experimental"`
}

// Validate checks this disposable projection's shape. Authorization is
// checked by DeviceView and again by the native selector/receiving transport.
// Candidate IDs are choices over shared transports, never outbound tags.
func (profile RuntimeProfile) Validate(routes []RouteCandidate) error {
	if err := (control.RuntimeProfile{Kind: profile.Kind, Config: profile.Config}).Validate(); err != nil {
		return err
	}
	var document runtimeDocument
	if err := json.Unmarshal([]byte(profile.Config), &document); err != nil {
		return err
	}
	if len(document.Inbounds) != 0 || document.Experimental.ClashAPI.ExternalController != "" || document.Experimental.ClashAPI.Secret != "" {
		return errors.New("projection contains host inputs")
	}
	seen := map[string]bool{}
	for _, route := range routes {
		if route.Validate() != nil || seen[route.ID] {
			return errors.New("invalid candidate projection")
		}
		seen[route.ID] = true
	}
	return nil
}

// ProjectRuntimeCandidates validates the complete route/profile mapping and
// returns a stable, I/O-free projection. Platform adapters may add ephemeral
// process handles, but must not change these identities or route semantics.
func ProjectRuntimeCandidates(routes []RouteCandidate, profile RuntimeProfile) ([]RuntimeCandidate, error) {
	if err := profile.Validate(routes); err != nil {
		return nil, err
	}
	result := make([]RuntimeCandidate, 0, len(routes))
	for _, route := range routes {
		result = append(result, RuntimeCandidate{ID: route.ID, PolicyID: route.PolicyID, FinalExit: route.FinalExit,
			Chain: append([]string(nil), route.Chain...), Scope: route.Scope, Transport: route.Transport})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Scope != result[j].Scope {
			return result[i].Scope < result[j].Scope
		}
		return result[i].ID < result[j].ID
	})
	return result, nil
}
