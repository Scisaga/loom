// Package clientmodel implements the I/O-free client runtime model shared by
// Android, Linux, and Windows. Platform adapters apply its choice and report readback;
// this package never performs network, clock, storage, or selector I/O.
package clientmodel

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"loom/internal/control"
)

type RouteCandidate struct {
	ID         string             `json:"id"`
	PolicyID   string             `json:"policy_id"`
	FinalExit  string             `json:"final_exit"`
	Chain      []string           `json:"chain"`
	Scope      string             `json:"scope"`
	FirstHop   *ResourceSampleRef `json:"first_hop,omitempty"`
	RelayLinks []LinkSampleRef    `json:"relay_links,omitempty"`
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

type ServicePreference = control.PolicyChoice

type Preference struct {
	Schema   int                 `json:"schema"`
	Services []ServicePreference `json:"services"`
}

func (preference Preference) Equal(other Preference) bool {
	return preference.Schema == other.Schema && slices.Equal(preference.Services, other.Services)
}

func (preference Preference) Policy(serviceID string) string {
	for _, choice := range preference.Services {
		if choice.ServiceID == serviceID {
			return choice.PolicyID
		}
	}
	return ""
}

type Selection struct {
	CandidateID string `json:"candidate_id"`
	Scope       string `json:"scope"`
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
		control.ValidateDigest(ref.SpecDigest) != nil || !validName(ref.Target) || ref.Action != "hysteria2_tls" && ref.Action != "wireguard_dns") {
		return errors.New("candidate first-hop evidence reference is invalid")
	}
	seenLinks := map[string]bool{}
	for _, ref := range candidate.RelayLinks {
		if control.ValidateID(ref.LinkID) != nil || control.ValidateID(ref.DeviceID) != nil || control.ValidateID(ref.ResourceID) != nil || control.ValidateDigest(ref.SpecDigest) != nil || !validName(ref.Target) || ref.Action != "wireguard_dns" || seenLinks[ref.LinkID] {
			return errors.New("candidate relay evidence reference is invalid")
		}
		seenLinks[ref.LinkID] = true
	}

	return nil
}

func (observation Observation) Validate() error {
	if !validName(observation.CandidateID) || !validName(observation.NetworkGeneration) ||
		!validName(observation.Scope) || !validName(observation.Action) || observation.MetricMillis < 0 ||
		observation.Target != "" && control.ValidateHTTPSURL(observation.Target) != nil {
		return errors.New("observation is incomplete")
	}
	switch observation.Result {
	case "available", "unavailable", "unknown":
	default:
		return errors.New("observation result is invalid")
	}
	observed, err := time.Parse(time.RFC3339, observation.ObservedAt)
	if err != nil || observation.ObservedAt != observed.UTC().Format(time.RFC3339) {
		return errors.New("observation time is not canonical")
	}
	until, err := time.Parse(time.RFC3339, observation.ValidUntil)
	if err != nil || observation.ValidUntil != until.UTC().Format(time.RFC3339) || !until.After(observed) {
		return errors.New("observation validity is invalid")
	}
	return nil
}

func (preference Preference) Validate() error {
	if preference.Schema != 3 {
		return errors.New("preference schema is invalid")
	}
	return control.ValidatePolicyChoices(preference.Services)
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
	if err := preference.Validate(); err != nil || !validName(networkGeneration) {
		return Selection{}, errors.New("selection input is invalid")
	}
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return Selection{}, err
		}
	}
	resourceByID := map[string]control.Observation{}
	localLinks := map[string]control.Observation{}
	for _, sample := range resources {
		if err := sample.Validate(); err != nil || sample.Level != "resource" && sample.Level != "link" {
			return Selection{}, errors.New("first-hop sample is invalid")
		}
		if sample.Level == "link" {
			if _, exists := localLinks[sample.LinkID]; exists {
				return Selection{}, errors.New("local relay samples are duplicated")
			}
			localLinks[sample.LinkID] = sample
			continue
		}
		if _, exists := resourceByID[sample.ResourceID]; exists {
			return Selection{}, errors.New("first-hop samples are duplicated")
		}
		resourceByID[sample.ResourceID] = sample
	}
	linkByID := map[string]control.DeviceLinkObservation{}
	for _, sample := range links {
		if sample.Validate() != nil {
			return Selection{}, errors.New("relay sample is invalid")
		}
		if _, found := linkByID[sample.Observation.LinkID]; found {
			return Selection{}, errors.New("relay samples are duplicated")
		}
		linkByID[sample.Observation.LinkID] = sample
	}
	byID := map[string]string{}
	failures := map[string]string{}
	metrics := map[string]int64{}
	hopAvailable := map[string]bool{}
	hopFailed := map[string]bool{}
	for _, candidate := range routes {
		state, failure, metric, err := candidateEvidence(observations, candidate.ID, candidate.Scope, networkGeneration, targets, now)
		if err != nil {
			return Selection{}, err
		}
		byID[candidate.ID], failures[candidate.ID], metrics[candidate.ID] = state, failure, metric
		consume := func(hop control.Observation, until int64, complete bool) error {
			if hop.ObservedAt > now.UnixMilli() {
				return nil
			}
			recovered, err := businessSucceededAfter(observations, candidate, networkGeneration, targets, hop.ObservedAt, now)
			if complete {
				recovered, err = businessCompleteSucceededAfter(observations, candidate, networkGeneration, targets, hop.ObservedAt, now)
			}
			if err != nil {
				return err
			}
			if hop.Result == "unavailable" && !recovered {
				hopFailed[candidate.ID] = hopFailed[candidate.ID] || now.UnixMilli() < until
				at := time.UnixMilli(hop.ObservedAt).UTC().Truncate(time.Second).Format(time.RFC3339)
				if at > failures[candidate.ID] {
					failures[candidate.ID] = at
				}
			}
			hopAvailable[candidate.ID] = hopAvailable[candidate.ID] || hop.Result == "available" && now.UnixMilli() < until
			return nil
		}
		if candidate.FirstHop != nil {
			hop, found := resourceByID[candidate.FirstHop.ResourceID]
			if found && matchesFirstHop(candidate.FirstHop, hop, networkGeneration) {
				if err := consume(hop, hop.ValidUntil, false); err != nil {
					return Selection{}, err
				}
			}
		}
		for _, ref := range candidate.RelayLinks {
			if hop, found := localLinks[ref.LinkID]; found && hop.NetworkGeneration == networkGeneration && hop.ResourceID == ref.ResourceID && hop.SpecDigest == ref.SpecDigest && hop.Target == ref.Target && hop.Action == ref.Action {
				if err := consume(hop, hop.ValidUntil, true); err != nil {
					return Selection{}, err
				}
				continue
			}
			sample, found := linkByID[ref.LinkID]
			hop := sample.Observation
			if !found || sample.DeviceID != ref.DeviceID || hop.ResourceID != ref.ResourceID || hop.SpecDigest != ref.SpecDigest || hop.Target != ref.Target || hop.Action != ref.Action {
				continue
			}
			if err := consume(hop, sample.CurrentUntil, true); err != nil {
				return Selection{}, err
			}
		}
	}
	eligible := make([]RouteCandidate, 0, len(routes))
	seen := map[string]bool{}
	for _, candidate := range routes {
		if err := candidate.Validate(); err != nil || seen[candidate.ID] {
			return Selection{}, errors.New("route candidates are invalid or duplicated")
		}
		seen[candidate.ID] = true
		_, serviceID, found := strings.Cut(candidate.Scope, ":")
		allowed := found && preference.Policy(serviceID) == candidate.PolicyID
		if !allowed || byID[candidate.ID] == "unavailable" || hopFailed[candidate.ID] {
			continue
		}
		eligible = append(eligible, candidate)
	}
	if len(eligible) == 0 {
		return Selection{}, ErrNoUsableCandidate
	}
	rank := func(candidate RouteCandidate) int {
		if byID[candidate.ID] == "available" {
			return 0
		}
		return 1
	}
	sort.Slice(eligible, func(i, j int) bool {
		left, right := eligible[i], eligible[j]
		leftRank, rightRank := rank(left), rank(right)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if leftRank == 1 && failures[left.ID] != failures[right.ID] {
			return failures[left.ID] < failures[right.ID]
		}
		if (left.ID == current) != (right.ID == current) {
			return left.ID == current
		}
		if leftRank == 1 && hopAvailable[left.ID] != hopAvailable[right.ID] {
			return hopAvailable[left.ID]
		}
		return left.ID < right.ID
	})
	selected := eligible[0]
	// Mixing pairwise metric comparisons with current/ID tie breakers creates
	// comparison cycles when a metric is missing. Establish the stable baseline
	// first, then replace it only with a strictly better comparable measurement.
	if len(targets) == 1 && rank(selected) == 0 && metrics[selected.ID] > 0 {
		for _, candidate := range eligible[1:] {
			if rank(candidate) == 0 && metrics[candidate.ID] > 0 && metrics[candidate.ID] < metrics[selected.ID] {
				selected = candidate
			}
		}
	}
	return Selection{CandidateID: selected.ID, Scope: selected.Scope}, nil
}

type runtimeDocument struct {
	Inbounds []struct {
		Type      string `json:"type"`
		Tag       string `json:"tag"`
		AutoRoute bool   `json:"auto_route"`
	} `json:"inbounds"`
	Outbounds []struct {
		Type      string   `json:"type"`
		Detour    string   `json:"detour"`
		Tag       string   `json:"tag"`
		Outbounds []string `json:"outbounds,omitempty"`
		Default   string   `json:"default"`
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

func (profile RuntimeProfile) Validate(routes []RouteCandidate) error {
	if profile.Kind != "sing_box" || profile.Config == "" {
		return errors.New("runtime profile is incomplete")
	}
	if err := (control.RuntimeProfile{Kind: profile.Kind, Config: profile.Config}).Validate(); err != nil {
		return err
	}
	var document runtimeDocument
	if err := json.Unmarshal([]byte(profile.Config), &document); err != nil {
		return err
	}
	// Host capture and local API authentication belong to the platform adapter.
	// The authenticated profile contains no platform listeners or local secret.
	if len(document.Inbounds) != 0 || document.Experimental.ClashAPI.ExternalController != "" || document.Experimental.ClashAPI.Secret != "" {
		return errors.New("authorization profile contains host execution inputs")
	}
	outboundType := map[string]string{}
	selectors := map[string][]string{}
	for _, outbound := range document.Outbounds {
		if !validName(outbound.Tag) || outboundType[outbound.Tag] != "" {
			return errors.New("runtime profile outbound tags are invalid")
		}
		outboundType[outbound.Tag] = outbound.Type
		if outbound.Type == "selector" {
			if len(outbound.Outbounds) == 0 || outbound.Default != "reject" {
				return errors.New("runtime profile selector is empty")
			}
			selectors[outbound.Tag] = append([]string(nil), outbound.Outbounds...)
		}
	}
	wanted := map[string]map[string]bool{}
	for _, route := range routes {
		if err := route.Validate(); err != nil || outboundType[route.ID] == "" || outboundType[route.ID] == "selector" {
			return errors.New("runtime profile does not contain an authorized candidate outbound")
		}
		if len(route.Chain) == 0 && outboundType[route.ID] != "direct" {
			return errors.New("direct route is not backed by a direct outbound")
		}
		if wanted[route.Scope] == nil {
			wanted[route.Scope] = map[string]bool{}
		}
		if wanted[route.Scope][route.ID] {
			return errors.New("runtime route mapping is duplicated")
		}
		wanted[route.Scope][route.ID] = true
	}
	for scope, members := range selectors {
		if !strings.HasPrefix(scope, "service:") && !strings.HasPrefix(scope, "local_network:") {
			return errors.New("runtime selector has no Service scope")
		}
		candidates := wanted[scope]
		if len(members) != len(candidates)+1 {
			return errors.New("runtime selector members do not match authorized candidates")
		}
		seen := map[string]bool{}
		for _, member := range members {
			if member != "reject" && !candidates[member] || seen[member] {
				return errors.New("runtime selector contains an unauthorized candidate")
			}
			seen[member] = true
		}
		if !seen["reject"] || outboundType["reject"] != "block" {
			return errors.New("runtime selector has no rejecting default")
		}
		delete(wanted, scope)
	}
	if len(wanted) != 0 {
		return errors.New("runtime selectors do not match authorized scopes")
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
	var document runtimeDocument
	if err := json.Unmarshal([]byte(profile.Config), &document); err != nil {
		return nil, err
	}
	transport := make(map[string]string, len(document.Outbounds))
	for _, outbound := range document.Outbounds {
		transport[outbound.Tag] = outbound.Type
	}
	for _, endpoint := range document.Endpoints {
		for _, outbound := range document.Outbounds {
			if outbound.Type == "direct" && outbound.Detour == endpoint.Tag && endpoint.Type == "wireguard" {
				transport[outbound.Tag] = "wireguard"
			}
		}
	}
	result := make([]RuntimeCandidate, 0, len(routes))
	for _, route := range routes {
		result = append(result, RuntimeCandidate{ID: route.ID, PolicyID: route.PolicyID, FinalExit: route.FinalExit,
			Chain: append([]string(nil), route.Chain...), Scope: route.Scope, Transport: transport[route.ID]})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Scope != result[j].Scope {
			return result[i].Scope < result[j].Scope
		}
		return result[i].ID < result[j].ID
	})
	return result, nil
}
