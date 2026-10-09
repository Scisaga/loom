// Package clientmodel implements the I/O-free client runtime model shared by
// Android, Linux, and Windows. Platform adapters apply its choice and report readback;
// this package never performs network, clock, storage, or selector I/O.
package clientmodel

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"loom/internal/control"
)

const (
	ModeDirect Mode = "direct"
	ModeAuto   Mode = "auto"
	ModeFixed  Mode = "fixed_exit"
)

type Mode string

type RouteCandidate struct {
	ID        string   `json:"id"`
	FinalExit string   `json:"final_exit"`
	Chain     []string `json:"chain"`
	Scope     string   `json:"scope"`
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
	Schema int    `json:"schema"`
	Mode   Mode   `json:"mode"`
	Exit   string `json:"exit,omitempty"`
}

type Selection struct {
	CandidateID string `json:"candidate_id"`
	Scope       string `json:"scope"`
}

func validName(value string) bool {
	return value != "" && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (candidate RouteCandidate) Validate() error {
	if !validName(candidate.ID) || !validName(candidate.FinalExit) || !validName(candidate.Scope) {
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
	switch preference.Mode {
	case ModeDirect, ModeAuto:
		if preference.Exit != "" {
			return errors.New("direct and auto preferences cannot name an exit")
		}
	case ModeFixed:
		if !validName(preference.Exit) || preference.Exit == "direct" || preference.Exit == "auto" {
			return errors.New("fixed preference exit is invalid")
		}
	default:
		return errors.New("preference mode is invalid")
	}
	return nil
}

// ErrNoUsableCandidate distinguishes a current selection limit from invalid
// inputs or a failed runtime operation. It does not revoke authorization.
var ErrNoUsableCandidate = errors.New("no authorized route candidate is usable")

// Select returns one candidate for one selector scope. Missing, expired, and
// other-generation observations remain unknown. Known unavailable candidates
// are excluded; a current candidate is retained when evidence does not prove a
// strictly better comparable result.
func Select(routes []RouteCandidate, observations []Observation, preference Preference, current,
	networkGeneration string, now time.Time, targets ...string) (Selection, error) {
	if err := preference.Validate(); err != nil || !validName(networkGeneration) {
		return Selection{}, errors.New("selection input is invalid")
	}
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return Selection{}, err
		}
	}
	byID := map[string]string{}
	failures := map[string]string{}
	metrics := map[string]int64{}
	for _, candidate := range routes {
		state, failure, metric, err := candidateEvidence(observations, candidate.ID, candidate.Scope, networkGeneration, targets, now)
		if err != nil {
			return Selection{}, err
		}
		byID[candidate.ID], failures[candidate.ID], metrics[candidate.ID] = state, failure, metric
	}
	eligible := make([]RouteCandidate, 0, len(routes))
	seen := map[string]bool{}
	for _, candidate := range routes {
		if err := candidate.Validate(); err != nil || seen[candidate.ID] {
			return Selection{}, errors.New("route candidates are invalid or duplicated")
		}
		seen[candidate.ID] = true
		allowed := strings.HasPrefix(candidate.Scope, "local_network:") || preference.Mode == ModeAuto ||
			preference.Mode == ModeDirect && candidate.FinalExit == "direct" ||
			preference.Mode == ModeFixed && candidate.FinalExit == preference.Exit
		if !allowed || byID[candidate.ID] == "unavailable" {
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
			if len(outbound.Outbounds) == 0 {
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
	if len(selectors) != len(wanted) {
		return errors.New("runtime selectors do not match authorized scopes")
	}
	for scope, candidates := range wanted {
		members, found := selectors[scope]
		if !found || len(members) != len(candidates) {
			return errors.New("runtime selector members do not match authorized candidates")
		}
		seen := map[string]bool{}
		for _, member := range members {
			if !candidates[member] || seen[member] {
				return errors.New("runtime selector contains an unauthorized candidate")
			}
			seen[member] = true
		}
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
		result = append(result, RuntimeCandidate{ID: route.ID, FinalExit: route.FinalExit,
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
