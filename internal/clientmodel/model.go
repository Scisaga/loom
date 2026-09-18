// Package clientmodel implements the I/O-free client runtime model shared by
// Android and Linux. Platform adapters apply its choice and report readback;
// this package never performs network, clock, storage, or selector I/O.
package clientmodel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	ModeDirect = "direct"
	ModeAuto   = "auto"
	ModeFixed  = "fixed_exit"
)

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

type Observation struct {
	CandidateID       string `json:"candidate_id"`
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
	Mode   string `json:"mode"`
	Exit   string `json:"exit,omitempty"`
}

type Selection struct {
	CandidateID string `json:"candidate_id"`
	Scope       string `json:"scope"`
}

func validName(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsControl) < 0
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
	if len(candidate.Chain) == 0 && candidate.FinalExit != "direct" {
		return errors.New("empty route candidate chain must be Direct")
	}
	return nil
}

func (observation Observation) Validate() error {
	if !validName(observation.CandidateID) || !validName(observation.NetworkGeneration) ||
		!validName(observation.Scope) || !validName(observation.Action) || observation.MetricMillis < 0 {
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
	if preference.Schema != 1 {
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

// Select returns one candidate for one selector scope. Missing, expired, and
// other-generation observations remain unknown. Known unavailable candidates
// are excluded; a current candidate is retained when evidence does not prove a
// strictly better comparable result.
func Select(routes []RouteCandidate, observations []Observation, preference Preference, current,
	networkGeneration string, now time.Time) (Selection, error) {
	if err := preference.Validate(); err != nil || !validName(networkGeneration) {
		return Selection{}, errors.New("selection input is invalid")
	}
	byID := map[string]Observation{}
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return Selection{}, err
		}
		if observation.NetworkGeneration != networkGeneration {
			continue
		}
		until, _ := time.Parse(time.RFC3339, observation.ValidUntil)
		if !now.Before(until) {
			continue
		}
		previous, found := byID[observation.CandidateID]
		if !found || previous.ObservedAt < observation.ObservedAt {
			byID[observation.CandidateID] = observation
		}
	}
	eligible := make([]RouteCandidate, 0, len(routes))
	seen := map[string]bool{}
	for _, candidate := range routes {
		if err := candidate.Validate(); err != nil || seen[candidate.ID] {
			return Selection{}, errors.New("route candidates are invalid or duplicated")
		}
		seen[candidate.ID] = true
		allowed := preference.Mode == ModeAuto ||
			preference.Mode == ModeDirect && len(candidate.Chain) == 0 ||
			preference.Mode == ModeFixed && candidate.FinalExit == preference.Exit
		if !allowed || byID[candidate.ID].Result == "unavailable" {
			continue
		}
		eligible = append(eligible, candidate)
	}
	if len(eligible) == 0 {
		return Selection{}, errors.New("no authorized route candidate is usable")
	}
	rank := func(candidate RouteCandidate) int {
		if byID[candidate.ID].Result == "available" {
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
		leftObservation, rightObservation := byID[left.ID], byID[right.ID]
		comparable := leftRank == 0 && leftObservation.Scope == rightObservation.Scope &&
			leftObservation.Action == rightObservation.Action && leftObservation.MetricMillis > 0 &&
			rightObservation.MetricMillis > 0
		if comparable && leftObservation.MetricMillis != rightObservation.MetricMillis {
			return leftObservation.MetricMillis < rightObservation.MetricMillis
		}
		if left.ID == current {
			return true
		}
		if right.ID == current {
			return false
		}
		return left.ID < right.ID
	})
	return Selection{CandidateID: eligible[0].ID, Scope: eligible[0].Scope}, nil
}

type runtimeDocument struct {
	Inbounds []struct {
		Type      string `json:"type"`
		Tag       string `json:"tag"`
		AutoRoute bool   `json:"auto_route"`
	} `json:"inbounds"`
	Outbounds []struct {
		Type      string   `json:"type"`
		Tag       string   `json:"tag"`
		Outbounds []string `json:"outbounds,omitempty"`
	} `json:"outbounds"`
	Experimental struct {
		ClashAPI struct {
			ExternalController string `json:"external_controller"`
			Secret             string `json:"secret"`
		} `json:"clash_api"`
	} `json:"experimental"`
}

// CanonicalizeRuntimeConfig rejects duplicate/trailing JSON and returns the
// unique compact representation stored inside a certified DeviceView.
func CanonicalizeRuntimeConfig(body []byte) (string, error) {
	if len(body) == 0 || len(body) > 4<<20 {
		return "", errors.New("runtime config exceeds boundary")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("runtime config has trailing content")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	// Decode through the typed boundary too; duplicate keys are rejected by
	// comparing each object key while walking the original input.
	if err := rejectDuplicateKeys(body); err != nil {
		return "", err
	}
	return string(canonical), nil
}

func rejectDuplicateKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("runtime config has duplicate object key")
				}
				seen[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
	}
	return walk()
}

func (profile RuntimeProfile) Validate(routes []RouteCandidate) error {
	if profile.Kind != "sing_box" || profile.Config == "" {
		return errors.New("runtime profile is incomplete")
	}
	canonical, err := CanonicalizeRuntimeConfig([]byte(profile.Config))
	if err != nil || canonical != profile.Config {
		return errors.New("runtime profile config is not canonical")
	}
	var document runtimeDocument
	if err := json.Unmarshal([]byte(profile.Config), &document); err != nil {
		return err
	}
	tun := 0
	for _, inbound := range document.Inbounds {
		if inbound.Type == "tun" {
			tun++
			if inbound.Tag != "tun-in" || !inbound.AutoRoute {
				return errors.New("runtime profile TUN contract is invalid")
			}
		}
	}
	if tun != 1 || document.Experimental.ClashAPI.ExternalController != "127.0.0.1:61800" ||
		!validName(document.Experimental.ClashAPI.Secret) {
		return errors.New("runtime profile host control is invalid")
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
	if len(wanted) == 0 || len(selectors) != len(wanted) {
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
