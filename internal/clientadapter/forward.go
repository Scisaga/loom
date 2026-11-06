package clientadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	P "loom/protocol"
)

type forwardProjection struct {
	Tag    string
	Policy P.HopPolicy
	Node   string
	Nodes  map[string]forwardNextHop
}

type forwardNextHop struct {
	NodeID, ResourceID string
}

// Performance work only applies where this node can continue a Policy path.
// Retained facilities do not grant this position or replace per-connection checks.
func forwardingPositionAllowed(node string, policy control.NetworkPolicy) bool {
	return policy.Action == "allow" && (policy.EntryScope.Allows(node) || policy.RelayScope.Allows(node))
}

// ForwardMeasurementLinks reuses the applied forwarding memory. Only own
// outgoing links within the same Policy and final-exit scope can be promoted.
func ForwardMeasurementLinks(view control.DeviceExecution, memory map[string]clientmodel.SelectionMemory, generation string) ([]string, error) {
	if !slices.Contains(view.Responsibilities, "forward") || len(memory) == 0 {
		return nil, nil
	}
	policies := map[string]control.NetworkPolicy{}
	for _, policy := range view.Policies {
		if forwardingPositionAllowed(view.DeviceID, policy) {
			policies[policy.ID] = policy
		}
	}
	exits := map[string]map[string]bool{}
	for _, value := range view.PolicyExits {
		exits[value.PolicyID] = map[string]bool{}
		for _, id := range value.NodeIDs {
			exits[value.PolicyID][id] = true
		}
	}
	byTag := map[string]control.NetworkLink{}
	for _, link := range view.Links {
		if link.FromNodeID != view.DeviceID {
			continue
		}
		tag, err := control.ForwardSegmentTag(link.ResourceID)
		if err != nil {
			return nil, err
		}
		byTag[tag] = link
	}
	ids := map[string]bool{}
	for key, value := range memory {
		scope, exit, ok := strings.Cut(key, "\x00")
		policy, allowed := policies[value.PolicyID]
		if !ok || !allowed || scope != control.ForwardSelectorTag(policy.ID) || !exits[policy.ID][exit] {
			continue
		}
		current := clientmodel.Selection{Scope: scope, PolicyID: policy.ID, CandidateID: value.Decisions[""].Current, Targets: map[string]string{}}
		if value.NetworkGeneration != generation {
			continue
		}
		for _, tag := range clientmodel.MeasurementCandidates(current, value, generation) {
			if link, found := byTag[tag]; found && (link.ToNodeID == exit || policy.RelayScope.Allows(link.ToNodeID)) {
				ids[link.ID] = true
			}
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

func forwardProjections(view control.DeviceView) ([]forwardProjection, error) {
	execution, err := control.ProjectDeviceCandidates(view, nil)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(view.Responsibilities, "forward") {
		return nil, nil
	}
	values := []forwardProjection{}
	for _, policy := range execution.Policies {
		if policy.Action != "allow" {
			continue
		}
		hop, err := control.HopPolicyProjection(execution, policy)
		if err != nil {
			return nil, err
		}
		hop.Origins = []string{}
		hop.EntryScope = P.PolicyScope{Mode: "any", NodeIDs: []string{}}
		nodes := map[string]forwardNextHop{}
		for _, link := range control.ForwardingLinks(execution, policy) {
			tag, err := control.ForwardSegmentTag(link.ResourceID)
			if err != nil {
				return nil, err
			}
			nodes[tag] = forwardNextHop{NodeID: link.ToNodeID, ResourceID: link.ResourceID}
		}
		values = append(values, forwardProjection{control.ForwardSelectorTag(policy.ID), hop, view.DeviceID, nodes})
	}
	return values, nil
}

type forwardReadback struct {
	Revision string              `json:"revision"`
	Choices  map[string][]string `json:"exit_choices"`
}

func decodeForwardReadback(body []byte) (forwardReadback, error) {
	var value forwardReadback
	if json.Unmarshal(body, &value) != nil || !validSnapshotRevision(value.Revision) || value.Choices == nil {
		return value, errors.New("incomplete forwarding readback")
	}
	for exit, choices := range value.Choices {
		if control.ValidateID(exit) != nil || choices == nil {
			return value, errors.New("invalid forwarding exit readback")
		}
		seen := map[string]bool{}
		for _, id := range choices {
			if id == "" || len(id) > 128 || seen[id] {
				return value, errors.New("invalid forwarding choice readback")
			}
			seen[id] = true
		}
	}
	return value, nil
}
func (selector *HTTPSelector) readForward(ctx context.Context, scope string) (forwardReadback, error) {
	body, err := selector.request(ctx, http.MethodGet, "/proxies/"+url.PathEscape(scope), nil)
	if err != nil {
		return forwardReadback{}, err
	}
	return decodeForwardReadback(body)
}
func (selector *HTTPSelector) applyForward(ctx context.Context, scope string, before forwardReadback, choices map[string][]string) (forwardReadback, error) {
	body, err := json.Marshal(map[string]any{"exit_choices": choices, "expected_exit_choices": before.Choices, "expected_revision": before.Revision})
	if err != nil {
		return forwardReadback{}, err
	}
	body, err = selector.request(ctx, http.MethodPut, "/proxies/"+url.PathEscape(scope), body)
	if err != nil {
		return forwardReadback{}, err
	}
	applied, err := decodeForwardReadback(body)
	if err != nil {
		return forwardReadback{}, err
	}
	if applied.Revision == before.Revision || !reflect.DeepEqual(applied.Choices, choices) {
		return forwardReadback{}, ErrSelectionSuperseded
	}
	current, err := selector.readForward(ctx, scope)
	if err != nil {
		return forwardReadback{}, err
	}
	if current.Revision != applied.Revision || !reflect.DeepEqual(current.Choices, applied.Choices) {
		return forwardReadback{}, ErrSelectionSuperseded
	}
	return applied, nil
}

// OptimizeForwarding returns memory only after complete own-operation readback.
// It stores no recommendations or measurements in the signed authorization.
func (selector *HTTPSelector) OptimizeForwarding(ctx context.Context, view control.DeviceView, local []control.Observation, shared []control.DeviceLinkObservation, generation string, now time.Time, memory map[string]clientmodel.SelectionMemory) (map[string]clientmodel.SelectionMemory, error) {
	projections, err := forwardProjections(view)
	if err != nil {
		return memory, err
	}
	applicable := map[string]bool{}
	for _, policy := range view.Policies {
		if forwardingPositionAllowed(view.DeviceID, policy) {
			applicable[policy.ID] = true
		}
	}
	active := projections[:0]
	for _, projection := range projections {
		if applicable[projection.Policy.PolicyID] {
			active = append(active, projection)
		}
	}
	projections = active
	policies := make([]string, 0, len(projections))
	for _, projection := range projections {
		policies = append(policies, projection.Policy.PolicyID)
	}
	graphs, err := PolicyGraphs(view, policies)
	if err != nil {
		return memory, err
	}
	routes := []clientmodel.RouteCandidate{}
	for _, p := range projections {
		for _, exit := range p.Policy.Exits {
			for tag, hop := range p.Nodes {
				node := hop.NodeID
				if exit == p.Node || node != exit && !p.Policy.RelayScope.Allows(node) {
					continue
				}
				chain := []string{node}
				if node != exit {
					chain = append(chain, exit)
				}
				routes = append(routes, clientmodel.RouteCandidate{ID: tag, PolicyID: p.Policy.PolicyID, FixedExit: true, SourceNode: p.Node, FirstResourceID: hop.ResourceID, FinalExit: exit, Chain: chain, Scope: p.Tag})
			}
		}
	}
	// Matching graph constraints and final exits share reverse-search results.
	routes, err = clientmodel.ForwardRoutePaths(routes, graphs, local, shared, generation, now)
	if err != nil {
		return memory, err
	}
	grouped := map[string][]clientmodel.RouteCandidate{}
	for _, route := range routes {
		key := route.Scope + "\x00" + route.FinalExit
		grouped[key] = append(grouped[key], route)
	}
	for key := range grouped {
		slices.SortFunc(grouped[key], func(a, b clientmodel.RouteCandidate) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
	}
	nextMemory := map[string]clientmodel.SelectionMemory{}
	for key, value := range memory {
		nextMemory[key] = value
	}
	clock := selector.ElapsedMillis()
	for _, p := range projections {
		before, err := selector.readForward(ctx, p.Tag)
		if err != nil {
			return memory, err
		}
		if len(before.Choices) != len(p.Policy.Exits) {
			return memory, errors.New("forwarding readback has another authorized exit set")
		}
		desired := map[string][]string{}
		planned := map[string]clientmodel.SelectionMemory{}
		for _, exit := range p.Policy.Exits {
			choices, exists := before.Choices[exit]
			if !exists {
				return memory, errors.New("forwarding readback omits an authorized exit")
			}
			actual := "reject"
			if len(choices) > 0 {
				actual = choices[0]
			}
			key := p.Tag + "\x00" + exit
			current := clientmodel.Selection{Scope: p.Tag, CandidateID: actual, Targets: map[string]string{}}
			choices, decision, err := clientmodel.ChooseForwardWithStability(grouped[key], local, shared, clientmodel.Preference{Schema: 3, PolicyID: p.Policy.PolicyID}, current, nextMemory[key], generation, now, clock, clientmodel.DefaultPerformanceRule)
			if errors.Is(err, clientmodel.ErrNoUsableCandidate) {
				choices = []string{}
				decision = clientmodel.SelectionMemory{PolicyID: p.Policy.PolicyID, NetworkGeneration: generation, ClockMS: clock, Decisions: map[string]clientmodel.SelectionDecision{}}
			} else if err != nil {
				return memory, err
			}
			desired[exit], planned[key] = choices, decision
		}
		if !reflect.DeepEqual(before.Choices, desired) {
			if _, err = selector.applyForward(ctx, p.Tag, before, desired); err != nil {
				return memory, err
			}
		}
		for exit, choices := range desired {
			current := "reject"
			if len(choices) > 0 {
				current = choices[0]
			}
			key := p.Tag + "\x00" + exit
			confirmed, err := clientmodel.ConfirmSelection(planned[key], clientmodel.Selection{Scope: p.Tag, CandidateID: current, Targets: map[string]string{}}, clock)
			if err != nil {
				return memory, err
			}
			nextMemory[key] = confirmed
		}
	}
	// Drop memory for removed Policies/exits; it is bounded by current projection.
	keys := make([]string, 0, len(nextMemory))
	for key := range nextMemory {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	allowed := map[string]bool{}
	for _, p := range projections {
		for _, exit := range p.Policy.Exits {
			allowed[p.Tag+"\x00"+exit] = true
		}
	}
	for _, key := range keys {
		if !allowed[key] {
			delete(nextMemory, key)
		}
	}
	return nextMemory, nil
}
