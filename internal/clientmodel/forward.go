package clientmodel

import (
	"errors"
	"slices"
	"sort"
	"time"

	"loom/internal/control"
)

// ChooseForwardWithStability uses the same comparison and confirmation rule as
// access, for one already constrained final exit. It never considers URLs or
// changes the original connection's Policy/exit. The tail retains exploration
// choices; the native receiver skips visited nodes at connection establishment.
func ChooseForwardWithStability(routes []RouteCandidate, local []control.Observation, shared []control.DeviceLinkObservation, preference Preference, current Selection, memory SelectionMemory, generation string, now time.Time, clockMS int64, rule PerformanceRule) ([]string, SelectionMemory, error) {
	if rule.Validate() != nil || clockMS < 0 {
		return nil, memory, errors.New("invalid forwarding performance inputs")
	}
	evaluation, err := evaluateRouting(routes, nil, local, shared, preference, current.CandidateID, generation, now, nil)
	if err != nil {
		return nil, memory, err
	}
	for _, route := range routes {
		if !route.FixedExit {
			return nil, memory, errors.New("forward cannot choose another final exit")
		}
	}
	desired, memory, err := chooseStable(evaluation, preference, current, memory, generation, now, clockMS, rule, nil)
	if err != nil {
		return nil, memory, err
	}
	ranked := make([]routeEvidence, 0, len(evaluation.paths))
	for _, path := range evaluation.paths {
		ranked = append(ranked, path)
	}
	sort.Slice(ranked, func(i, j int) bool { return transportLess(ranked[i], ranked[j], current.CandidateID) })
	choices := []string{desired.CandidateID}
	for _, path := range ranked {
		if path.route.ID != desired.CandidateID {
			choices = append(choices, path.route.ID)
		}
	}
	return choices, memory, nil
}

// ForwardRoutePaths computes one suffix per next hop and final exit, using the
// shared reverse graph search. It does not expand possible complete paths.
func ForwardRoutePaths(routes []RouteCandidate, graphs []PolicyGraph, local []control.Observation, shared []control.DeviceLinkObservation, generation string, now time.Time) ([]RouteCandidate, error) {
	filtered := make([]PolicyGraph, len(graphs))
	first := map[string]map[string]LinkSampleRef{}
	for i, graph := range graphs {
		filtered[i] = graph
		filtered[i].Links = []GraphLink{}
		first[graph.PolicyID] = map[string]LinkSampleRef{}
		if graph.MaxHops > 0 {
			filtered[i].MaxHops = max(1, graph.MaxHops-1)
		}
		for _, link := range graph.Links {
			if link.From == graph.SourceNode {
				first[graph.PolicyID][link.To] = link.Ref
			}
			if link.From != graph.SourceNode && link.To != graph.SourceNode {
				filtered[i].Links = append(filtered[i].Links, link)
			}
		}
	}
	result, err := EstimateRoutePaths(routes, filtered, local, shared, generation, now)
	if err != nil {
		return nil, err
	}
	for i, route := range result {
		if len(route.Chain) == 0 {
			return nil, errors.New("forwarding estimate lacks its next hop")
		}
		firstLink, ok := first[route.PolicyID][route.Chain[0]]
		if !ok {
			return nil, errors.New("forwarding estimate lacks its authorized local link")
		}
		result[i].Chain = append([]string{route.SourceNode}, route.Chain...)
		result[i].RelayLinks = append([]LinkSampleRef{firstLink}, slices.Clone(route.RelayLinks)...)
		for _, graph := range graphs {
			if graph.PolicyID == route.PolicyID && graph.MaxHops > 0 && len(result[i].Chain) > graph.MaxHops {
				result[i].GraphUnavailable = true
				break
			}
		}
	}
	return result, nil
}
