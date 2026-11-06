package clientmodel

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"loom/internal/control"
)

// PolicyGraph is a deletable calculation input, projected once from the signed
// resources/Policy. It is not a route registry, credential or persisted choice.
type PolicyGraph struct {
	PolicyID   string
	SourceNode string
	RelayScope control.PolicyScope
	MaxHops    int
	Links      []GraphLink
}
type GraphLink struct {
	From, To string
	Ref      LinkSampleRef
}

// EstimateRoutePaths shares one reverse search per exit/constraint set and
// updates runtime estimates only. Unknown samples never become zero RTTs.
func EstimateRoutePaths(routes []RouteCandidate, graphs []PolicyGraph, local []control.Observation, shared []control.DeviceLinkObservation, generation string, now time.Time) ([]RouteCandidate, error) {
	if len(graphs) == 0 {
		return routes, nil
	}
	native := map[string]routeFact{}
	remote := map[string]routeFact{}
	for _, sample := range local {
		if sample.Level != "link" || sample.NetworkGeneration != generation {
			continue
		}
		if sample.Validate() != nil {
			return nil, fmt.Errorf("invalid local graph observation")
		}
		fact, err := reportFact("local", sample, sample.ValidUntil)
		if err != nil {
			return nil, err
		}
		key := sampleTuple(sample.Level, "", sample.ResourceID, sample.LinkID, sample.SpecDigest, sample.Target, sample.Action)
		old, found := native[key]
		native[key] = mergeRouteFact(old, found, fact)
	}
	for _, sample := range shared {
		if sample.Observation.Level != "link" {
			continue
		}
		if sample.Validate() != nil {
			return nil, fmt.Errorf("invalid shared graph observation")
		}
		fact, err := reportFact(sample.DeviceID, sample.Observation, sample.CurrentUntil)
		if err != nil {
			return nil, err
		}
		value := sample.Observation
		key := sampleTuple(value.Level, sample.DeviceID, value.ResourceID, value.LinkID, value.SpecDigest, value.Target, value.Action)
		old, found := remote[key]
		remote[key] = mergeRouteFact(old, found, fact)
	}
	byPolicy := map[string]PolicyGraph{}
	graphKeys := map[string][32]byte{}
	for _, graph := range graphs {
		if graph.RelayScope.Validate() != nil || graph.MaxHops < 0 || byPolicy[graph.PolicyID].PolicyID != "" {
			return nil, fmt.Errorf("invalid or duplicated Policy graph")
		}
		byPolicy[graph.PolicyID] = graph
		var identity strings.Builder
		field := func(value string) {
			identity.WriteString(strconv.Itoa(len(value)))
			identity.WriteByte(':')
			identity.WriteString(value)
		}
		field(graph.SourceNode)
		field(graph.RelayScope.Mode)
		field(strconv.Itoa(graph.MaxHops))
		field(strconv.Itoa(len(graph.RelayScope.NodeIDs)))
		for _, node := range graph.RelayScope.NodeIDs {
			field(node)
		}
		field(strconv.Itoa(len(graph.Links)))
		for _, link := range graph.Links {
			field(link.Ref.ResourceID)
			field(link.From)
			field(link.To)
			field(link.Ref.LinkID)
			field(link.Ref.DeviceID)
			field(link.Ref.SpecDigest)
			field(link.Ref.Target)
			field(link.Ref.Action)
		}
		graphKeys[graph.PolicyID] = sha256.Sum256([]byte(identity.String()))
	}

	type estimates struct {
		measured map[string]PathEstimate
		topology map[string]PathEstimate
		fallback map[string]PathEstimate
		refs     map[string]LinkSampleRef
	}
	type estimateKey struct {
		graph [32]byte
		exit  string
	}
	cached := map[estimateKey]estimates{}
	result := slices.Clone(routes)
	for index, route := range result {
		graph, found := byPolicy[route.PolicyID]
		if !found || route.FinalExit == "direct" || len(route.Chain) == 0 {
			continue
		}
		entry := route.Chain[0]
		// Entry scope has already qualified the entry/exit candidate. Only relay
		// constraints affect the suffix, so matching Policies share this work.
		key := estimateKey{graph: graphKeys[graph.PolicyID], exit: route.FinalExit}
		value, exists := cached[key]
		if !exists {
			edges := []PathEdge{}
			qualified := []PathEdge{}
			refs := map[string]LinkSampleRef{}
			for _, link := range graph.Links {
				if link.From == route.FinalExit || link.To != route.FinalExit && !graph.RelayScope.Allows(link.To) {
					continue
				}
				ref := link.Ref
				refs[ref.LinkID] = ref
				qualified = append(qualified, PathEdge{ID: ref.LinkID, From: link.From, To: link.To})
				tuple := sampleTuple("link", ref.DeviceID, ref.ResourceID, ref.LinkID, ref.SpecDigest, ref.Target, ref.Action)
				fact, present := remote[tuple]
				if ref.DeviceID == graph.SourceNode {
					fact, present = native[sampleTuple("link", "", ref.ResourceID, ref.LinkID, ref.SpecDigest, ref.Target, ref.Action)]
				}
				var rtt *time.Duration
				if present && fact.current(now) {
					if fact.result == "unavailable" {
						continue
					}
					if fact.result == "available" && fact.rtt != nil {
						duration := time.Duration(*fact.rtt) * time.Millisecond
						if *fact.rtt < 0 || int64(duration)/int64(time.Millisecond) != *fact.rtt {
							return nil, fmt.Errorf("graph RTT overflow")
						}
						rtt = &duration
					}
				}
				edges = append(edges, PathEdge{ID: ref.LinkID, From: link.From, To: link.To, RTT: rtt})
			}
			maximum := 0
			if graph.MaxHops > 0 {
				maximum = graph.MaxHops - 1
			}
			measured := map[string]PathEstimate{}
			var err error
			if graph.MaxHops != 1 {
				measured, err = ShortestMeasuredPaths(edges, map[string]time.Duration{route.FinalExit: 0}, maximum)
				if err != nil {
					return nil, err
				}
			} else {
				measured[route.FinalExit] = PathEstimate{Exit: route.FinalExit, Nodes: []string{route.FinalExit}, EdgeIDs: []string{}}
			}
			value = estimates{measured: measured,
				topology: topologySuffixes(edges, route.FinalExit, maximum, graph.MaxHops == 1),
				fallback: topologySuffixes(qualified, route.FinalExit, maximum, graph.MaxHops == 1), refs: refs}
			cached[key] = value
		}
		path, known := value.measured[entry]
		if !known {
			path, known = value.topology[entry]
		}
		if !known {
			// A failed diagnostic does not remove the last legal suffix.
			// Policy/relay/hop constraints already filtered this same graph.
			path, known = value.fallback[entry]
		}
		result[index].GraphUnavailable = !known
		if !known {
			continue
		}
		result[index].Chain = slices.Clone(path.Nodes)
		result[index].RelayLinks = []LinkSampleRef{}
		for _, id := range path.EdgeIDs {
			result[index].RelayLinks = append(result[index].RelayLinks, value.refs[id])
		}
	}
	return result, nil
}

// A topology fallback has no measured RTT and is used only for exploration.
func topologySuffixes(edges []PathEdge, exit string, maximum int, localOnly bool) map[string]PathEstimate {
	values := map[string]PathEstimate{exit: {Exit: exit, Nodes: []string{exit}, EdgeIDs: []string{}}}
	if localOnly {
		return values
	}
	reverse := map[string][]PathEdge{}
	for _, edge := range edges {
		reverse[edge.To] = append(reverse[edge.To], edge)
	}
	for node := range reverse {
		slices.SortFunc(reverse[node], func(a, b PathEdge) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
	}
	queue := []string{exit}
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		suffix := values[node]
		if maximum > 0 && len(suffix.EdgeIDs) >= maximum {
			continue
		}
		for _, edge := range reverse[node] {
			if _, seen := values[edge.From]; seen {
				continue
			}
			values[edge.From] = PathEstimate{Exit: exit, Nodes: append([]string{edge.From}, suffix.Nodes...), EdgeIDs: append([]string{edge.ID}, suffix.EdgeIDs...)}
			queue = append(queue, edge.From)
		}
	}
	return values
}
