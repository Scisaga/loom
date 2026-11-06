package clientmodel

import (
	"errors"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"loom/internal/control"
	"loom/protocol"
)

// These values are disposable calculation inputs, not additional reports or
// authority. Each fact keeps the original sample identity and sampling time.
type routeFact struct {
	id, digest, result string
	at, until, started int64
	rtt                *int64
	conflict           bool
	generation, spec   string
}
type routeEvidence struct {
	route              RouteCandidate
	entryReady, failed bool
	cost               *int64
	facts              map[string]routeFact
	coverage           int
}
type originEvidence struct {
	result string
	facts  map[string]routeFact
}
type routingEvaluation struct {
	selection    Selection
	paths        map[string]routeEvidence
	origins      map[string][]string
	exits        map[string]map[string]routeFact
	business     map[string]map[string]routeFact
	native       map[string]map[string]routeFact
	knownOrigins map[string]bool
	originCache  map[string]map[string]originEvidence
	frontier     []routeEvidence
	fixed        bool
	now          time.Time
}

func probeOrigin(target string) (string, error) {
	if control.ValidateHTTPSURL(target) != nil {
		return "", errors.New("invalid measurement URL")
	}
	parsed, _ := url.Parse(target)
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	number, _ := strconv.ParseUint(port, 10, 16)
	return protocol.ConnectionTargetKey("tcp", parsed.Hostname(), uint16(number))
}
func sampleTuple(level, owner, resource, link, spec, target, action string) string {
	return strings.Join([]string{level, owner, resource, link, spec, target, action}, "\x00")
}
func reportFact(owner string, sample control.Observation, until int64) (routeFact, error) {
	body, err := control.CanonicalEncode(sample)
	if err != nil {
		return routeFact{}, err
	}
	return routeFact{id: sampleTuple(sample.Level, owner, sample.ResourceID, sample.LinkID, sample.SpecDigest, sample.Target, sample.Action) + "\x00" + sample.NetworkGeneration,
		digest: control.ReleaseDigest(body), result: sample.Result, at: sample.ObservedAt, until: min(until, sample.ValidUntil), rtt: sample.RoundTripMS, generation: sample.NetworkGeneration, spec: sample.SpecDigest}, nil
}
func mergeRouteFact(old routeFact, found bool, value routeFact) routeFact {
	if !found {
		return value
	}
	// Deliveries with conflicting source generations/specifications cannot be
	// silently combined. The formal delivery already filters current sources.
	if old.generation != value.generation || old.spec != value.spec {
		old.conflict = true
		return old
	}
	if value.at > old.at {
		return value
	}
	if value.at == old.at && value.digest != old.digest {
		old.conflict = true
	}
	return old
}
func (fact routeFact) current(now time.Time) bool {
	return !fact.conflict && fact.at > 0 && fact.at <= now.UnixMilli() && now.UnixMilli() < fact.until
}
func (e routingEvaluation) origin(path routeEvidence, origin string) originEvidence {
	key := path.route.ID
	if len(e.business[key]) == 0 {
		key = "exit\x00" + path.route.FinalExit
	}
	if cached, found := e.originCache[key][origin]; found {
		return cached
	}
	result := originEvidence{result: "unknown", facts: map[string]routeFact{}}
	targets := e.origins[origin]
	if len(targets) == 0 {
		return result
	}
	allFailure := true
	for _, target := range targets {
		sample, found := e.exits[path.route.FinalExit][target]
		if local, exists := e.business[path.route.ID][target]; exists && (!found || local.at > sample.at) {
			sample, found = local, true
		}
		if !found || !sample.current(e.now) || sample.result == "unknown" {
			allFailure = false
			continue
		}
		result.facts[sample.id] = sample
		if sample.result == "available" {
			result.result = "available"
		} else if sample.result != "unavailable" {
			allFailure = false
		}
	}
	if result.result != "available" && allFailure {
		result.result = "unavailable"
	}
	if e.originCache[key] == nil {
		e.originCache[key] = map[string]originEvidence{}
	}
	e.originCache[key][origin] = result
	return result
}

// TCP confirmation is target/candidate-specific. It never changes URL coverage
// or segment facts, and a TCP success cannot erase a failed HTTPS request.
func (e routingEvaluation) connectionOrigin(path routeEvidence, origin string) originEvidence {
	website := e.origin(path, origin)
	sample, found := e.native[path.route.ID][origin]
	if !found || !sample.current(e.now) {
		return website
	}
	if sample.result == "unavailable" || website.result != "unavailable" {
		return originEvidence{result: sample.result, facts: map[string]routeFact{sample.id: sample}}
	}
	return website
}

func mergeNativeFact(old routeFact, found bool, value routeFact) routeFact {
	if !found || value.started > old.started {
		return value
	}
	if value.started == old.started {
		if old.conflict || old.result == "unknown" || value.result == "unknown" || old.result != value.result {
			old.conflict = true
			return old
		}
		// Millisecond-resolution starts can describe concurrent connections.
		// An identical outcome is one attempt coordinate, not another vote.
		// Retain one real original deterministically, including its deadline.
		if value.at < old.at || value.at == old.at && (value.until < old.until || value.until == old.until && value.digest < old.digest) {
			return value
		}
	}
	return old
}

// evaluateRouting shares exit coverage and segment samples. Its work is linear
// in actual candidates/segments and exit requests; it never probes a URL or
// constructs the candidate x URL product.
func evaluateRouting(routes []RouteCandidate, observations []Observation, resources []control.Observation, shared []control.DeviceLinkObservation,
	preference Preference, current, generation string, now time.Time, targets []string) (routingEvaluation, error) {
	return evaluateNativeRouting(routes, observations, nil, resources, shared, preference, current, generation, now, targets)
}

func evaluateNativeRouting(routes []RouteCandidate, observations, nativeObservations []Observation, resources []control.Observation, shared []control.DeviceLinkObservation,
	preference Preference, current, generation string, now time.Time, targets []string) (routingEvaluation, error) {
	e := routingEvaluation{paths: map[string]routeEvidence{}, origins: map[string][]string{}, exits: map[string]map[string]routeFact{}, business: map[string]map[string]routeFact{}, native: map[string]map[string]routeFact{}, knownOrigins: map[string]bool{}, originCache: map[string]map[string]originEvidence{}, now: now}
	if preference.Validate() != nil || !validName(generation) {
		return e, errors.New("invalid routing input")
	}
	configured := map[string]bool{}
	configuredOrigins := map[string]bool{}
	for _, target := range targets {
		origin, err := probeOrigin(target)
		if err != nil || configured[target] {
			return e, errors.New("invalid or duplicate Service measurement URL")
		}
		configured[target] = true
		configuredOrigins[origin] = true
		e.origins[origin] = append(e.origins[origin], target)
	}
	native := map[string]routeFact{}
	for _, sample := range resources {
		if sample.Validate() != nil || sample.Level != "resource" && sample.Level != "link" && sample.Level != "egress" {
			return e, errors.New("invalid local node measurement")
		}
		if sample.NetworkGeneration != generation {
			continue
		}
		value, err := reportFact("local", sample, sample.ValidUntil)
		if err != nil {
			return e, err
		}
		key := sampleTuple(sample.Level, "", sample.ResourceID, sample.LinkID, sample.SpecDigest, sample.Target, sample.Action)
		old, found := native[key]
		native[key] = mergeRouteFact(old, found, value)
	}
	links := map[string]routeFact{}
	for _, sample := range shared {
		if sample.Validate() != nil {
			return e, errors.New("invalid shared measurement")
		}
		value, err := reportFact(sample.DeviceID, sample.Observation, sample.CurrentUntil)
		if err != nil {
			return e, err
		}
		if sample.Observation.Level == "link" {
			key := sampleTuple("link", sample.DeviceID, sample.Observation.ResourceID, sample.Observation.LinkID, sample.Observation.SpecDigest, sample.Observation.Target, sample.Observation.Action)
			old, found := links[key]
			links[key] = mergeRouteFact(old, found, value)
		} else if sample.Observation.Level == "egress" && configured[sample.Observation.Target] {
			if e.exits[sample.DeviceID] == nil {
				e.exits[sample.DeviceID] = map[string]routeFact{}
			}
			old, found := e.exits[sample.DeviceID][sample.Observation.Target]
			e.exits[sample.DeviceID][sample.Observation.Target] = mergeRouteFact(old, found, value)
		}
	}
	for _, sample := range observations {
		if sample.Validate() != nil {
			return e, errors.New("invalid local business observation")
		}
		if sample.Scope != control.AccessSelectorScope || sample.NetworkGeneration != generation || sample.Action != "https_request" || sample.Target == "" {
			continue
		}
		// Actual target observations may later refine a target outside the probe
		// list. Only configured targets contribute to default Service coverage.
		body, err := control.CanonicalEncode(sample)
		if err != nil {
			return e, err
		}
		at, _ := time.Parse(time.RFC3339, sample.ObservedAt)
		until, _ := time.Parse(time.RFC3339, sample.ValidUntil)
		fact := routeFact{id: "business\x00" + sample.CandidateID + "\x00" + sample.Target + "\x00" + generation, digest: control.ReleaseDigest(body), result: sample.Result, at: at.UnixMilli(), until: until.UnixMilli(), generation: generation}
		if e.business[sample.CandidateID] == nil {
			e.business[sample.CandidateID] = map[string]routeFact{}
		}
		old, found := e.business[sample.CandidateID][sample.Target]
		e.business[sample.CandidateID][sample.Target] = mergeRouteFact(old, found, fact)
	}
	for _, sample := range nativeObservations {
		if sample.Validate() != nil || sample.Action != "tcp_connect" && sample.Action != "tcp_calibration" {
			return e, errors.New("invalid local native TCP observation")
		}
		if sample.NetworkGeneration != generation {
			continue
		}
		host, text, _ := net.SplitHostPort(sample.Target)
		port, _ := strconv.ParseUint(text, 10, 16)
		origin, err := protocol.ConnectionTargetKey("tcp", host, uint16(port))
		if err != nil {
			return e, err
		}
		body, err := control.CanonicalEncode(sample)
		if err != nil {
			return e, err
		}
		at, _ := time.Parse(time.RFC3339Nano, sample.ObservedAt)
		until, _ := time.Parse(time.RFC3339Nano, sample.ValidUntil)
		fact := routeFact{id: "native\x00" + sample.CandidateID + "\x00" + origin + "\x00" + generation,
			digest: control.ReleaseDigest(body), result: sample.Result, at: at.UnixMilli(), until: until.UnixMilli(), started: at.UnixMilli() - sample.MetricMillis, generation: generation}
		if e.native[sample.CandidateID] == nil {
			e.native[sample.CandidateID] = map[string]routeFact{}
		}
		old, found := e.native[sample.CandidateID][origin]
		e.native[sample.CandidateID][origin] = mergeNativeFact(old, found, fact)
	}
	seen := map[string]bool{}
	scope := ""
	fixedSet := false
	source, fixedExit := "", ""
	for _, route := range routes {
		if route.Validate() != nil || seen[route.ID] {
			return e, errors.New("invalid or duplicate authorized route")
		}
		seen[route.ID] = true
		if route.PolicyID != preference.PolicyID {
			continue
		}
		if scope != "" && scope != route.Scope {
			return e, errors.New("one Policy cannot refer to different Services")
		}
		scope = route.Scope
		if fixedSet && e.fixed != route.FixedExit {
			return e, errors.New("inconsistent Policy exit constraint")
		}
		e.fixed = route.FixedExit
		fixedSet = true
		if source != "" && source != route.SourceNode || route.FixedExit && fixedExit != "" && fixedExit != route.FinalExit {
			return e, errors.New("inconsistent Policy source or fixed exit")
		}
		source = route.SourceNode
		if route.FixedExit {
			fixedExit = route.FinalExit
		}
		if route.GraphUnavailable {
			continue
		}
		path := routeEvidence{route: route, facts: map[string]routeFact{}, cost: new(int64(0)), entryReady: true}
		// These actual connection samples have already passed the consumer's
		// Policy/network/execution binding. The candidate fixes its local first
		// transport, but not the suffix independently chosen by forward nodes.
		var entrySuccess routeFact
		for _, outcome := range e.native[route.ID] {
			if outcome.current(now) && outcome.result == "available" && (outcome.started > entrySuccess.started ||
				outcome.started == entrySuccess.started && outcome.id < entrySuccess.id) {
				entrySuccess = outcome
			}
		}
		consume := func(fact routeFact, found, entry bool) {
			if !found || !fact.current(now) {
				path.cost = nil
				if entry {
					path.entryReady = false
				}
				return
			}
			path.facts[fact.id] = fact
			if fact.result == "unavailable" {
				if entry && entrySuccess.started > fact.at {
					// A later actual TCP success proves this first transport,
					// not an HTTPS response or a new RTT. Keep both originals.
					path.facts[entrySuccess.id] = entrySuccess
					path.cost = nil
					return
				}
				path.failed = true
			}
			if fact.result != "available" {
				path.cost = nil
				if entry {
					path.entryReady = false
				}
				return
			}
			if fact.rtt == nil || path.cost == nil {
				path.cost = nil
				return
			}
			if *fact.rtt > math.MaxInt64-*path.cost {
				path.cost = nil
				return
			}
			*path.cost += *fact.rtt
		}
		needsEntry := len(route.Chain) > 0 && route.Chain[0] != route.SourceNode
		if needsEntry {
			if ref := route.FirstHop; ref != nil {
				key := sampleTuple("resource", "", ref.ResourceID, "", ref.SpecDigest, ref.Target, ref.Action)
				sample, found := native[key]
				consume(sample, found, true)
			} else {
				path.cost = nil
				path.entryReady = false
			}
		}
		expectedLinks := max(0, len(route.Chain)-1)
		if len(route.RelayLinks) != expectedLinks {
			path.cost = nil
		}
		for index, ref := range route.RelayLinks {
			key := sampleTuple("link", "", ref.ResourceID, ref.LinkID, ref.SpecDigest, ref.Target, ref.Action)
			sample, found := native[key]
			if !found {
				key = sampleTuple("link", ref.DeviceID, ref.ResourceID, ref.LinkID, ref.SpecDigest, ref.Target, ref.Action)
				sample, found = links[key]
			}
			consume(sample, found, !needsEntry && index == 0 && ref.DeviceID == route.SourceNode)
		}
		// Diagnostic failures lower preference; they do not withdraw an
		// otherwise qualified path or prevent its actual connection attempts.
		e.paths[route.ID] = path
	}
	if len(e.paths) == 0 {
		return e, ErrNoUsableCandidate
	}
	if e.fixed {
		var selected routeEvidence
		for _, path := range e.paths {
			if selected.route.ID == "" || transportLess(path, selected, current) {
				selected = path
			}
		}
		e.selection = Selection{CandidateID: selected.route.ID, Scope: control.AccessSelectorScope, Targets: map[string]string{}}
		return e, nil
	}
	// A hybrid node consumes its own exit checks immediately, without waiting
	// for a report round trip. These samples cannot describe another exit.
	if source != "" {
		for _, sample := range resources {
			if sample.Level != "egress" || sample.NetworkGeneration != generation || !configured[sample.Target] {
				continue
			}
			value, err := reportFact(source, sample, sample.ValidUntil)
			if err != nil {
				return e, err
			}
			if e.exits[source] == nil {
				e.exits[source] = map[string]routeFact{}
			}
			old, found := e.exits[source][sample.Target]
			e.exits[source][sample.Target] = mergeRouteFact(old, found, value)
		}
	}
	// Only actual observations of current Policy candidates create target
	// refinements. An old observation from another Policy cannot create one.
	originURLSets := map[string]map[string]bool{}
	for origin, urls := range e.origins {
		originURLSets[origin] = map[string]bool{}
		for _, target := range urls {
			originURLSets[origin][target] = true
		}
	}
	for id, values := range e.business {
		path, allowed := e.paths[id]
		if !allowed {
			continue
		}
		for target, fact := range values {
			if !fact.current(now) {
				continue
			}
			origin, err := probeOrigin(target)
			if err != nil {
				return e, err
			}
			if fact.result == "available" || fact.result == "unavailable" {
				e.knownOrigins[origin] = true
			}
			if originURLSets[origin] == nil {
				originURLSets[origin] = map[string]bool{}
			}
			if !originURLSets[origin][target] {
				originURLSets[origin][target] = true
				e.origins[origin] = append(e.origins[origin], target)
			}
			if path.route.FinalExit == "direct" {
				if e.exits["direct"] == nil {
					e.exits["direct"] = map[string]routeFact{}
				}
				old, found := e.exits["direct"][target]
				e.exits["direct"][target] = mergeRouteFact(old, found, fact)
			}
		}
	}
	// Ordinary targets remain a bounded, sparse local working set. They do not
	// become additional Service URLs or shared exit measurements.
	nativeOrigins := map[string]bool{}
	for id, values := range e.native {
		if _, allowed := e.paths[id]; !allowed {
			continue
		}
		for origin, fact := range values {
			if !fact.current(now) || fact.result == "unknown" {
				continue
			}
			e.knownOrigins[origin] = true
			nativeOrigins[origin] = true
			if _, exists := e.origins[origin]; !exists {
				e.origins[origin] = []string{}
			}
		}
	}
	for origin := range e.origins {
		sort.Strings(e.origins[origin])
	}
	// Shared coverage is calculated once per exit, independently of which
	// complete candidate happened to be visited first in a map.
	coverage := map[string]int{}
	for _, path := range e.paths {
		exit := path.route.FinalExit
		if _, done := coverage[exit]; done {
			continue
		}
		total := 0
		for origin := range configuredOrigins {
			state := e.origin(routeEvidence{route: RouteCandidate{FinalExit: exit}}, origin).result
			if state != "unknown" {
				e.knownOrigins[origin] = true
			}
			if state == "available" {
				total++
			}
		}
		coverage[exit] = total
	}
	best := map[string]routeEvidence{}
	for id, path := range e.paths {
		path.coverage = coverage[path.route.FinalExit]
		e.paths[id] = path
		old, found := best[path.route.FinalExit]
		if !found || transportLess(path, old, current) {
			best[path.route.FinalExit] = path
		}
	}
	eligible := make([]routeEvidence, 0, len(best))
	for _, path := range best {
		eligible = append(eligible, path)
		if path.entryReady && path.cost != nil {
			e.frontier = append(e.frontier, path)
		}
	}
	sort.Slice(e.frontier, func(i, j int) bool { return transportLess(e.frontier[i], e.frontier[j], current) })
	sort.Slice(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		if a.failed != b.failed {
			return !a.failed
		}
		if a.entryReady != b.entryReady {
			return a.entryReady
		}
		if !e.fixed && a.coverage != b.coverage {
			return a.coverage > b.coverage
		}
		return transportLess(a, b, current)
	})
	selected := eligible[0]
	e.selection = Selection{CandidateID: selected.route.ID, Scope: control.AccessSelectorScope, Targets: map[string]string{}}
	if e.fixed {
		return e, nil
	}
	originIDs := make([]string, 0, len(e.origins))
	for origin := range e.origins {
		originIDs = append(originIDs, origin)
	}
	sort.Strings(originIDs)
	for _, origin := range originIDs {
		candidates := append([]routeEvidence{}, eligible...)
		if nativeOrigins[origin] {
			// A target failure can affect the best entry of an exit without
			// disqualifying another legal entry to that same exit.
			candidates = candidates[:0]
			for _, path := range e.paths {
				candidates = append(candidates, path)
			}
		}
		// Sparse actual path observations refine the shared exit estimate without
		// generating observations for every path and every URL.
		for id, values := range e.business {
			path, exists := e.paths[id]
			if !exists {
				continue
			}
			for target := range values {
				if owner, _ := probeOrigin(target); owner == origin {
					candidates = append(candidates, path)
					break
				}
			}
		}
		rank := func(path routeEvidence) int {
			switch e.connectionOrigin(path, origin).result {
			case "available":
				return 0
			case "unavailable":
				return 2
			}
			return 1
		}
		sort.Slice(candidates, func(i, j int) bool {
			a, b := candidates[i], candidates[j]
			if rank(a) != rank(b) {
				return rank(a) < rank(b)
			}
			if a.failed != b.failed {
				return !a.failed
			}
			if a.entryReady != b.entryReady {
				return a.entryReady
			}
			if rank(a) == 1 && (a.route.ID == selected.route.ID) != (b.route.ID == selected.route.ID) {
				return a.route.ID == selected.route.ID
			}
			return transportLess(a, b, current)
		})
		winner := candidates[0]
		if rank(winner) < 2 && winner.route.ID != selected.route.ID {
			e.selection.Targets[origin] = winner.route.ID
		}
	}
	return e, nil
}

func transportLess(a, b routeEvidence, current string) bool {
	if a.failed != b.failed {
		return !a.failed
	}
	if a.entryReady != b.entryReady {
		return a.entryReady
	}
	if (a.cost != nil) != (b.cost != nil) {
		return a.cost != nil
	}
	if a.cost != nil && b.cost != nil && *a.cost != *b.cost {
		return *a.cost < *b.cost
	}
	if (a.route.ID == current) != (b.route.ID == current) {
		return a.route.ID == current
	}
	if len(a.route.Chain) != len(b.route.Chain) {
		return len(a.route.Chain) < len(b.route.Chain)
	}
	return a.route.ID < b.route.ID
}

// ConnectionOrigin is the exact key used by the one native selector.
func ConnectionOrigin(target string) (string, error) { return probeOrigin(target) }
