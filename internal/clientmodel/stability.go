package clientmodel

import (
	"errors"
	"maps"
	"sort"
	"strings"
	"time"

	"loom/internal/control"
	"loom/protocol"
)

// SelectionMemory is bounded by the current selector's targets. It lives only
// in the host adapter's running instance, never in identity, LKG or a report.
// Its clock is that instance's injected monotonic millisecond clock.
type SelectionMemory struct {
	PolicyID          string                       `json:"policy_id"`
	NetworkGeneration string                       `json:"network_generation"`
	ClockMS           int64                        `json:"clock_ms"`
	Version           uint64                       `json:"version"`
	Samples           map[string]sampleVersion     `json:"samples"`
	Decisions         map[string]SelectionDecision `json:"decisions"`
	NativeBinding     *NativeBinding               `json:"native_binding,omitempty"`
	NativeHealthUntil int64                        `json:"native_health_until,omitempty"`
}

// NativeBinding associates one confirmed runtime snapshot with its local
// network and execution inputs. It is disposable, never an authorization.
type NativeBinding struct {
	Revision          string `json:"revision"`
	NetworkGeneration string `json:"network_generation"`
	ExecutionSpec     string `json:"execution_spec"`
}
type sampleVersion struct {
	ObservedAt int64  `json:"observed_at"`
	Version    uint64 `json:"version"`
}
type SelectionDecision struct {
	Current   string `json:"current"`
	AppliedMS int64  `json:"applied_ms"`
	// Qualified records that this scope/target has completed initial usable
	// discovery in this Policy/network, not health of its current candidate.
	Qualified     bool   `json:"qualified"`
	Pending       string `json:"pending"`
	Confirmations int    `json:"confirmations"`
	Through       uint64 `json:"through"`
	Basis         string `json:"basis"`
	CalibrateTCP  bool   `json:"calibrate_tcp,omitempty"`
}

func copySelectionMemory(memory SelectionMemory) SelectionMemory {
	result := memory
	if memory.NativeBinding != nil {
		binding := *memory.NativeBinding
		result.NativeBinding = &binding
	}
	result.Samples = maps.Clone(memory.Samples)
	if result.Samples == nil {
		result.Samples = map[string]sampleVersion{}
	}
	result.Decisions = make(map[string]SelectionDecision, len(memory.Decisions))
	for key, value := range memory.Decisions {
		result.Decisions[key] = value
	}
	return result
}
func selectedTarget(selection Selection, target string) string {
	if value, exists := selection.Targets[target]; target != "" && exists {
		return value
	}
	return selection.CandidateID
}
func clearPending(value SelectionDecision) SelectionDecision {
	value.Pending = ""
	value.Confirmations = 0
	value.Through, value.Basis = 0, ""
	value.CalibrateTCP = false
	return value
}

// ChooseWithStability is the sole routing calculation used by host adapters.
// Current is an actual readback. Returning a plan does not record it as applied;
// ConfirmSelection is called only after successful complete selector readback.
func ChooseWithStability(routes []RouteCandidate, observations []Observation, resources []control.Observation, shared []control.DeviceLinkObservation,
	preference Preference, current Selection, memory SelectionMemory, generation string, now time.Time, clockMS int64, rule PerformanceRule, targets ...string) (Selection, SelectionMemory, error) {
	return ChooseWithNativeStability(routes, observations, nil, resources, shared, preference, current, memory, generation, now, clockMS, rule, targets...)
}

// ChooseWithNativeStability consumes already-bound local TCP results separately
// from HTTPS samples. Neither input can change the other action's evidence.
func ChooseWithNativeStability(routes []RouteCandidate, observations, native []Observation, resources []control.Observation, shared []control.DeviceLinkObservation,
	preference Preference, current Selection, memory SelectionMemory, generation string, now time.Time, clockMS int64, rule PerformanceRule, targets ...string) (Selection, SelectionMemory, error) {
	if rule.Validate() != nil || clockMS < 0 {
		return Selection{}, memory, errors.New("invalid performance clock or rule")
	}
	evaluation, err := evaluateNativeRouting(routes, observations, native, resources, shared, preference, current.CandidateID, generation, now, targets)
	if err != nil {
		return Selection{}, memory, err
	}
	desired, next, err := chooseStable(evaluation, preference, current, memory, generation, now, clockMS, rule, targets)
	if err == nil && ValidSelectorScope(desired.Scope) {
		desired, err = BindSelectionChoices(desired, routes)
	}
	return desired, next, err
}

func chooseStable(evaluation routingEvaluation, preference Preference, current Selection, memory SelectionMemory, generation string, now time.Time, clockMS int64, rule PerformanceRule, targets []string) (Selection, SelectionMemory, error) {
	if memory.PolicyID != preference.PolicyID || memory.NetworkGeneration != generation || clockMS < memory.ClockMS {
		memory = SelectionMemory{PolicyID: preference.PolicyID, NetworkGeneration: generation, Decisions: map[string]SelectionDecision{}}
		// Old target preferences do not carry across a changed network or Policy.
		current.Targets = map[string]string{}
	}
	memory = copySelectionMemory(memory)
	memory.ClockMS = clockMS
	usedSamples := map[string]bool{}
	sampleKeys := map[string]string{}
	finish := func(desired Selection) (Selection, SelectionMemory, error) {
		for key := range memory.Samples {
			if !usedSamples[key] {
				delete(memory.Samples, key)
			}
		}
		return desired, memory, nil
	}
	qualified := func(path routeEvidence, target string) bool {
		if path.failed || !path.entryReady {
			return false
		}
		if evaluation.fixed {
			return true
		}
		if target != "" {
			return evaluation.connectionOrigin(path, target).result == "available"
		}
		if len(targets) == 0 {
			return true
		}
		return path.coverage > 0
	}
	decide := func(target, proposed, actual string) string {
		previous, exists := memory.Decisions[target]
		if !exists && target != "" {
			previous = memory.Decisions[""]
			previous = clearPending(previous)
			previous.Qualified = false
		}
		if previous.Current != actual || !exists && target == "" {
			previous = SelectionDecision{Current: actual, AppliedMS: clockMS, Qualified: previous.Qualified}
		}
		before, allowed := evaluation.paths[actual]
		after := evaluation.paths[proposed]
		if !evaluation.fixed && target != "" && allowed && evaluation.connectionOrigin(before, target).result == "unavailable" {
			// A definite failure of this target permits immediate exploration,
			// even when the alternative is still unknown or has a higher RTT.
			// This is not a failure of the path for other targets. If every
			// proposed route is also known to fail, keep the current choice
			// instead of cycling between failures on transport performance.
			memory.Decisions[target] = clearPending(previous)
			if evaluation.connectionOrigin(after, target).result != "unavailable" {
				return proposed
			}
			return actual
		}
		if allowed && before.failed && !after.failed {
			// An alternative with no current diagnostic failure can be tried
			// immediately. With none, retain the qualified current path rather
			// than turning a probe outcome into an Internet rejection.
			memory.Decisions[target] = clearPending(previous)
			return proposed
		}
		transportRecovery := false
		if target != "" && allowed {
			if candidate, found := evaluation.recoveryProposal(before, target, rule); found {
				proposed, after, transportRecovery = candidate.route.ID, candidate, true
			}
		}
		if allowed && qualified(before, target) {
			previous.Qualified = true
		}
		// An applied target override has already made its first choice. A
		// different path's recovery is then an optimization, regardless of
		// whether this Service also has optional measurement URLs.
		initialDiscovery := !transportRecovery && !previous.Qualified && qualified(after, target) && (target == "" || current.Targets[target] == "")
		// Withdrawal, observed transport failure, initial selection and initial
		// availability discovery do not wait for a performance cooldown.
		if !allowed || initialDiscovery {
			memory.Decisions[target] = clearPending(previous)
			return proposed
		}
		if actual == proposed {
			memory.Decisions[target] = clearPending(previous)
			return actual
		}
		proof, better := evaluation.improvement(before, after, target, rule)
		if transportRecovery {
			proof, better = evaluation.transportImprovement(before, after, rule)
		}
		if !better {
			memory.Decisions[target] = clearPending(previous)
			return actual
		}
		if previous.Pending != proposed {
			previous = clearPending(previous)
			previous.Pending = proposed
		}
		// Related exit HTTPS evidence is already measured and shared. Its
		// success can support the combination, but never erase a live local
		// TCP failure; its failure cannot be washed by a TCP calibration.
		previous.CalibrateTCP = transportRecovery && evaluation.origin(after, target).result == "unknown" && evaluation.connectionOrigin(after, target).result != "available"
		versions := make([]uint64, 0, len(proof))
		keys := make([]string, 0, len(proof))
		ids := make([]string, 0, len(proof))
		for id := range proof {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fact := proof[id]
			key, exists := sampleKeys[id]
			if !exists {
				key = control.ReleaseDigest([]byte(id))
				sampleKeys[id] = key
			}
			keys = append(keys, key)
			usedSamples[key] = true
			known := memory.Samples[key]
			progressAt := fact.at
			if fact.started > 0 {
				progressAt = fact.started
			}
			if progressAt > known.ObservedAt {
				memory.Version++
				known = sampleVersion{ObservedAt: progressAt, Version: memory.Version}
				memory.Samples[key] = known
			}
			version := known.Version
			if progressAt < known.ObservedAt {
				version = 0
			}
			versions = append(versions, version)
		}
		sort.Strings(keys)
		basis := control.ReleaseDigest([]byte(strings.Join(keys, "\x00")))
		if previous.Basis != basis {
			calibrate := previous.CalibrateTCP
			previous = clearPending(previous)
			previous.Pending, previous.Basis = proposed, basis
			previous.CalibrateTCP = calibrate
		}
		// Versions are local processing coordinates, not signed facts or a
		// clock shared by sources. Each original advances only its own item.
		fresh := true
		for _, version := range versions {
			if version <= previous.Through {
				fresh = false
			}
		}
		if fresh {
			previous.Confirmations++
			previous.Through = memory.Version
		}
		memory.Decisions[target] = previous
		if previous.Confirmations >= rule.Confirmations && clockMS-previous.AppliedMS >= rule.MinimumInterval.Milliseconds() {
			if transportRecovery && evaluation.connectionOrigin(after, target).result != "available" {
				return actual
			}
			return proposed
		}
		return actual
	}
	scope := current.Scope
	if scope == "" {
		scope = control.AccessSelectorScope
	}
	desired := Selection{Scope: scope, Targets: map[string]string{}}
	desired.CandidateID = decide("", evaluation.selection.CandidateID, current.CandidateID)
	if evaluation.fixed {
		for key := range memory.Decisions {
			if key != "" {
				delete(memory.Decisions, key)
			}
		}
		return finish(desired)
	}
	keys := map[string]bool{}
	for key := range evaluation.knownOrigins {
		keys[key] = true
	}
	for key := range evaluation.selection.Targets {
		keys[key] = true
	}
	for key := range current.Targets {
		keys[key] = true
	}
	for key := range keys {
		if _, _, _, err := protocol.ParseConnectionTargetKey(key); err != nil {
			return Selection{}, memory, errors.New("invalid actual selector target")
		}
	}
	boundPassiveTargets(keys, memory, evaluation, targets)
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, target := range ordered {
		proposed := selectedTarget(evaluation.selection, target)
		actual := selectedTarget(current, target)
		// A never-overridden unknown target simply follows the stable default.
		if _, known := evaluation.origins[target]; !known {
			if _, kept := current.Targets[target]; !kept {
				delete(memory.Decisions, target)
				continue
			}
			network, _, _, _ := protocol.ParseConnectionTargetKey(target)
			if _, allowed := evaluation.paths[actual]; allowed && network != "tcp" {
				if actual != desired.CandidateID {
					desired.Targets[target] = actual
				}
				if decision, exists := memory.Decisions[target]; exists {
					memory.Decisions[target] = clearPending(decision)
				}
				continue
			}
			proposed = desired.CandidateID
		}
		chosen := decide(target, proposed, actual)
		if chosen != desired.CandidateID {
			desired.Targets[target] = chosen
		}
	}
	for key := range memory.Decisions {
		if key != "" && !keys[key] {
			delete(memory.Decisions, key)
		}
	}
	return finish(desired)
}

// Expiry is not a reason to restore a formerly failed path. Capacity eviction
// alone bounds passive target preferences; configured Service URLs are exempt.
func boundPassiveTargets(keys map[string]bool, memory SelectionMemory, evaluation routingEvaluation, targets []string) {
	configured := map[string]bool{}
	for _, target := range targets {
		if origin, err := probeOrigin(target); err == nil {
			configured[origin] = true
		}
	}
	passive := make([]string, 0, len(keys))
	for key := range keys {
		if !configured[key] {
			passive = append(passive, key)
		}
	}
	if len(passive) <= 128 {
		return
	}
	fresh := map[string]int64{}
	for id, values := range evaluation.native {
		if _, allowed := evaluation.paths[id]; !allowed {
			continue
		}
		for key, fact := range values {
			if fact.at <= evaluation.now.UnixMilli() && evaluation.now.UnixMilli() < fact.until {
				fresh[key] = max(fresh[key], fact.started)
			}
		}
	}
	sort.Slice(passive, func(i, j int) bool {
		a, b := passive[i], passive[j]
		if fresh[a] != fresh[b] {
			return fresh[a] > fresh[b]
		}
		if memory.Decisions[a].AppliedMS != memory.Decisions[b].AppliedMS {
			return memory.Decisions[a].AppliedMS > memory.Decisions[b].AppliedMS
		}
		return a < b
	})
	for _, key := range passive[128:] {
		delete(keys, key)
	}
}

// MeasurementCandidates projects current use and an already significant
// pending improvement into disposable scheduling hints. Callers still match
// every ID to their current authorized candidates or own directed links.
func MeasurementCandidates(current Selection, memory SelectionMemory, generation string) []string {
	values := map[string]bool{}
	add := func(id string) {
		if id != "reject" && validName(id) {
			values[id] = true
		}
	}
	add(current.CandidateID)
	for _, id := range current.Targets {
		add(id)
	}
	if memory.PolicyID == current.PolicyID && memory.NetworkGeneration == generation {
		for target, decision := range memory.Decisions {
			if decision.Current == selectedTarget(current, target) && decision.Confirmations > 0 {
				add(decision.Pending)
			}
		}
	}
	result := make([]string, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func (e routingEvaluation) improvement(before, after routeEvidence, target string, rule PerformanceRule) (map[string]routeFact, bool) {
	facts := map[string]routeFact{}
	add := func(values map[string]routeFact) {
		for id, fact := range values {
			facts[id] = fact
		}
	}
	if !e.fixed && target == "" && after.coverage > before.coverage {
		for origin := range e.origins {
			a, b := e.origin(before, origin), e.origin(after, origin)
			if b.result == "available" && a.result != "available" {
				add(a.facts)
				add(b.facts)
			}
		}
	} else if !e.fixed && target != "" && e.connectionOrigin(after, target).result == "available" && e.connectionOrigin(before, target).result != "available" {
		add(e.connectionOrigin(before, target).facts)
		add(e.connectionOrigin(after, target).facts)
	} else {
		transport, better := e.transportImprovement(before, after, rule)
		if !better {
			return nil, false
		}
		add(transport)
		if !e.fixed && target != "" && before.route.FinalExit != after.route.FinalExit {
			add(e.connectionOrigin(before, target).facts)
			add(e.connectionOrigin(after, target).facts)
		}
	}
	if len(facts) == 0 {
		return nil, false
	}
	for _, fact := range facts {
		if !fact.current(e.now) {
			return nil, false
		}
	}
	return facts, true
}

func significantTransportGain(before, after routeEvidence, rule PerformanceRule) bool {
	if before.cost == nil || after.cost == nil || *after.cost >= *before.cost {
		return false
	}
	delta := *before.cost - *after.cost
	relative := *before.cost/10000*rule.ImprovementBasisPoints + (*before.cost%10000*rule.ImprovementBasisPoints+9999)/10000
	absolute := int64(rule.MinimumImprovement / time.Millisecond)
	if rule.MinimumImprovement%time.Millisecond != 0 {
		absolute++
	}
	return delta >= relative && delta >= absolute
}

func (e routingEvaluation) transportImprovement(before, after routeEvidence, rule PerformanceRule) (map[string]routeFact, bool) {
	if !significantTransportGain(before, after, rule) {
		return nil, false
	}
	facts := map[string]routeFact{}
	for id, fact := range before.facts {
		if _, common := after.facts[id]; !common {
			facts[id] = fact
		}
	}
	for id, fact := range after.facts {
		if _, common := before.facts[id]; !common {
			facts[id] = fact
		}
	}
	if len(facts) == 0 {
		return nil, false
	}
	for _, fact := range facts {
		if !fact.current(e.now) {
			return nil, false
		}
	}
	return facts, true
}

// One pre-ranked transport winner per exit is reused by all target decisions.
// Target success does not prevent a better unknown transport from being
// measured; only actual/composed target success can release the application.
func (e routingEvaluation) recoveryProposal(before routeEvidence, target string, rule PerformanceRule) (routeEvidence, bool) {
	if e.fixed {
		return routeEvidence{}, false
	}
	network, _, _, err := protocol.ParseConnectionTargetKey(target)
	if err != nil || network != "tcp" {
		return routeEvidence{}, false
	}
	for _, candidate := range e.frontier {
		if candidate.route.ID == before.route.ID {
			continue
		}
		if !significantTransportGain(before, candidate, rule) {
			break
		}
		if e.origin(candidate, target).result == "unavailable" {
			continue
		}
		return candidate, true
	}
	return routeEvidence{}, false
}

// ConfirmSelection records only an actual successfully applied/read-back plan.
// A failed or superseded operation discards its proposed memory instead.
func ConfirmSelection(memory SelectionMemory, actual Selection, clockMS int64) (SelectionMemory, error) {
	if clockMS < 0 || clockMS < memory.ClockMS || !validName(actual.Scope) || !validName(actual.CandidateID) {
		return memory, errors.New("invalid applied selection confirmation")
	}
	memory = copySelectionMemory(memory)
	memory.ClockMS = clockMS
	keys := map[string]bool{"": true}
	for key := range actual.Targets {
		keys[key] = true
	}
	for key := range memory.Decisions {
		keys[key] = true
	}
	for key := range keys {
		id := selectedTarget(actual, key)
		value := memory.Decisions[key]
		if value.Current != id {
			value = SelectionDecision{Current: id, AppliedMS: clockMS, Qualified: value.Qualified}
		}
		memory.Decisions[key] = value
	}
	return memory, nil
}
