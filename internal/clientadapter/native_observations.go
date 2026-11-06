package clientadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"sort"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

const NativeObservationReadbackLimit = 64 << 10
const NativeObservationLimit = 128

// NativeTCPObservation is a bounded process-local readback, never a signed
// measurement or an authorization value. Its revision was pinned at creation.
type NativeTCPObservation struct {
	Revision    string `json:"revision"`
	PolicyID    string `json:"policy_id"`
	CandidateID string `json:"candidate_id"`
	Target      string `json:"target"`
	Result      string `json:"result"`
	StartedAt   int64  `json:"started_at"`
	ObservedAt  int64  `json:"observed_at"`
}

func DecodeNativeObservations(body []byte) ([]NativeTCPObservation, error) {
	if len(body) == 0 || len(body) > NativeObservationReadbackLimit {
		return nil, errors.New("native TCP readback exceeds its bound")
	}
	var value struct {
		Observations []NativeTCPObservation `json:"observations"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Observations == nil || len(value.Observations) > NativeObservationLimit {
		return nil, errors.New("invalid native TCP readback")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing native TCP readback")
	}
	for _, event := range value.Observations {
		if !validSnapshotRevision(event.Revision) || control.ValidateID(event.PolicyID) != nil || control.ValidateDigest(event.CandidateID) != nil || control.ValidateConnectionTarget(event.Target) != nil || event.StartedAt <= 0 || event.ObservedAt < event.StartedAt || event.ObservedAt > time.Date(9999, 12, 31, 23, 59, 59, 999000000, time.UTC).UnixMilli() {
			return nil, errors.New("invalid native TCP observation")
		}
		if event.Result != "available" && event.Result != "unavailable" && event.Result != "unknown" {
			return nil, errors.New("invalid native TCP outcome")
		}
	}
	return value.Observations, nil
}

func (selector *HTTPSelector) ReadNativeObservations(ctx context.Context) ([]byte, error) {
	return selector.request(ctx, http.MethodGet, "/loom/tcp-observations", nil)
}

// NativeBindingMatches compares disposable execution ownership. Network changes
// are not authorization changes, and labels/probe-only edits are not execution.
func NativeBindingMatches(memory clientmodel.SelectionMemory, actual clientmodel.Selection, generation, spec string) bool {
	b := memory.NativeBinding
	return spec != "" && b != nil && b.Revision == actual.Revision && b.NetworkGeneration == generation && b.ExecutionSpec == spec && memory.NetworkGeneration == generation && memory.PolicyID == actual.PolicyID
}

func BindNativeSelection(memory clientmodel.SelectionMemory, actual clientmodel.Selection, generation, spec string) clientmodel.SelectionMemory {
	if actual.Scope == control.AccessSelectorScope && actual.CandidateID != BlockedSelection && validSnapshotRevision(actual.Revision) && generation != "" && spec != "" && memory.PolicyID == actual.PolicyID && memory.NetworkGeneration == generation {
		memory.NativeBinding = &clientmodel.NativeBinding{Revision: actual.Revision, NetworkGeneration: generation, ExecutionSpec: spec}
	} else {
		memory.NativeBinding = nil
	}
	return memory
}

// ConsumeNativeObservations never repairs an event using a current selector.
// Only the original revision can attribute a new event. Already consumed facts
// survive a performance revision while their network/spec and deadline remain.
func ConsumeNativeObservations(body []byte, state State, routes []clientmodel.RouteCandidate, now time.Time) ([]clientmodel.Observation, error) {
	authorized := map[string]bool{}
	for _, route := range routes {
		if route.PolicyID == state.Preference.PolicyID && clientmodel.CandidateSelectorScope(route) == control.AccessSelectorScope {
			authorized[route.ID] = true
		}
	}
	return consumeNativeObservations(body, state, authorized, authorized, now)
}

// ConsumeNativeSelectionObservations is the narrow quick-consumption path.
// The caller already owns this complete confirmed snapshot under its existing
// View/preference/network fence. It cannot bind or manufacture authorization.
func ConsumeNativeSelectionObservations(body []byte, state State, current clientmodel.Selection, now time.Time) ([]clientmodel.Observation, error) {
	if err := clientmodel.ValidateAccessSelection(current); err != nil {
		return nil, err
	}
	existing, events := map[string]bool{}, map[string]bool{}
	for _, sample := range state.NativeObservations {
		existing[sample.CandidateID] = true
	}
	if NativeBindingMatches(state.SelectionMemory[control.AccessSelectorScope], current, state.NetworkGeneration, state.NativeExecutionSpec) {
		for id := range current.Choices {
			events[id] = true
		}
	}
	return consumeNativeObservations(body, state, existing, events, now)
}

func consumeNativeObservations(body []byte, state State, retainedAllowed, eventAllowed map[string]bool, now time.Time) ([]clientmodel.Observation, error) {
	events, err := DecodeNativeObservations(body)
	if err != nil {
		return nil, err
	}
	memory := state.SelectionMemory[control.AccessSelectorScope]
	binding := memory.NativeBinding
	if binding == nil || binding.ExecutionSpec != state.NativeExecutionSpec || binding.NetworkGeneration != state.NetworkGeneration || memory.PolicyID != state.Preference.PolicyID {
		return []clientmodel.Observation{}, nil
	}
	values := map[string]clientmodel.Observation{}
	merge := func(value clientmodel.Observation) {
		key := value.Key()
		old, exists := values[key]
		start := func(v clientmodel.Observation) int64 {
			end, _ := time.Parse(time.RFC3339Nano, v.ObservedAt)
			return end.UnixMilli() - v.MetricMillis
		}
		if !exists || start(value) > start(old) {
			values[key] = value
			return
		}
		if start(value) == start(old) && value != old {
			valueAt, _ := time.Parse(time.RFC3339Nano, value.ObservedAt)
			oldAt, _ := time.Parse(time.RFC3339Nano, old.ObservedAt)
			valueUntil, _ := time.Parse(time.RFC3339Nano, value.ValidUntil)
			oldUntil, _ := time.Parse(time.RFC3339Nano, old.ValidUntil)
			// Multiple fast attempts may share the millisecond start. Equal
			// health is not a conflict and cannot renew the original sample.
			if value.Result == old.Result {
				if valueAt.Before(oldAt) {
					old = value
				}
				old.ValidUntil = time.UnixMilli(min(oldUntil.UnixMilli(), valueUntil.UnixMilli())).UTC().Format(time.RFC3339Nano)
				values[key] = old
				return
			}
			// Different outcomes, including an existing unknown, cannot be
			// washed into a fresh conclusion by a later duplicate read.
			if valueAt.Before(oldAt) {
				old = value
				oldAt = valueAt
			}
			old.Result = "unknown"
			old.ValidUntil = time.UnixMilli(min(oldUntil.UnixMilli(), valueUntil.UnixMilli(), oldAt.Add(DefaultMeasurementTiming.FailureValidity).UnixMilli())).UTC().Format(time.RFC3339Nano)
			values[key] = old
		}
	}
	for _, value := range state.NativeObservations {
		at, _ := time.Parse(time.RFC3339Nano, value.ObservedAt)
		retained := value.CurrentAt(now) || value.Action == "tcp_connect" && !now.Before(at) && now.Before(at.Add(DefaultMeasurementTiming.SuccessValidity))
		if value.Validate() == nil && (value.Action == "tcp_connect" || value.Action == "tcp_calibration") && value.Scope == control.AccessSelectorScope && value.NetworkGeneration == state.NetworkGeneration && retainedAllowed[value.CandidateID] && retained {
			merge(value)
		}
	}
	for _, event := range events {
		if event.Revision != binding.Revision || event.PolicyID != memory.PolicyID || !eventAllowed[event.CandidateID] || event.ObservedAt > now.UnixMilli() {
			continue
		}
		key := "tcp://" + event.Target
		selected, exists := memory.Decisions[key]
		if !exists {
			selected = memory.Decisions[""]
		}
		if selected.Current != event.CandidateID {
			continue
		}
		validity := DefaultMeasurementTiming.FailureValidity
		if event.Result == "available" {
			validity = DefaultMeasurementTiming.SuccessValidity
		}
		at := time.UnixMilli(event.ObservedAt).UTC()
		value := clientmodel.Observation{CandidateID: event.CandidateID, Scope: control.AccessSelectorScope, Target: event.Target, NetworkGeneration: state.NetworkGeneration, Result: event.Result, Action: "tcp_connect", ObservedAt: at.Format(time.RFC3339Nano), ValidUntil: at.Add(validity).Format(time.RFC3339Nano), MetricMillis: event.ObservedAt - event.StartedAt}
		if value.Validate() != nil {
			return nil, errors.New("native TCP result could not form a local observation")
		}
		if value.CurrentAt(now) || now.Before(at.Add(DefaultMeasurementTiming.SuccessValidity)) {
			merge(value)
		}
	}
	result := make([]clientmodel.Observation, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	// Retain the newest attempts under the same native cache bound.
	sort.Slice(result, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, result[i].ObservedAt)
		b, _ := time.Parse(time.RFC3339Nano, result[j].ObservedAt)
		if a.UnixMilli()-result[i].MetricMillis != b.UnixMilli()-result[j].MetricMillis {
			return a.UnixMilli()-result[i].MetricMillis > b.UnixMilli()-result[j].MetricMillis
		}
		return result[i].Key() < result[j].Key()
	})
	if len(result) > NativeObservationLimit {
		result = result[:NativeObservationLimit]
	}
	bytesUsed, retained := 2, 0
	for _, value := range result {
		encoded, _ := json.Marshal(value)
		required := len(encoded)
		if retained > 0 {
			required++
		}
		if bytesUsed+required > NativeObservationReadbackLimit {
			break
		}
		bytesUsed += required
		retained++
	}
	result = result[:retained]
	sort.Slice(result, func(i, j int) bool { return result[i].Key() < result[j].Key() })
	return result, nil
}

// NativeRoutingChanged ignores newer timing for the same qualitative fact
// unless a pending performance decision needs a genuinely new original sample.
func NativeRoutingChanged(before, after []clientmodel.Observation, memory clientmodel.SelectionMemory) bool {
	old := map[string]string{}
	for _, value := range before {
		old[value.Key()] = value.Result
	}
	if len(old) != len(after) {
		return true
	}
	for _, value := range after {
		if old[value.Key()] != value.Result {
			return true
		}
	}
	for _, decision := range memory.Decisions {
		if decision.Pending != "" && !slices.Equal(before, after) {
			return true
		}
	}
	return false
}

// RefreshNativeHealth advances a deletable wake-up coordinate, not sample TTL.
// An expired ordinary row may remain for activity, but loses health exactly at
// its original deadline and triggers only one subsequent routing evaluation.
func RefreshNativeHealth(memory clientmodel.SelectionMemory, values []clientmodel.Observation, now time.Time) (clientmodel.SelectionMemory, bool) {
	due := memory.NativeHealthUntil > 0 && now.UnixMilli() >= memory.NativeHealthUntil
	next := int64(0)
	for _, value := range values {
		if value.CurrentAt(now) {
			until, _ := time.Parse(time.RFC3339Nano, value.ValidUntil)
			if next == 0 || until.UnixMilli() < next {
				next = until.UnixMilli()
			}
		}
	}
	memory.NativeHealthUntil = next
	return memory, due
}

// RefreshNativeObservations only reads local snapshots. No graph estimation,
// remote request, probe, report or new binding occurs on an unchanged tick.
func RefreshNativeObservations(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state State, now func() time.Time) (State, bool, error) {
	if state.NativeExecutionSpec == "" {
		return state, false, nil
	}
	current, err := selector.ReadSelection(ctx, control.AccessSelectorScope)
	if err != nil {
		return state, false, err
	}
	if current.CandidateID == BlockedSelection {
		return state, false, nil
	}
	bound := NativeBindingMatches(state.SelectionMemory[control.AccessSelectorScope], current, state.NetworkGeneration, state.NativeExecutionSpec)
	body := []byte(`{"observations":[]}`)
	if reader, ok := selector.(interface {
		ReadNativeObservations(context.Context) ([]byte, error)
	}); ok && bound {
		body, err = reader.ReadNativeObservations(ctx)
		if err != nil {
			return state, false, err
		}
	}
	at := now()
	completed, err := ConsumeNativeObservations(body, state, routes, at)
	if err != nil {
		return state, false, err
	}
	changed := !bound
	memory, healthDue := RefreshNativeHealth(state.SelectionMemory[control.AccessSelectorScope], completed, at)
	state.SelectionMemory = maps.Clone(state.SelectionMemory)
	state.SelectionMemory[control.AccessSelectorScope] = memory
	for _, route := range routes {
		if route.PolicyID == state.Preference.PolicyID && !route.FixedExit {
			changed = changed || healthDue || NativeRoutingChanged(state.NativeObservations, completed, memory)
			break
		}
	}
	state.NativeObservations = completed
	return state, changed, nil
}

// NativeExecutionSpec uses the already projected current Policy's execution
// dependencies. It excludes observations, estimated paths, labels, unselected
// Policies and probe URLs which do not restrict access.
func NativeExecutionSpec(view control.DeviceView, routes []clientmodel.RouteCandidate, graphs []clientmodel.PolicyGraph, policyID string) (string, error) {
	if policyID == "" {
		return "", nil
	}
	var policy control.NetworkPolicy
	for _, value := range view.Policies {
		if value.ID == policyID {
			policy = value
			break
		}
	}
	if policy.ID == "" || !slices.Contains(view.PolicyIDs, policyID) {
		return "", errors.New("native observation Policy is not granted")
	}
	executionPolicy := map[string]any{"id": policy.ID, "service_id": policy.ServiceID, "action": policy.Action, "entry_scope": policy.EntryScope, "relay_scope": policy.RelayScope, "exit_scope": policy.ExitScope, "allow_direct": policy.AllowDirect, "local_egress_devices": policy.LocalEgressDevices, "max_hops": policy.MaxHops}
	var service control.Service
	for _, value := range view.Services {
		if value.ID == policy.ServiceID {
			service = value
			break
		}
	}
	if service.Kind != "internet" {
		return "", nil
	}
	entries, exits, resourceIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	choices := []any{}
	for _, route := range routes {
		if route.PolicyID != policyID {
			continue
		}
		entries[route.EntryNodeID] = true
		exits[route.FinalExit] = true
		if route.FirstResourceID != "" {
			resourceIDs[route.FirstResourceID] = true
		}
		choices = append(choices, struct {
			ID       string                         `json:"id"`
			FirstHop *clientmodel.ResourceSampleRef `json:"first_hop,omitempty"`
		}{route.ID, route.FirstHop})
	}
	links := []clientmodel.GraphLink{}
	for _, graph := range graphs {
		if graph.PolicyID != policyID {
			continue
		}
		for _, link := range graph.Links {
			if (entries[link.From] || policy.RelayScope.Allows(link.From)) && (exits[link.To] || policy.RelayScope.Allows(link.To)) {
				links = append(links, link)
			}
		}
	}
	// Both ends must lie on a possible entry-to-exit suffix, independent of
	// transient weights. This is not a second path recommendation.
	outgoing, incoming := map[string][]string{}, map[string][]string{}
	for _, link := range links {
		outgoing[link.From] = append(outgoing[link.From], link.To)
		incoming[link.To] = append(incoming[link.To], link.From)
	}
	walk := func(seeds map[string]bool, next map[string][]string) map[string]bool {
		seen := map[string]bool{}
		queue := []string{}
		for id := range seeds {
			seen[id] = true
			queue = append(queue, id)
		}
		for head := 0; head < len(queue); head++ {
			for _, id := range next[queue[head]] {
				if !seen[id] {
					seen[id] = true
					queue = append(queue, id)
				}
			}
		}
		return seen
	}
	forward, reverse := walk(entries, outgoing), walk(exits, incoming)
	relevant := []map[string]any{}
	for _, link := range links {
		if forward[link.From] && reverse[link.To] {
			relevant = append(relevant, map[string]any{"from": link.From, "to": link.To, "ref": link.Ref})
			resourceIDs[link.Ref.ResourceID] = true
		}
	}
	resources := []control.TransportResource{}
	for _, resource := range view.Resources {
		if resourceIDs[resource.ID] {
			resources = append(resources, resource)
		}
	}
	credentials := []control.TransportCredential{}
	for _, credential := range view.TransportCredentials {
		if resourceIDs[credential.ResourceID] && credential.SenderID == view.DeviceID {
			credentials = append(credentials, credential)
		}
	}
	resolver := map[string][]string{}
	for _, node := range view.Nodes {
		if exits[node.ID] {
			resolver[node.ID] = append([]string{}, node.DNSServers...)
		}
	}
	boundary := service.TargetMatchers(view.DNSRecords...)
	inputs := map[string]any{"network_id": view.NetworkID, "source": view.DeviceID, "source_public_key": view.DevicePublicKey, "wireguard_public_key": view.WireGuardPublicKey, "source_dns": append([]string{}, view.DNSServers...), "policy": executionPolicy, "boundary": boundary, "choices": choices, "links": relevant, "resources": resources, "credentials": credentials, "exit_dns": resolver}
	body, err := control.CanonicalEncode(inputs)
	if err != nil {
		return "", err
	}
	return control.ReleaseDigest(body), nil
}
