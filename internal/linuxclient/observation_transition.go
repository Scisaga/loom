package linuxclient

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// Both envelopes come from the running daemon's accepted identity store. The
// previous value is only a comparison input, never an execution fallback. A
// restart without that input retains the conservative exact-view cache rule.
func loadLocalStateForView(path, generation string, current, previous *control.DeviceViewEnvelope) (LocalState, error) {
	return loadLocalStateWithEvidence(path, generation, current.ViewDigest, func(state LocalState) ([]clientmodel.Observation, []control.Observation) {
		var resources []control.Observation
		if sameObservationIdentity(state, previous, current) {
			if probes, err := control.FirstHopProbes(current.View); err == nil {
				resources = clientadapter.RetainResourceObservations(probes, state.ResourceObservations, generation)
			}
		}
		return unchangedObservations(state, previous, current), resources
	})
}

func sameObservationIdentity(state LocalState, previous, current *control.DeviceViewEnvelope) bool {
	return previous != nil && current != nil && state.ObservationViewDigest == previous.ViewDigest &&
		previous.NetworkID == current.NetworkID && previous.GenesisDigest == current.GenesisDigest &&
		previous.View.DeviceID == current.View.DeviceID && previous.View.DevicePublicKey == current.View.DevicePublicKey &&
		previous.View.Platform == current.View.Platform && reflect.DeepEqual(previous.View.DNSServers, current.View.DNSServers)
}

func unchangedObservations(state LocalState, previous, current *control.DeviceViewEnvelope) []clientmodel.Observation {
	result := []clientmodel.Observation{}
	if !sameObservationIdentity(state, previous, current) {
		return result
	}
	before, after := previous.View, current.View
	oldOutbounds, newOutbounds := observationOutbounds(before.RuntimeProfile), observationOutbounds(after.RuntimeProfile)
	oldRoutes := map[string]control.RouteCandidate{}
	newRoutes := map[string]control.RouteCandidate{}
	for _, route := range before.Routes {
		oldRoutes[route.ID] = route
	}
	for _, route := range after.Routes {
		newRoutes[route.ID] = route
	}
	for _, observation := range state.Observations {
		old, wasAuthorized := oldRoutes[observation.CandidateID]
		next, isAuthorized := newRoutes[observation.CandidateID]
		if !wasAuthorized || !isAuthorized || observation.Scope != old.Scope || !reflect.DeepEqual(old, next) ||
			observation.NetworkGeneration != state.NetworkGeneration ||
			observation.Action != "https_request" && observation.Action != "tcp_udp_dns" {
			continue
		}
		if observation.Action == "tcp_udp_dns" && !reflect.DeepEqual(before.Endpoints, after.Endpoints) {
			// TUN endpoint exclusions are execution inputs of this action.
			continue
		}
		target := observation.Target
		if target == "" || !observationTarget(before, old.ServiceID, target) || !observationTarget(after, next.ServiceID, target) ||
			!sameObservationOutbound(oldOutbounds, newOutbounds, observation.CandidateID) {
			continue
		}
		// These are the original samples, including failures and original
		// validity limits. Neither re-binding nor reporting renews their age.
		result = append(result, observation)
	}
	return result
}

func observationTarget(view control.DeviceView, serviceID, target string) bool {
	for _, group := range view.BusinessProbeTargets {
		if group.ServiceID == serviceID {
			return slices.Contains(group.Targets, target)
		}
	}
	return false
}

func observationOutbounds(profile *control.RuntimeProfile) map[string]json.RawMessage {
	if profile == nil || profile.Kind != "sing_box" {
		return nil
	}
	var document struct {
		Outbounds []json.RawMessage `json:"outbounds"`
		Endpoints []json.RawMessage `json:"endpoints"`
	}
	if json.Unmarshal([]byte(profile.Config), &document) != nil {
		return nil
	}
	result := map[string]json.RawMessage{}
	for _, body := range append(document.Outbounds, document.Endpoints...) {
		var outbound struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(body, &outbound) != nil || outbound.Tag == "" || result[outbound.Tag] != nil {
			return nil
		}
		result[outbound.Tag] = body
	}
	return result
}

func sameObservationOutbound(before, after map[string]json.RawMessage, tag string) bool {
	seen := map[string]bool{}
	for tag != "" {
		if seen[tag] || before[tag] == nil || !bytes.Equal(before[tag], after[tag]) {
			return false
		}
		seen[tag] = true
		var outbound struct {
			Detour string `json:"detour"`
		}
		if json.Unmarshal(before[tag], &outbound) != nil {
			return false
		}
		tag = outbound.Detour
	}
	return len(seen) != 0
}
