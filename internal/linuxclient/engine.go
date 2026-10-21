package linuxclient

import (
	"context"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

type ProbeResult = clientadapter.ProbeResult
type Probe = clientadapter.Probe
type Probes = clientadapter.Probes

const blockedSelection = clientadapter.BlockedSelection

type Activation struct {
	State         LocalState
	Selections    []SelectionStatus
	BlockedScopes []string
}

func scopesFor(routes []clientmodel.RouteCandidate, scopeIDs ...string) ([]string, map[string][]clientmodel.RouteCandidate, error) {
	return clientadapter.Scopes(routes, scopeIDs...)
}

// Local persistence stays platform-owned; all Service selection and sampling
// use the same executor as Windows and the same pure model as Android.
func Activate(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state LocalState,
	probes Probes, now func() time.Time) (Activation, error) {
	return activateWithLinkSamples(ctx, selector, routes, state, nil, nil, probes, now)
}

func activateWithLinkSamples(ctx context.Context, selector Selector, routes []clientmodel.RouteCandidate, state LocalState,
	local []control.Observation, remote []control.DeviceLinkObservation, probes Probes, now func() time.Time, scopeIDs ...string) (Activation, error) {
	value, err := clientadapter.Activate(ctx, selector, routes, clientadapter.State{
		Preference: state.Preference, NetworkGeneration: state.NetworkGeneration,
		Observations: state.Observations, ResourceObservations: state.ResourceObservations,
		LinkObservations:      remote,
		LocalLinkObservations: local,
	}, probes, now, scopeIDs...)
	if value.State.NetworkGeneration == "" {
		return Activation{}, err
	}
	state.Observations, state.ResourceObservations = value.State.Observations, value.State.ResourceObservations
	return Activation{State: state, Selections: value.Selections, BlockedScopes: value.BlockedScopes}, err
}
