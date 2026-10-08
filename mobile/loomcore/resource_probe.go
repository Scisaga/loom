package loomcore

import (
	"context"
	"errors"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func androidSelectedCandidates(view control.DeviceView, body []byte) ([]string, error) {
	var selections []androidSelection
	if err := decodeStrictJSON(body, 1<<20, &selections); err != nil {
		return nil, err
	}
	if selections == nil {
		return nil, errors.New("Android selector readback is missing")
	}
	routes := map[string]control.RouteCandidate{}
	for _, route := range view.Routes {
		routes[route.ID] = route
	}
	seen := map[string]bool{}
	selected := make([]string, 0, len(selections))
	for _, value := range selections {
		route, found := routes[value.CandidateID]
		if !found || route.Scope != value.Scope || seen[value.Scope] {
			return nil, errors.New("Android selector readback is outside the current authorization")
		}
		seen[value.Scope] = true
		selected = append(selected, value.CandidateID)
	}
	return selected, nil
}

// Kotlin calls this under its existing configuration and route operation locks,
// after actual selector readback. The result is the shared deletable cache, not
// another identity record or a report sequence reservation.
func ObserveAndroidFirstHops(stateBody, selectionsBody, previousBody []byte, generation string) ([]byte, error) {
	state, err := decodeState(stateBody)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 5*time.Second)
	defer cancel()
	return observeAndroidFirstHops(ctx, state, selectionsBody, previousBody, generation, func() time.Time {
		return time.Now().UTC().Truncate(time.Second)
	})
}

func observeAndroidFirstHops(ctx context.Context, state deviceclient.State, selectionsBody, previousBody []byte, generation string, now func() time.Time) ([]byte, error) {
	if state.LKG == nil {
		return nil, errors.New("Android first-hop sampling requires an accepted configuration")
	}
	selected, err := androidSelectedCandidates(state.LKG.View, selectionsBody)
	if err != nil {
		return nil, err
	}
	previous := []control.Observation{}
	if len(previousBody) > 0 {
		previous, err = clientadapter.DecodeResourceObservations(previousBody, *state.LKG, generation)
		if err != nil {
			return nil, err
		}
	}
	diagnostic, err := clientadapter.NativeDiagnosticContext(ctx, androidLocalRuntimeSecret(state), nil)
	if err != nil {
		return nil, err
	}
	values, err := clientadapter.ObserveFirstHops(diagnostic, state.LKG.View, selected, previous, generation, now)
	if err != nil {
		return nil, err
	}
	return clientadapter.EncodeResourceObservations(*state.LKG, values)
}
