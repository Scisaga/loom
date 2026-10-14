package clientadapter

import (
	"context"
	"errors"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"sort"
	"time"
)

type AlternateProbe struct {
	CandidateID string `json:"candidate_id"`
	Target      string `json:"target"`
}

// NextAlternateProbe is a pure fair rotation over existing samples. It needs no
// scheduler state: the oldest attempted candidate/target is sufficient.
func NextAlternateProbe(routes []clientmodel.RouteCandidate, state State, current string, targets []string, now time.Time) (AlternateProbe, bool, error) {
	type pending struct {
		value    AlternateProbe
		observed string
	}
	values := []pending{}
	transport := append(append([]control.Observation{}, state.ResourceObservations...), state.LocalLinkObservations...)
	for _, route := range routes {
		if route.ID == current {
			continue
		}
		_, err := clientmodel.SelectWithLinks([]clientmodel.RouteCandidate{route}, state.Observations, transport, state.LinkObservations, state.Preference, "", state.NetworkGeneration, now, targets...)
		if errors.Is(err, clientmodel.ErrNoUsableCandidate) {
			continue
		}
		if err != nil {
			return AlternateProbe{}, false, err
		}
		for _, target := range targets {
			if target == "" {
				continue
			}
			if control.ValidateHTTPSURL(target) != nil {
				return AlternateProbe{}, false, errors.New("invalid alternate probe target")
			}
			sample, found, err := clientmodel.LatestObservation(state.Observations, route.ID, route.Scope, state.NetworkGeneration, target)
			if err != nil {
				return AlternateProbe{}, false, err
			}
			if found && sample.CurrentAt(now) {
				continue
			}
			at := ""
			if found {
				observed, _ := time.Parse(time.RFC3339, sample.ObservedAt)
				if !observed.After(now) {
					at = sample.ObservedAt
				}
			}
			values = append(values, pending{value: AlternateProbe{route.ID, target}, observed: at})
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].observed != values[j].observed {
			return values[i].observed < values[j].observed
		}
		if values[i].value.CandidateID != values[j].value.CandidateID {
			return values[i].value.CandidateID < values[j].value.CandidateID
		}
		return values[i].value.Target < values[j].value.Target
	})
	if len(values) == 0 {
		return AlternateProbe{}, false, nil
	}
	return values[0].value, true, nil
}

// SampleAlternateBusiness performs at most one independent request. The caller
// may then use the same selector model; this function never changes a selector.
func SampleAlternateBusiness(ctx context.Context, routes []clientmodel.RouteCandidate, state State, current string, targets []string, now func() time.Time) (State, error) {
	if !candidateDiagnosticAvailable(ctx) {
		return state, nil
	}
	return sampleAlternateBusiness(ctx, routes, state, current, targets, now, ProbeCandidateBusiness)
}

func sampleAlternateBusiness(ctx context.Context, routes []clientmodel.RouteCandidate, state State, current string, targets []string, now func() time.Time, probe func(context.Context, string, string) ProbeResult) (State, error) {
	request, found, err := NextAlternateProbe(routes, state, current, targets, now())
	if err != nil || !found {
		return state, err
	}
	result := probe(ctx, request.CandidateID, request.Target)
	if ctx.Err() != nil {
		return state, ctx.Err()
	}
	result.Target = request.Target
	result.Action = "https_request"
	scope := ""
	for _, route := range routes {
		if route.ID == request.CandidateID {
			scope = route.Scope
			break
		}
	}
	return recordOutcome(state, map[string]string{scope: request.CandidateID}, result, now().UTC().Truncate(time.Second)), nil
}
