package clientadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

// TCPRecoveryInput is a transient input to the existing node worker round.
// Its local observations never enter the signed measurement reducer/cache.
type TCPRecoveryInput struct {
	Selector *HTTPSelector
	Routes   []clientmodel.RouteCandidate
	State    State
	Progress func([]clientmodel.Observation) error
	stale    atomic.Bool
}

func (selector *HTTPSelector) calibrateTCP(ctx context.Context, current clientmodel.Selection, route clientmodel.RouteCandidate, target string) (NativeTCPObservation, error) {
	var zero NativeTCPObservation
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, errors.New("TCP calibration requires the node measurement deadline")
	}
	network, host, port, err := protocol.ParseConnectionTargetKey(target)
	if err != nil || network != "tcp" || route.PolicyID != current.PolicyID {
		return zero, errors.New("TCP calibration is outside the current Policy")
	}
	body, err := json.Marshal(map[string]any{"expected_revision": current.Revision, "policy_id": current.PolicyID, "choice": protocol.RouteChoice{EntryNodeID: route.EntryNodeID, FirstResourceID: route.FirstResourceID, FinalExit: route.FinalExit}, "target": target})
	if err != nil {
		return zero, err
	}
	response, err := selector.request(ctx, http.MethodPost, "/loom/access/"+url.PathEscape(current.Scope)+"/tcp-connect", body)
	if err != nil {
		if errors.Is(err, ErrResourcesNotReady) {
			return zero, ErrMeasurementDeferred
		}
		return zero, err
	}
	wrapped := append([]byte(`{"observations":[`), response...)
	wrapped = append(wrapped, ']', '}')
	values, err := DecodeNativeObservations(wrapped)
	if err != nil || len(values) != 1 {
		return zero, errors.New("invalid TCP calibration response")
	}
	value := values[0]
	if value.Revision != current.Revision || value.PolicyID != current.PolicyID || value.CandidateID != route.ID || value.Target != net.JoinHostPort(host, strconv.Itoa(int(port))) {
		return zero, errors.New("TCP calibration response differs from its original request")
	}
	after, err := selector.ReadSelection(ctx, current.Scope)
	if err != nil {
		return zero, err
	}
	if after.Revision != current.Revision || !SameSelection(after, current) {
		return zero, ErrSelectionSuperseded
	}
	return value, nil
}

func MergeTCPRecoveryObservations(state State, routes []clientmodel.RouteCandidate, completed []clientmodel.Observation, now time.Time) ([]clientmodel.Observation, error) {
	for _, sample := range completed {
		if sample.Validate() != nil || sample.Action != "tcp_calibration" || sample.NetworkGeneration != state.NetworkGeneration {
			return nil, errors.New("invalid local TCP calibration completion")
		}
	}
	state.NativeObservations = append(append([]clientmodel.Observation{}, state.NativeObservations...), completed...)
	return ConsumeNativeObservations([]byte(`{"observations":[]}`), state, routes, now)
}

// AcceptTCPRecovery is called by the existing single reducer after its host
// owner fence. A performance revision supersedes only these local results.
func AcceptTCPRecovery(ctx context.Context, selector Selector, expected, current State, routes []clientmodel.RouteCandidate, completed []clientmodel.Observation, now func() time.Time) ([]clientmodel.Observation, error) {
	if !expected.Preference.Equal(current.Preference) || expected.NetworkGeneration != current.NetworkGeneration || expected.NativeExecutionSpec != current.NativeExecutionSpec {
		return nil, ErrSelectionSuperseded
	}
	binding := expected.SelectionMemory[control.AccessSelectorScope].NativeBinding
	actual, err := selector.ReadSelection(ctx, control.AccessSelectorScope)
	if err != nil {
		return current.NativeObservations, err
	}
	if binding == nil || !NativeBindingMatches(current.SelectionMemory[control.AccessSelectorScope], actual, current.NetworkGeneration, current.NativeExecutionSpec) || actual.Revision != binding.Revision {
		return current.NativeObservations, nil
	}
	return MergeTCPRecoveryObservations(current, routes, completed, now())
}

func tcpRecoveryJobs(ctx context.Context, input *TCPRecoveryInput, generation string, now func() time.Time) ([]nodeMeasurement, error) {
	if input == nil || input.Selector == nil || input.State.NetworkGeneration != generation || input.State.NativeExecutionSpec == "" {
		return nil, nil
	}
	memory := input.State.SelectionMemory[control.AccessSelectorScope]
	if memory.NativeBinding == nil || len(input.State.NativeObservations) == 0 {
		return nil, nil
	}
	current, err := input.Selector.ReadSelection(ctx, control.AccessSelectorScope)
	if err != nil {
		return nil, err
	}
	if !NativeBindingMatches(memory, current, generation, input.State.NativeExecutionSpec) {
		return nil, nil
	}
	planned, err := clientmodel.TCPRecoveryMeasurements(input.Routes, current, memory, input.State.NativeObservations, generation, now(), clientmodel.DefaultPerformanceRule, DefaultMeasurementTiming.SuccessValidity)
	if err != nil {
		return nil, err
	}
	routes := map[string]clientmodel.RouteCandidate{}
	for _, route := range input.Routes {
		routes[route.ID] = route
	}
	jobs := make([]nodeMeasurement, 0, len(planned))
	for _, request := range planned {
		route, allowed := routes[request.CandidateID]
		if !allowed || route.PolicyID != current.PolicyID || route.FixedExit {
			return nil, errors.New("TCP recovery recommendation is outside the current nonfixed Policy")
		}
		key := measurementIdentity(ctx, "tcp-calibration", input.State.NativeExecutionSpec, current.PolicyID, request.CandidateID, request.Target)
		job := nodeMeasurement{key: key, active: true, localProgress: input.Progress}
		for _, sample := range input.State.NativeObservations {
			if sample.Action == "tcp_calibration" && sample.CandidateID == route.ID && "tcp://"+sample.Target == request.Target && sample.NetworkGeneration == generation {
				at, _ := time.Parse(time.RFC3339Nano, sample.ObservedAt)
				job.observed = max(job.observed, at.UnixMilli())
			}
		}
		job.localRun = func(pending context.Context) (clientmodel.Observation, error) {
			if input.stale.Load() {
				return clientmodel.Observation{}, ErrSelectionSuperseded
			}
			value, err := runMeasurement(pending, measurementIdentity(pending, "tcp-calibration", input.State.NativeExecutionSpec, current.Revision, current.PolicyID, route.ID, request.Target), 32<<10, func(admitted context.Context) (NativeTCPObservation, error) {
				return input.Selector.calibrateTCP(admitted, current, route, request.Target)
			})
			if err != nil {
				if errors.Is(err, ErrSelectionSuperseded) {
					input.stale.Store(true)
				}
				return clientmodel.Observation{}, err
			}
			if value.ObservedAt > now().UnixMilli() {
				return clientmodel.Observation{}, errors.New("TCP calibration response has a future completion")
			}
			validity := DefaultMeasurementTiming.FailureValidity
			if value.Result == "available" {
				validity = DefaultMeasurementTiming.SuccessValidity
			}
			at := time.UnixMilli(value.ObservedAt).UTC()
			result := clientmodel.Observation{CandidateID: value.CandidateID, Target: value.Target, Scope: control.AccessSelectorScope, NetworkGeneration: generation, Result: value.Result, Action: "tcp_calibration", ObservedAt: at.Format(time.RFC3339Nano), ValidUntil: at.Add(validity).Format(time.RFC3339Nano), MetricMillis: value.ObservedAt - value.StartedAt}
			if err := result.Validate(); err != nil {
				return clientmodel.Observation{}, err
			}
			return result, nil
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}
