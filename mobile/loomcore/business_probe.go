package loomcore

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// AndroidBusinessRequest belongs to one existing host probe session. Cancellation
// closes that request; it owns no profile, selection, cache or network authority.
type AndroidBusinessRequest struct {
	ctx       context.Context
	cancel    context.CancelFunc
	candidate string
	target    string
}

func NewAndroidBusinessRequest(body []byte, candidate, target, generation string) (*AndroidBusinessRequest, error) {
	if control.ValidateID(generation) != nil {
		return nil, errors.New("business measurement requires its underlay generation")
	}
	state, err := decodeState(body)
	if err != nil || state.LKG == nil {
		return nil, errors.New("business probe requires an accepted View")
	}
	execution, err := control.ProjectDeviceCandidates(state.LKG.View, clientmodel.MeasurementPolicies(androidPreference(state)))
	if err != nil {
		return nil, err
	}
	service, selectorScope := "", ""
	for _, route := range execution.Routes {
		if route.ID == candidate {
			service = route.ServiceID
			selectorScope = clientmodel.CandidateSelectorScope(clientmodel.RouteCandidate{Scope: route.Scope})
			break
		}
	}
	allowed := false
	for _, group := range execution.BusinessProbeTargets {
		if group.ServiceID == service && slices.Contains(group.Targets, target) {
			allowed = true
		}
	}
	if service == "" || !allowed {
		return nil, errors.New("business probe differs from certified Service and candidate")
	}
	ctx, cancel := context.WithTimeout(clientadapter.WithMeasurementNetwork(androidNetworkContext(), generation), 8*time.Second)
	ctx, err = clientadapter.NativeDiagnosticContext(ctx, androidLocalRuntimeSecret(state), nil)
	if err != nil {
		cancel()
		return nil, err
	}
	return &AndroidBusinessRequest{ctx: clientadapter.WithCandidateScope(ctx, selectorScope), cancel: cancel, candidate: candidate, target: target}, nil
}

func (request *AndroidBusinessRequest) Cancel() { request.cancel() }

func (request *AndroidBusinessRequest) Run() ([]byte, error) {
	defer request.cancel()
	result := clientadapter.ProbeCandidateBusiness(request.ctx, request.candidate, request.target)
	if result.Deferred {
		return nil, clientadapter.ErrMeasurementDeferred
	}
	if errors.Is(request.ctx.Err(), context.Canceled) {
		return nil, context.Canceled
	}
	return json.Marshal(struct {
		Available    bool   `json:"available"`
		MetricMillis int64  `json:"metric_millis"`
		Description  string `json:"description"`
	}{result.Available, result.Metric.Milliseconds(), result.Description})
}
