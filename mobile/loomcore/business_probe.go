package loomcore

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"loom/internal/clientadapter"
)

// AndroidBusinessRequest belongs to one existing host probe session. Cancellation
// closes that request; it owns no profile, selection, cache or network authority.
type AndroidBusinessRequest struct {
	ctx       context.Context
	cancel    context.CancelFunc
	candidate string
	target    string
}

func NewAndroidBusinessRequest(body []byte, candidate, target string) (*AndroidBusinessRequest, error) {
	state, err := decodeState(body)
	if err != nil || state.LKG == nil {
		return nil, errors.New("business probe requires an accepted View")
	}
	service := ""
	for _, route := range state.LKG.View.Routes {
		if route.ID == candidate {
			service = route.ServiceID
			break
		}
	}
	allowed := false
	for _, group := range state.LKG.View.BusinessProbeTargets {
		if group.ServiceID == service && slices.Contains(group.Targets, target) {
			allowed = true
		}
	}
	if service == "" || !allowed {
		return nil, errors.New("business probe differs from certified Service and candidate")
	}
	ctx, cancel := context.WithTimeout(androidNetworkContext(), 8*time.Second)
	ctx, err = clientadapter.NativeDiagnosticContext(ctx, androidLocalRuntimeSecret(state), nil)
	if err != nil {
		cancel()
		return nil, err
	}
	return &AndroidBusinessRequest{ctx: ctx, cancel: cancel, candidate: candidate, target: target}, nil
}

func (request *AndroidBusinessRequest) Cancel() { request.cancel() }

func (request *AndroidBusinessRequest) Run() ([]byte, error) {
	defer request.cancel()
	result := clientadapter.ProbeCandidateBusiness(request.ctx, request.candidate, request.target)
	if errors.Is(request.ctx.Err(), context.Canceled) {
		return nil, context.Canceled
	}
	return json.Marshal(struct {
		Available    bool   `json:"available"`
		MetricMillis int64  `json:"metric_millis"`
		Description  string `json:"description"`
	}{result.Available, result.Metric.Milliseconds(), result.Description})
}
