package loomcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"loom/internal/attest"
	"loom/internal/clientroute"
	trustedobservation "loom/internal/observation"
)

const (
	androidIdleScheduleWait  = 5 * time.Minute
	androidObservationLimit  = 1 << 20
	androidEntryErrorLimit   = 512
	androidMaxObservationSet = 256
)

// §16.1.2：schema 2 只保存原始、已验证的服务器观测。已删除的 schema 1 窗口
// 来自完整候选/业务探测，不能迁移进新的客户端证据模型。
type androidScheduleState struct {
	Schema       int               `json:"schema"`
	PlanScope    string            `json:"plan_scope"`
	Observations []json.RawMessage `json:"observations,omitempty"`
}

type androidEntryMeasurements struct {
	Schema       int                       `json:"schema"`
	Source       string                    `json:"source,omitempty"`
	Measurements []androidEntryMeasurement `json:"measurements,omitempty"`
}

type androidEntryMeasurement struct {
	Node    string `json:"node"`
	Address string `json:"address"`
	TS      string `json:"ts"`
	RTTMS   int64  `json:"rtt_ms,omitempty"`
	Error   string `json:"error,omitempty"`
}

type androidRouteTick struct {
	Schema           int                     `json:"schema"`
	State            string                  `json:"state"`
	Application      androidRouteApplication `json:"application"`
	Changed          bool                    `json:"changed"`
	NextAfterMS      int64                   `json:"next_after_ms"`
	Detail           string                  `json:"detail"`
	ObservationError string                  `json:"observation_error,omitempty"`
	Decisions        []androidRouteDecision  `json:"decisions,omitempty"`
}

type androidRouteDecision struct {
	Declaration  string                   `json:"declaration"`
	Selector     string                   `json:"selector"`
	Current      string                   `json:"current"`
	Choice       string                   `json:"choice"`
	Switch       bool                     `json:"switch"`
	Chain        []string                 `json:"chain,omitempty"`
	Reason       string                   `json:"reason"`
	UpdatedAt    string                   `json:"updated_at"`
	Candidates   int                      `json:"candidates"`
	Measurements []androidPathMeasurement `json:"measurements,omitempty"`
}

// §7.3.3：androidPathMeasurement 是一条实际连线的只读显示证据，不增加上报字段
// 或探测；所有值都来自当前入口轮次或既有已验签观测缓存。
type androidPathMeasurement struct {
	Hop         int      `json:"hop"`
	From        string   `json:"from"`
	To          string   `json:"to"`
	Kind        string   `json:"kind"`
	ObservedAt  string   `json:"observed_at,omitempty"`
	Error       string   `json:"error,omitempty"`
	DelayMS     *int64   `json:"delay_ms,omitempty"`
	VariationMS *int64   `json:"variation_ms,omitempty"`
	RateBPS     *float64 `json:"rate_bps,omitempty"`
	Samples     int64    `json:"samples,omitempty"`
	Failures    int64    `json:"failures,omitempty"`
}

// RunAndroidRouteTick 执行与 Windows 相同的 §5.5.1 窄决策：每个去重授权入口只
// 消费调用方给出的一次结果，后段只用已验证服务器观测。它不执行网络 I/O、完整
// 候选/业务路径探测或 min_samples 等待，也不为缺失证据编造数值。
func RunAndroidRouteTick(routePlan, preference, savedSelections, routingInputs, actualSelections,
	entryMeasurements, schedulerState, observationResponse, ca []byte, nowRFC3339 string) ([]byte, error) {
	var plan androidRoutePlan
	if err := decodeStrictJSON(routePlan, maxBundleBytes, &plan); err != nil {
		return nil, fmt.Errorf("route plan JSON: %w", err)
	}
	if err := validateStandaloneRoutePlan(&plan); err != nil {
		return nil, err
	}
	now, err := time.Parse(time.RFC3339, nowRFC3339)
	if err != nil {
		return nil, fmt.Errorf("scheduler time must be RFC3339: %w", err)
	}
	now = now.UTC()

	applicationBody, err := EvaluateAndroidRoute(routePlan, preference, savedSelections)
	if err != nil {
		return nil, err
	}
	var application androidRouteApplication
	if err := json.Unmarshal(applicationBody, &application); err != nil {
		return nil, fmt.Errorf("decode route application: %w", err)
	}
	state, err := loadAndroidScheduleState(schedulerState, application.PlanScope)
	if err != nil {
		return nil, err
	}
	if application.Blocked {
		return androidRouteTickResult(state, application, false, application.BlockReason, "", nil)
	}

	actual, err := loadAndroidActualSelections(actualSelections, application.PlanScope, plan, application)
	if err != nil {
		return nil, err
	}
	for index := range application.Selectors {
		selection := &application.Selectors[index]
		candidate := findAndroidSelectorCandidate(plan.Selectors, selection.Selector, actual[selection.Selector])
		if candidate == nil {
			return nil, fmt.Errorf("selector %q actual candidate is outside the signed plan", selection.Selector)
		}
		selection.Candidate = candidate.Tag
		selection.Chain = append([]string(nil), candidate.Chain...)
	}

	state, observationWarning := updateAndroidObservationState(state, plan, observationResponse, ca, now)
	observations, err := androidClientEvidence(state, plan)
	if err != nil {
		return nil, err
	}
	inputs, err := loadAndroidRoutingInputs(routingInputs, plan)
	if err != nil {
		return nil, err
	}
	entries, err := loadAndroidEntryMeasurements(entryMeasurements, inputs, now)
	if err != nil {
		return nil, err
	}

	changed := false
	decisions := make([]androidRouteDecision, 0, len(plan.Declarations))
	for _, declared := range plan.Declarations {
		declaration := clientroute.Declaration{
			ID: declared.ID, Selector: declared.Selector, Objective: declared.Objective,
			Targets: append([]string(nil), declared.Targets...), SwitchThreshold: declared.SwitchThreshold,
		}
		declaration.Candidates = filterAndroidClientCandidates(declared.Candidates, application.Mode, application.Exit)
		if len(declaration.Candidates) == 0 {
			return nil, fmt.Errorf("declaration %q has no candidate allowed by the active preference", declaration.ID)
		}
		current := actual[declaration.Selector]
		if !clientCandidateContains(declaration.Candidates, current) {
			return nil, fmt.Errorf("selector %q actual candidate is outside the active preference", declaration.Selector)
		}
		selection, err := clientroute.Decide(declaration, current, entries, observations, inputs.HopCarriers, now)
		if err != nil {
			return nil, err
		}
		updatedAt := now.Format(time.RFC3339)
		decision := androidRouteDecision{
			Declaration: declaration.ID,
			Selector:    declaration.Selector,
			Current:     current,
			Choice:      selection.Candidate,
			Switch:      selection.Candidate != current,
			Chain:       append([]string(nil), selection.Chain...),
			Reason:      selection.Reason,
			UpdatedAt:   updatedAt,
			Candidates:  len(declaration.Candidates),
			Measurements: androidPathMeasurements(
				plan.Node,
				clientroute.Candidate{Tag: selection.Candidate, Chain: selection.Chain},
				declared.Targets,
				inputs.HopCarriers[selection.Candidate],
				entries,
				observations,
				now,
			),
		}
		decisions = append(decisions, decision)
		if decision.Switch {
			changed = true
			for index := range application.Selectors {
				if application.Selectors[index].Selector == decision.Selector {
					application.Selectors[index].Candidate = decision.Choice
					application.Selectors[index].Chain = append([]string(nil), decision.Chain...)
					break
				}
			}
		}
	}
	detail := "当前计划没有可自动重算的声明"
	if len(decisions) > 0 {
		detail = decisions[0].Reason
		for _, decision := range decisions {
			if decision.Switch {
				detail = decision.Declaration + "：" + decision.Reason
				break
			}
		}
	}
	return androidRouteTickResult(state, application, changed, detail, observationWarning, decisions)
}

func androidPathMeasurements(client string, candidate clientroute.Candidate, targets, carriers []string,
	entries map[string]clientroute.EntryResult, evidence clientroute.Evidence, now time.Time) []androidPathMeasurement {
	if len(candidate.Chain) == 0 {
		return nil
	}
	out := make([]androidPathMeasurement, 0, len(candidate.Chain)+len(targets))
	entry := androidPathMeasurement{Hop: 0, From: client, To: candidate.Chain[0], Kind: "entry"}
	if value, ok := entries[candidate.Chain[0]]; ok {
		entry.ObservedAt, entry.Samples = value.At.UTC().Format(time.RFC3339), 1
		if value.Err != nil {
			entry.Failures, entry.Error = 1, value.Err.Error()
		} else {
			ms := value.RTT.Milliseconds()
			entry.DelayMS = &ms
		}
	}
	out = append(out, entry)
	fresh := func(raw string) bool {
		at, err := time.Parse(time.RFC3339, raw)
		return err == nil && now.Sub(at) <= evidence.MaxAge && !at.After(now.Add(2*time.Minute))
	}
	for index, node := range candidate.Chain {
		value, ok := evidence.ByNode[node]
		valid := ok && fresh(value.TS)
		if index+1 == len(candidate.Chain) {
			for _, target := range targets {
				measurement := androidPathMeasurement{Hop: index + 1, From: node, To: target, Kind: "target"}
				if valid {
					for _, reach := range value.Targets {
						if !clientroute.EquivalentTargetURL(reach.Target, target) || reach.Samples <= 0 {
							continue
						}
						measurement.ObservedAt, measurement.Samples, measurement.Failures, measurement.Error =
							value.TS, int64(reach.Samples), int64(reach.Failures), reach.Error
						if reach.Samples > reach.Failures {
							ms := int64(reach.FirstByteMs)
							measurement.DelayMS = &ms
						}
						break
					}
				}
				out = append(out, measurement)
			}
			continue
		}
		measurement := androidPathMeasurement{Hop: index + 1, From: node, To: candidate.Chain[index+1], Kind: "unknown"}
		if index < len(carriers) {
			measurement.Kind = carriers[index]
		}
		if valid && measurement.Kind == "neighbor" {
			for _, edge := range value.Edges {
				if edge.To != measurement.To || edge.Samples <= 0 {
					continue
				}
				measurement.ObservedAt, measurement.Samples, measurement.Failures, measurement.Error =
					value.TS, int64(edge.Samples), int64(edge.Failures), edge.Error
				if edge.Samples > edge.Failures {
					ms := int64(edge.RTTMs)
					measurement.DelayMS = &ms
				}
				break
			}
		}
		if valid && measurement.Kind == "public-hysteria2" && value.LinkMetrics != nil {
			for _, metric := range value.LinkMetrics.Metrics {
				if metric.PeerNode != measurement.To || metric.Transport != attest.LinkMetricTransportHysteria2 ||
					metric.Carrier != attest.LinkMetricCarrierPublic || metric.Scope != attest.LinkMetricScopeSingleHop ||
					!fresh(metric.ObservedAt) || metric.Samples <= 0 {
					continue
				}
				measurement.ObservedAt, measurement.Samples, measurement.Failures, measurement.Error =
					metric.ObservedAt, metric.Samples, metric.Failures, metric.Error
				if metric.Samples > metric.Failures {
					ms := metric.RTTMS
					measurement.DelayMS = &ms
					if metric.Samples-metric.Failures >= 2 && metric.P95MS >= metric.P50MS {
						variation := metric.P95MS - metric.P50MS
						measurement.VariationMS = &variation
					}
					if metric.TransferBytes > 0 && metric.TransferDurationMS > 0 {
						rate := float64(metric.TransferBytes) * 8000 / float64(metric.TransferDurationMS)
						measurement.RateBPS = &rate
					}
				}
				break
			}
		}
		out = append(out, measurement)
	}
	return out
}

func androidRouteTickResult(state androidScheduleState, application androidRouteApplication, changed bool,
	detail, observationWarning string, decisions []androidRouteDecision) ([]byte, error) {
	stateBody, err := marshalCanonical(&state)
	if err != nil {
		return nil, err
	}
	if len(stateBody) > androidObservationLimit {
		return nil, errors.New("Android observation state exceeds the protected storage limit")
	}
	return marshalCanonical(&androidRouteTick{
		Schema: 2, State: string(stateBody), Application: application, Changed: changed,
		NextAfterMS: androidIdleScheduleWait.Milliseconds(), Detail: detail,
		ObservationError: observationWarning, Decisions: decisions,
	})
}

func loadAndroidScheduleState(body []byte, planScope string) (androidScheduleState, error) {
	state := androidScheduleState{Schema: 2, PlanScope: planScope}
	if len(body) == 0 {
		return state, nil
	}
	if len(body) > androidObservationLimit {
		return state, errors.New("saved Android observation state exceeds the size limit")
	}
	var header struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(body, &header); err != nil {
		return state, fmt.Errorf("saved Android observation state JSON: %w", err)
	}
	if header.Schema == 1 {
		return state, nil
	}
	var persisted androidScheduleState
	if err := decodeStrictJSON(body, androidObservationLimit, &persisted); err != nil {
		return state, fmt.Errorf("saved Android observation state JSON: %w", err)
	}
	if persisted.Schema != 2 || !validLowerHex(persisted.PlanScope, 64) {
		return state, errors.New("saved Android observation state has an invalid schema or scope")
	}
	if persisted.PlanScope != planScope {
		return state, nil
	}
	if len(persisted.Observations) > androidMaxObservationSet {
		return state, errors.New("saved Android observation state has too many sources")
	}
	return persisted, nil
}

func updateAndroidObservationState(state androidScheduleState, plan androidRoutePlan, response, ca []byte,
	now time.Time) (androidScheduleState, string) {
	allowed := map[string]bool{}
	for _, declaration := range plan.Declarations {
		for _, candidate := range declaration.Candidates {
			for _, node := range candidate.Chain {
				if node != plan.Node {
					allowed[node] = true
				}
			}
		}
	}
	maxAge := 10 * time.Minute
	if plan.ObservationStale != "" {
		if parsed, err := time.ParseDuration(plan.ObservationStale); err == nil {
			maxAge = parsed
		}
	}
	type accepted struct {
		at  time.Time
		raw json.RawMessage
	}
	byNode := map[string]accepted{}
	rejected := 0
	ingest := func(values []json.RawMessage) {
		for _, raw := range values {
			var observation trustedobservation.Observation
			if len(raw) > androidObservationLimit || json.Unmarshal(raw, &observation) != nil || !allowed[observation.Node] {
				rejected++
				continue
			}
			verified, err := trustedobservation.VerifyObservationAtLeast(&observation, ca, now, maxAge, 5)
			if err != nil || !verified.MeasurementsVerified || trustedobservation.VerifyAttachments(&observation, ca, now, maxAge) != nil {
				rejected++
				continue
			}
			at, err := time.Parse(time.RFC3339, observation.TS)
			if err != nil {
				rejected++
				continue
			}
			canonical, err := json.Marshal(&observation)
			if err != nil {
				rejected++
				continue
			}
			if old, ok := byNode[observation.Node]; !ok || at.After(old.at) {
				byNode[observation.Node] = accepted{at: at, raw: canonical}
			}
		}
	}
	ingest(state.Observations)
	warning := ""
	if len(response) > 0 {
		var latest []json.RawMessage
		if len(response) > androidObservationLimit || json.Unmarshal(response, &latest) != nil || len(latest) > androidMaxObservationSet {
			warning = "服务器观测正文无效；本次上报已接受，继续使用仍新鲜的既有证据"
		} else {
			ingest(latest)
		}
	}
	keys := sortedKeys(byNode)
	state.Observations = state.Observations[:0]
	for _, node := range keys {
		state.Observations = append(state.Observations, byNode[node].raw)
	}
	if rejected > 0 {
		warning = fmt.Sprintf("已拒绝 %d 份范围、签名或新鲜度无效的服务器观测", rejected)
	}
	return state, warning
}

func androidClientEvidence(state androidScheduleState, plan androidRoutePlan) (clientroute.Evidence, error) {
	maxAge := 10 * time.Minute
	if plan.ObservationStale != "" {
		parsed, err := time.ParseDuration(plan.ObservationStale)
		if err != nil {
			return clientroute.Evidence{}, err
		}
		maxAge = parsed
	}
	evidence := clientroute.Evidence{ByNode: map[string]trustedobservation.Observation{}, MaxAge: maxAge}
	for _, raw := range state.Observations {
		var value trustedobservation.Observation
		if err := json.Unmarshal(raw, &value); err != nil {
			return clientroute.Evidence{}, errors.New("verified Android observation state cannot be decoded")
		}
		evidence.ByNode[value.Node] = value
	}
	return evidence, nil
}

func loadAndroidActualSelections(body []byte, planScope string, plan androidRoutePlan,
	application androidRouteApplication) (map[string]string, error) {
	if len(body) == 0 {
		return nil, errors.New("actual selector readback is required")
	}
	var values androidSavedSelections
	if err := decodeStrictJSON(body, maxCurrentBytes, &values); err != nil {
		return nil, fmt.Errorf("actual selector readback JSON: %w", err)
	}
	if values.Schema != 1 || values.PlanScope != planScope {
		return nil, errors.New("actual selector readback does not match the active plan")
	}
	wanted := make(map[string]bool, len(application.Selectors))
	for _, selection := range application.Selectors {
		wanted[selection.Selector] = true
	}
	out := map[string]string{}
	for _, selection := range values.Selections {
		if !wanted[selection.Selector] || out[selection.Selector] != "" ||
			findAndroidSelectorCandidate(plan.Selectors, selection.Selector, selection.Candidate) == nil {
			return nil, errors.New("actual selector readback contains an unknown or duplicate candidate")
		}
		out[selection.Selector] = selection.Candidate
	}
	if len(out) != len(wanted) {
		return nil, errors.New("actual selector readback is incomplete")
	}
	return out, nil
}

func loadAndroidRoutingInputs(body []byte, plan androidRoutePlan) (androidRoutingInputs, error) {
	var inputs androidRoutingInputs
	if err := decodeStrictJSON(body, maxBundleBytes, &inputs); err != nil {
		return inputs, fmt.Errorf("Android routing inputs JSON: %w", err)
	}
	if inputs.Schema != 1 || inputs.HopCarriers == nil {
		return inputs, errors.New("Android routing inputs are incomplete")
	}
	allowedEntries := map[string]bool{}
	allowedCandidates := map[string]int{}
	for _, declaration := range plan.Declarations {
		for _, candidate := range declaration.Candidates {
			allowedCandidates[candidate.Tag] = max(0, len(candidate.Chain)-1)
			if len(candidate.Chain) > 0 {
				allowedEntries[candidate.Chain[0]] = true
			}
		}
	}
	seen := map[string]bool{}
	for _, entry := range inputs.Entries {
		if !allowedEntries[entry.Node] || entry.Address == "" || len(entry.Address) > 253 ||
			strings.TrimSpace(entry.Address) != entry.Address || strings.ContainsAny(entry.Address, "\r\n\x00") || seen[entry.Node] {
			return inputs, errors.New("Android routing inputs contain an invalid entry")
		}
		seen[entry.Node] = true
	}
	if len(seen) != len(allowedEntries) {
		return inputs, errors.New("Android routing inputs do not cover every authorized entry")
	}
	for candidate, count := range allowedCandidates {
		carriers, ok := inputs.HopCarriers[candidate]
		if !ok || len(carriers) != count {
			return inputs, errors.New("Android routing inputs do not match the signed candidate chains")
		}
		for _, carrier := range carriers {
			if carrier != "neighbor" && carrier != "public-hysteria2" && carrier != "unknown" {
				return inputs, errors.New("Android routing inputs contain an unknown hop carrier")
			}
		}
	}
	if len(inputs.HopCarriers) != len(allowedCandidates) {
		return inputs, errors.New("Android routing inputs contain an extra candidate")
	}
	return inputs, nil
}

func loadAndroidEntryMeasurements(body []byte, inputs androidRoutingInputs, now time.Time) (map[string]clientroute.EntryResult, error) {
	entries := map[string]string{}
	for _, entry := range inputs.Entries {
		entries[entry.Node] = entry.Address
	}
	out := map[string]clientroute.EntryResult{}
	seen := map[string]bool{}
	if len(body) == 0 {
		return out, nil
	}
	var measurements androidEntryMeasurements
	if err := decodeStrictJSON(body, maxCurrentBytes, &measurements); err != nil {
		return nil, fmt.Errorf("Android entry measurements JSON: %w", err)
	}
	if measurements.Schema != 1 || len(measurements.Source) > 128 || strings.ContainsAny(measurements.Source, "\r\n\x00") {
		return nil, errors.New("Android entry measurements have an invalid schema or source")
	}
	for _, measurement := range measurements.Measurements {
		at, err := time.Parse(time.RFC3339, measurement.TS)
		if entries[measurement.Node] != measurement.Address || seen[measurement.Node] || err != nil ||
			at.After(now.Add(2*time.Minute)) || measurement.RTTMS < 0 || len(measurement.Error) > androidEntryErrorLimit ||
			strings.ContainsAny(measurement.Error, "\r\n\x00") || (measurement.Error != "" && measurement.RTTMS != 0) {
			return nil, errors.New("Android entry measurements contain an invalid or unauthorized result")
		}
		seen[measurement.Node] = true
		result := clientroute.EntryResult{RTT: time.Duration(measurement.RTTMS) * time.Millisecond, At: at.UTC()}
		if measurement.Error != "" {
			result.Err = errors.New(measurement.Error)
		}
		out[measurement.Node] = result
	}
	return out, nil
}

func filterAndroidClientCandidates(candidates []androidRouteCandidate, mode, exit string) []clientroute.Candidate {
	out := make([]clientroute.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		eligible := mode == androidRouteModeAuto ||
			(mode == androidRouteModeDirect && len(candidate.Chain) == 0) ||
			(mode == androidRouteModeFixed && len(candidate.Chain) > 0 && candidate.Chain[len(candidate.Chain)-1] == exit)
		if eligible {
			out = append(out, clientroute.Candidate{Tag: candidate.Tag, Chain: append([]string(nil), candidate.Chain...)})
		}
	}
	return out
}

func findAndroidSelectorCandidate(selectors []androidSelectorPlan, selector, candidate string) *androidRouteCandidate {
	for _, plan := range selectors {
		if plan.Selector == selector {
			for index := range plan.Candidates {
				if plan.Candidates[index].Tag == candidate {
					return &plan.Candidates[index]
				}
			}
		}
	}
	return nil
}

func clientCandidateContains(candidates []clientroute.Candidate, wanted string) bool {
	for _, candidate := range candidates {
		if candidate.Tag == wanted {
			return true
		}
	}
	return false
}
