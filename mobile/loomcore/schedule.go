package loomcore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

const (
	androidProbeTimeout     = 8 * time.Second
	androidMinThroughput    = 32 << 10
	androidMaxProbeBytes    = 256 << 10
	androidMaxMeasurements  = 384
	androidIdleScheduleWait = 5 * time.Minute
)

type androidScheduleState struct {
	Schema       int                       `json:"schema"`
	PlanScope    string                    `json:"plan_scope"`
	LastRuns     []androidLastRun          `json:"last_runs,omitempty"`
	NextProbes   []androidNextProbe        `json:"next_probes,omitempty"`
	Measurements []androidRouteMeasurement `json:"measurements,omitempty"`
}

type androidLastRun struct {
	Declaration string `json:"declaration"`
	TS          string `json:"ts"`
}

type androidNextProbe struct {
	Declaration string `json:"declaration"`
	Candidate   string `json:"candidate"`
}

type androidRouteMeasurement struct {
	TS            string `json:"ts"`
	DecisionScope string `json:"decision_scope"`
	Declaration   string `json:"declaration"`
	Candidate     string `json:"candidate"`
	Target        string `json:"target"`
	FirstByteMS   int    `json:"first_byte_ms,omitempty"`
	KBps          int    `json:"kbps,omitempty"`
	Error         string `json:"error,omitempty"`
}

type androidRouteTick struct {
	Schema      int                     `json:"schema"`
	State       string                  `json:"state"`
	Application androidRouteApplication `json:"application"`
	Changed     bool                    `json:"changed"`
	NextAfterMS int64                   `json:"next_after_ms"`
	Detail      string                  `json:"detail"`
	Decisions   []androidRouteDecision  `json:"decisions,omitempty"`
}

type androidRouteDecision struct {
	Declaration string `json:"declaration"`
	Selector    string `json:"selector"`
	Current     string `json:"current"`
	Choice      string `json:"choice"`
	Switch      bool   `json:"switch"`
	Reason      string `json:"reason"`
	Probed      int    `json:"probed"`
	Skipped     int    `json:"skipped,omitempty"`
}

type androidRouteSummary struct {
	Candidate string
	Samples   int
	Failures  int
	P50       int
	P95       int
	KBps      int
}

type androidRouteRank struct {
	tier  int
	score float64
}

// RunAndroidRouteTick executes at most one due round per signed declaration.
// Probes are deliberately serial so candidates do not distort each other's
// latency on a mobile uplink. The returned state must be committed only after
// the returned selector application has been applied successfully.
func RunAndroidRouteTick(routePlan, preference, savedSelections, schedulerState []byte, nowRFC3339 string) ([]byte, error) {
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
	if application.Blocked {
		return androidRouteTickResult(androidScheduleState{Schema: 1, PlanScope: application.PlanScope}, application,
			false, androidIdleScheduleWait, application.BlockReason, nil)
	}

	state, err := loadAndroidScheduleState(schedulerState, application.PlanScope, plan, now)
	if err != nil {
		return nil, err
	}
	if application.Mode == androidRouteModeDirect {
		return androidRouteTickResult(state, application, false, androidIdleScheduleWait,
			"Direct 模式不执行候选探测", nil)
	}
	if len(plan.Declarations) == 0 {
		return androidRouteTickResult(state, application, false, androidIdleScheduleWait,
			"当前签名计划没有可自动调度的声明", nil)
	}

	current := make(map[string]string, len(application.Selectors))
	for _, selection := range application.Selectors {
		current[selection.Selector] = selection.Candidate
	}
	lastRuns := androidLastRunMap(state.LastRuns)
	nextProbes := androidNextProbeMap(state.NextProbes)
	var decisions []androidRouteDecision
	changed := false
	for index := range plan.Declarations {
		declaration := plan.Declarations[index]
		period, _ := time.ParseDuration(declaration.TuningPeriod)
		if last, ok := lastRuns[declaration.ID]; ok && now.Before(last.Add(period)) {
			continue
		}
		eligible := eligibleAndroidCandidates(declaration.Candidates, application.Mode, application.Exit)
		if len(eligible) == 0 {
			return nil, fmt.Errorf("declaration %q has no candidate allowed by the active preference", declaration.ID)
		}
		selected := current[declaration.Selector]
		if !androidCandidateContains(eligible, selected) {
			return nil, fmt.Errorf("selector %q current candidate is outside the active preference", declaration.Selector)
		}
		scope := androidDecisionScope(plan.Node, declaration, application.Mode, application.Exit, eligible)
		probe, next, skipped := pickAndroidProbeCandidates(eligible, selected, declaration.ProbeBudget, nextProbes[declaration.ID])
		nextProbes[declaration.ID] = next
		for _, candidate := range probe {
			for _, target := range declaration.Targets {
				measurement := androidRouteMeasurement{
					TS: now.Format(time.RFC3339), DecisionScope: scope, Declaration: declaration.ID,
					Candidate: candidate.Tag, Target: target,
				}
				result, probeErr := probeAndroidCandidate(plan.Probe, plan.ProbeSecret, candidate.ProbeUser, target, androidProbeTimeout)
				if probeErr != nil {
					measurement.Error = boundedAndroidProbeError(probeErr)
				} else {
					measurement.FirstByteMS = result.firstByteMS
					measurement.KBps = result.kbps
				}
				state.Measurements = append(state.Measurements, measurement)
			}
		}
		lastRuns[declaration.ID] = now
		window, _ := time.ParseDuration(declaration.Window)
		stale, _ := time.ParseDuration(declaration.StaleAfter)
		summaries := summarizeAndroidRoute(inAndroidWindow(state.Measurements, declaration.ID, scope, now, window, stale))
		decision := decideAndroidRoute(declaration, eligible, selected, summaries)
		decision.Probed = len(probe)
		decision.Skipped = skipped
		decisions = append(decisions, decision)
		if decision.Switch {
			for selectionIndex := range application.Selectors {
				selection := &application.Selectors[selectionIndex]
				if selection.Selector != declaration.Selector {
					continue
				}
				candidate := findAndroidCandidate(eligible, decision.Choice)
				if candidate == nil {
					return nil, fmt.Errorf("decision selected an unknown candidate %q", decision.Choice)
				}
				selection.Candidate = candidate.Tag
				selection.Chain = append([]string(nil), candidate.Chain...)
				current[selection.Selector] = candidate.Tag
				changed = true
				break
			}
		}
	}
	state.LastRuns = encodeAndroidLastRuns(lastRuns)
	state.NextProbes = encodeAndroidNextProbes(nextProbes)
	state.Measurements = trimAndroidMeasurements(state.Measurements, now)
	nextWait := nextAndroidScheduleWait(plan.Declarations, lastRuns, now)
	detail := "尚未到下一轮候选测量时间"
	if len(decisions) > 0 {
		detail = fmt.Sprintf("%s：%s", decisions[0].Declaration, decisions[0].Reason)
		for _, decision := range decisions[1:] {
			if decision.Switch {
				detail = fmt.Sprintf("%s：%s", decision.Declaration, decision.Reason)
				break
			}
		}
	}
	return androidRouteTickResult(state, application, changed, nextWait, detail, decisions)
}

func androidRouteTickResult(state androidScheduleState, application androidRouteApplication, changed bool,
	next time.Duration, detail string, decisions []androidRouteDecision) ([]byte, error) {
	if next < time.Second {
		next = time.Second
	}
	stateBody, err := marshalCanonical(&state)
	if err != nil {
		return nil, err
	}
	if len(stateBody) > maxCurrentBytes {
		return nil, fmt.Errorf("scheduler state exceeds the protected storage limit")
	}
	return marshalCanonical(&androidRouteTick{
		Schema: 1, State: string(stateBody), Application: application, Changed: changed,
		NextAfterMS: next.Milliseconds(), Detail: detail, Decisions: decisions,
	})
}

func loadAndroidScheduleState(body []byte, planScope string, plan androidRoutePlan, now time.Time) (androidScheduleState, error) {
	state := androidScheduleState{Schema: 1, PlanScope: planScope}
	if len(body) == 0 {
		return state, nil
	}
	var persisted androidScheduleState
	if err := decodeStrictJSON(body, maxCurrentBytes, &persisted); err != nil {
		return state, fmt.Errorf("saved scheduler state JSON: %w", err)
	}
	if persisted.Schema != 1 || !validLowerHex(persisted.PlanScope, 64) {
		return state, fmt.Errorf("saved scheduler state has an invalid schema or scope")
	}
	if persisted.PlanScope != planScope {
		return state, nil
	}
	declarations := make(map[string]androidRouteDeclaration, len(plan.Declarations))
	for _, declaration := range plan.Declarations {
		declarations[declaration.ID] = declaration
	}
	seenRuns := map[string]bool{}
	for _, run := range persisted.LastRuns {
		parsed, parseErr := time.Parse(time.RFC3339, run.TS)
		if declarations[run.Declaration].ID == "" || parseErr != nil || parsed.After(now.Add(2*time.Minute)) || seenRuns[run.Declaration] {
			return state, fmt.Errorf("saved scheduler state contains an invalid last run")
		}
		seenRuns[run.Declaration] = true
	}
	seenNext := map[string]bool{}
	for _, cursor := range persisted.NextProbes {
		declaration := declarations[cursor.Declaration]
		if declaration.ID == "" || !androidCandidateContains(declaration.Candidates, cursor.Candidate) || seenNext[cursor.Declaration] {
			return state, fmt.Errorf("saved scheduler state contains an invalid probe cursor")
		}
		seenNext[cursor.Declaration] = true
	}
	if len(persisted.Measurements) > androidMaxMeasurements {
		return state, fmt.Errorf("saved scheduler state contains too many measurements")
	}
	for _, measurement := range persisted.Measurements {
		declaration := declarations[measurement.Declaration]
		ts, parseErr := time.Parse(time.RFC3339, measurement.TS)
		if declaration.ID == "" || parseErr != nil || ts.After(now.Add(2*time.Minute)) ||
			!validLowerHex(measurement.DecisionScope, 64) || !androidCandidateContains(declaration.Candidates, measurement.Candidate) ||
			!containsUnsorted(declaration.Targets, measurement.Target) || measurement.FirstByteMS < 0 || measurement.KBps < 0 ||
			(measurement.Error != "" && (measurement.FirstByteMS != 0 || measurement.KBps != 0)) {
			return state, fmt.Errorf("saved scheduler state contains an invalid measurement")
		}
	}
	return persisted, nil
}

type androidProbeResult struct {
	firstByteMS int
	kbps        int
}

func probeAndroidCandidate(probeAddr, secret, probeUser, target string, timeout time.Duration) (androidProbeResult, error) {
	proxyURL := &url.URL{Scheme: "http", User: url.UserPassword(probeUser, secret), Host: probeAddr}
	client := &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true, TLSHandshakeTimeout: timeout},
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return androidProbeResult{}, err
	}
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return androidProbeResult{}, err
	}
	defer response.Body.Close()
	firstByte := int(time.Since(start).Milliseconds())
	if response.StatusCode == http.StatusProxyAuthRequired || response.StatusCode >= 500 {
		return androidProbeResult{}, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, androidMaxProbeBytes))
	totalMS := int(time.Since(start).Milliseconds())
	result := androidProbeResult{firstByteMS: firstByte}
	if readErr == nil && read >= androidMinThroughput && totalMS > 0 {
		result.kbps = int(read) * 1000 / totalMS / 1024
	}
	return result, nil
}

func eligibleAndroidCandidates(candidates []androidRouteCandidate, mode, exit string) []androidRouteCandidate {
	out := make([]androidRouteCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		eligible := mode == androidRouteModeAuto ||
			(mode == androidRouteModeDirect && len(candidate.Chain) == 0) ||
			(mode == androidRouteModeFixed && len(candidate.Chain) > 0 && candidate.Chain[len(candidate.Chain)-1] == exit)
		if eligible {
			out = append(out, candidate)
		}
	}
	return out
}

func androidDecisionScope(node string, declaration androidRouteDeclaration, mode, exit string,
	candidates []androidRouteCandidate) string {
	hash := sha256.New()
	field := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	duration := func(raw string) string {
		if parsed, err := time.ParseDuration(raw); err == nil {
			return parsed.String()
		}
		return raw
	}
	field("loom-android-decision-scope-v1")
	field(node)
	field(declaration.ID)
	field(declaration.Selector)
	field(declaration.Objective)
	field(mode)
	field(exit)
	field(duration(declaration.TuningPeriod))
	field(strconv.FormatFloat(declaration.SwitchThreshold, 'g', -1, 64))
	field(duration(declaration.Window))
	field(strconv.Itoa(declaration.MinSamples))
	field(duration(declaration.StaleAfter))
	field(strconv.Itoa(declaration.ProbeBudget))
	targets := append([]string(nil), declaration.Targets...)
	sort.Strings(targets)
	field(strconv.Itoa(len(targets)))
	for _, target := range targets {
		field(target)
	}
	ordered := append([]androidRouteCandidate(nil), candidates...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Tag < ordered[j].Tag })
	field(strconv.Itoa(len(ordered)))
	for _, candidate := range ordered {
		field(candidate.Tag)
		field(strconv.Itoa(len(candidate.Chain)))
		for _, nodeID := range candidate.Chain {
			field(nodeID)
		}
		field(candidate.ProbeUser)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func pickAndroidProbeCandidates(candidates []androidRouteCandidate, current string, budget int,
	nextTag string) ([]androidRouteCandidate, string, int) {
	probe := append([]androidRouteCandidate(nil), candidates...)
	sort.Slice(probe, func(i, j int) bool { return probe[i].Tag < probe[j].Tag })
	if budget <= 0 || len(probe) <= budget {
		return probe, nextTag, 0
	}
	selected := make([]androidRouteCandidate, 0, budget)
	others := make([]androidRouteCandidate, 0, len(probe))
	for _, candidate := range probe {
		if candidate.Tag == current {
			selected = append(selected, candidate)
		} else {
			others = append(others, candidate)
		}
	}
	slots := budget - len(selected)
	if slots < 0 {
		slots = 0
	}
	if slots > len(others) {
		slots = len(others)
	}
	start := 0
	if nextTag != "" && len(others) > 0 {
		start = sort.Search(len(others), func(index int) bool { return others[index].Tag >= nextTag })
		if start == len(others) {
			start = 0
		}
	}
	for index := 0; index < slots; index++ {
		selected = append(selected, others[(start+index)%len(others)])
	}
	if slots > 0 {
		nextTag = others[(start+slots)%len(others)].Tag
	}
	return selected, nextTag, len(probe) - len(selected)
}

func inAndroidWindow(measurements []androidRouteMeasurement, declaration, scope string, now time.Time,
	window, stale time.Duration) []androidRouteMeasurement {
	cut := now.Add(-window)
	staleCut := now.Add(-stale)
	futureCut := now.Add(2 * time.Minute)
	newest := map[string]time.Time{}
	parsed := make([]time.Time, len(measurements))
	for index, measurement := range measurements {
		ts, err := time.Parse(time.RFC3339, measurement.TS)
		if err != nil || ts.After(futureCut) {
			continue
		}
		parsed[index] = ts
		if measurement.Declaration == declaration && measurement.DecisionScope == scope && ts.After(newest[measurement.Candidate]) {
			newest[measurement.Candidate] = ts
		}
	}
	var out []androidRouteMeasurement
	for index, measurement := range measurements {
		if measurement.Declaration != declaration || measurement.DecisionScope != scope || parsed[index].IsZero() || parsed[index].Before(cut) ||
			newest[measurement.Candidate].Before(staleCut) {
			continue
		}
		out = append(out, measurement)
	}
	return out
}

func summarizeAndroidRoute(measurements []androidRouteMeasurement) []androidRouteSummary {
	type accumulator struct {
		latency []int
		speed   []int
		failed  int
	}
	values := map[string]*accumulator{}
	for _, measurement := range measurements {
		entry := values[measurement.Candidate]
		if entry == nil {
			entry = &accumulator{}
			values[measurement.Candidate] = entry
		}
		if measurement.Error != "" {
			entry.failed++
			continue
		}
		entry.latency = append(entry.latency, measurement.FirstByteMS)
		if measurement.KBps > 0 {
			entry.speed = append(entry.speed, measurement.KBps)
		}
	}
	keys := sortedKeys(values)
	out := make([]androidRouteSummary, 0, len(keys))
	for _, candidate := range keys {
		entry := values[candidate]
		sort.Ints(entry.latency)
		sort.Ints(entry.speed)
		summary := androidRouteSummary{Candidate: candidate, Samples: len(entry.latency) + entry.failed, Failures: entry.failed}
		if len(entry.latency) > 0 {
			summary.P50 = androidPercentile(entry.latency, 50)
			summary.P95 = androidPercentile(entry.latency, 95)
		}
		if len(entry.speed) > 0 {
			summary.KBps = entry.speed[len(entry.speed)/2]
		}
		out = append(out, summary)
	}
	return out
}

func decideAndroidRoute(declaration androidRouteDeclaration, candidates []androidRouteCandidate, current string,
	summaries []androidRouteSummary) androidRouteDecision {
	decision := androidRouteDecision{Declaration: declaration.ID, Selector: declaration.Selector, Current: current, Choice: current}
	inSet := map[string]bool{}
	for _, candidate := range candidates {
		inSet[candidate.Tag] = true
	}
	byCandidate := map[string]androidRouteSummary{}
	var healthy []androidRouteSummary
	for _, summary := range summaries {
		if !inSet[summary.Candidate] {
			continue
		}
		byCandidate[summary.Candidate] = summary
		if summary.Samples > summary.Failures {
			healthy = append(healthy, summary)
		}
	}
	if len(healthy) == 0 {
		decision.Reason = "窗口内没有任何候选成功过，保持不动"
		return decision
	}
	if declaration.Objective == "throughput" {
		measured := false
		for _, summary := range healthy {
			measured = measured || summary.KBps > 0
		}
		if !measured {
			decision.Reason = "没有候选测出足够的吞吐数据，保持不动"
			return decision
		}
	}
	sort.Slice(healthy, func(i, j int) bool {
		left, right := rankAndroidRoute(declaration.Objective, healthy[i]), rankAndroidRoute(declaration.Objective, healthy[j])
		if left != right {
			return left.less(right)
		}
		return healthy[i].Candidate < healthy[j].Candidate
	})
	currentSummary, hasCurrent := byCandidate[current]
	if hasCurrent && currentSummary.Samples > 0 && currentSummary.Failures == currentSummary.Samples {
		decision.Choice, decision.Switch = healthy[0].Candidate, true
		decision.Reason = fmt.Sprintf("当前候选全部失败，切到 %s", healthy[0].Candidate)
		return decision
	}
	if !hasCurrent {
		decision.Choice, decision.Switch = healthy[0].Candidate, healthy[0].Candidate != current
		decision.Reason = fmt.Sprintf("当前候选没有窗口样本，选择 %s", healthy[0].Candidate)
		return decision
	}
	var qualified []androidRouteSummary
	for _, summary := range healthy {
		if summary.Samples >= declaration.MinSamples {
			qualified = append(qualified, summary)
		}
	}
	if len(qualified) == 0 {
		decision.Reason = fmt.Sprintf("没有候选达到 min_samples=%d，保持不动", declaration.MinSamples)
		return decision
	}
	best := qualified[0]
	if best.Candidate == current {
		decision.Reason = "当前候选仍是最优，保持不动"
		return decision
	}
	bestRank, currentRank := rankAndroidRoute(declaration.Objective, best), rankAndroidRoute(declaration.Objective, currentSummary)
	if bestRank.tier < currentRank.tier {
		decision.Choice, decision.Switch = best.Candidate, true
		decision.Reason = fmt.Sprintf("%s 的失败率更低，切换", best.Candidate)
		return decision
	}
	if currentRank.score <= 0 {
		decision.Reason = "当前候选没有可比较的指标，保持不动"
		return decision
	}
	gain := (currentRank.score - bestRank.score) / currentRank.score
	if gain <= declaration.SwitchThreshold {
		decision.Reason = fmt.Sprintf("最优候选仅改善 %.0f%%，未过 %.0f%% 阈值", gain*100, declaration.SwitchThreshold*100)
		return decision
	}
	decision.Choice, decision.Switch = best.Candidate, true
	decision.Reason = fmt.Sprintf("%s 改善 %.0f%%，超过 %.0f%% 阈值", best.Candidate, gain*100, declaration.SwitchThreshold*100)
	return decision
}

func rankAndroidRoute(objective string, summary androidRouteSummary) androidRouteRank {
	rank := androidRouteRank{score: float64(summary.P50)}
	if summary.Samples > 0 {
		rank.tier = summary.Failures * 10 / summary.Samples
	}
	switch objective {
	case "stability":
		rank.score = float64(summary.P95)
	case "throughput":
		if summary.KBps <= 0 {
			rank.score = 1e9
		} else {
			rank.score = 1e6 / float64(summary.KBps)
		}
	}
	return rank
}

func (rank androidRouteRank) less(other androidRouteRank) bool {
	if rank.tier != other.tier {
		return rank.tier < other.tier
	}
	return rank.score < other.score
}

func androidPercentile(sorted []int, percentile int) int {
	indexNumerator := (len(sorted) - 1) * percentile
	index := indexNumerator / 100
	if indexNumerator%100 != 0 {
		index++
	}
	return sorted[index]
}

func androidLastRunMap(values []androidLastRun) map[string]time.Time {
	out := make(map[string]time.Time, len(values))
	for _, value := range values {
		out[value.Declaration], _ = time.Parse(time.RFC3339, value.TS)
	}
	return out
}

func androidNextProbeMap(values []androidNextProbe) map[string]string {
	out := make(map[string]string, len(values))
	for _, value := range values {
		out[value.Declaration] = value.Candidate
	}
	return out
}

func encodeAndroidLastRuns(values map[string]time.Time) []androidLastRun {
	keys := sortedKeys(values)
	out := make([]androidLastRun, 0, len(keys))
	for _, declaration := range keys {
		out = append(out, androidLastRun{Declaration: declaration, TS: values[declaration].UTC().Format(time.RFC3339)})
	}
	return out
}

func encodeAndroidNextProbes(values map[string]string) []androidNextProbe {
	keys := sortedKeys(values)
	out := make([]androidNextProbe, 0, len(keys))
	for _, declaration := range keys {
		if values[declaration] != "" {
			out = append(out, androidNextProbe{Declaration: declaration, Candidate: values[declaration]})
		}
	}
	return out
}

func nextAndroidScheduleWait(declarations []androidRouteDeclaration, lastRuns map[string]time.Time, now time.Time) time.Duration {
	var next time.Duration
	for _, declaration := range declarations {
		period, _ := time.ParseDuration(declaration.TuningPeriod)
		last, ok := lastRuns[declaration.ID]
		if !ok {
			return time.Second
		}
		remaining := last.Add(period).Sub(now)
		if next == 0 || remaining < next {
			next = remaining
		}
	}
	if next == 0 {
		return androidIdleScheduleWait
	}
	return next
}

func trimAndroidMeasurements(values []androidRouteMeasurement, now time.Time) []androidRouteMeasurement {
	cut := now.Add(-24 * time.Hour)
	out := make([]androidRouteMeasurement, 0, len(values))
	for _, value := range values {
		ts, err := time.Parse(time.RFC3339, value.TS)
		if err == nil && !ts.Before(cut) {
			out = append(out, value)
		}
	}
	if len(out) > androidMaxMeasurements {
		out = append([]androidRouteMeasurement(nil), out[len(out)-androidMaxMeasurements:]...)
	}
	return out
}

func androidCandidateContains(candidates []androidRouteCandidate, wanted string) bool {
	return findAndroidCandidate(candidates, wanted) != nil
}

func findAndroidCandidate(candidates []androidRouteCandidate, wanted string) *androidRouteCandidate {
	for index := range candidates {
		if candidates[index].Tag == wanted {
			return &candidates[index]
		}
	}
	return nil
}

func containsUnsorted(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func boundedAndroidProbeError(err error) string {
	message := []rune(err.Error())
	if len(message) > 512 {
		message = append(message[:511], '…')
	}
	return string(message)
}
