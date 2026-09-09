package loomcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	androidRouteModeDirect = "direct"
	androidRouteModeAuto   = "auto"
	androidRouteModeFixed  = "fixed_exit"
)

type androidRouteCandidate struct {
	Tag       string   `json:"tag"`
	Chain     []string `json:"chain,omitempty"`
	ProbeUser string   `json:"probe_user"`
}

type androidSelectorPlan struct {
	Selector   string                  `json:"selector"`
	Default    string                  `json:"default"`
	Candidates []androidRouteCandidate `json:"candidates"`
}

type androidRouteDeclaration struct {
	ID              string                  `json:"id"`
	Selector        string                  `json:"selector"`
	Objective       string                  `json:"objective"`
	Targets         []string                `json:"targets"`
	TuningPeriod    string                  `json:"tuning_period"`
	SwitchThreshold float64                 `json:"switch_threshold"`
	Window          string                  `json:"window"`
	MinSamples      int                     `json:"min_samples"`
	StaleAfter      string                  `json:"stale_after"`
	ProbeBudget     int                     `json:"probe_budget,omitempty"`
	Candidates      []androidRouteCandidate `json:"candidates"`
}

type androidRoutePlan struct {
	Schema                int                       `json:"schema"`
	Node                  string                    `json:"node"`
	API                   string                    `json:"api"`
	APISecret             string                    `json:"api_secret"`
	Probe                 string                    `json:"probe"`
	ProbeSecret           string                    `json:"probe_secret"`
	Declarations          []androidRouteDeclaration `json:"declarations"`
	Selectors             []androidSelectorPlan     `json:"selectors"`
	Peers                 []json.RawMessage         `json:"peers,omitempty"`
	SelfReport            string                    `json:"self_report,omitempty"`
	PeerPeriod            string                    `json:"peer_period,omitempty"`
	ObservationStale      string                    `json:"observation_stale,omitempty"`
	AttestationMinVersion int                       `json:"attestation_min_version,omitempty"`
	AttestationCA         string                    `json:"attestation_ca,omitempty"`
}

type androidSingBox struct {
	Inbounds     []androidInbound   `json:"inbounds"`
	Outbounds    []androidOutbound  `json:"outbounds"`
	Route        androidRoute       `json:"route"`
	Experimental *androidExperiment `json:"experimental"`
}

type androidInbound struct {
	Type       string        `json:"type"`
	Tag        string        `json:"tag"`
	Listen     string        `json:"listen"`
	ListenPort int           `json:"listen_port"`
	Users      []androidUser `json:"users"`
}

type androidUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type androidOutbound struct {
	Type       string   `json:"type"`
	Tag        string   `json:"tag"`
	Outbounds  []string `json:"outbounds"`
	Default    string   `json:"default"`
	Server     string   `json:"server"`
	ServerPort int      `json:"server_port"`
	Detour     string   `json:"detour"`
}

type androidRoute struct {
	Rules []androidRule `json:"rules"`
}

type androidRule struct {
	Inbound  []string `json:"inbound"`
	AuthUser []string `json:"auth_user"`
	Outbound string   `json:"outbound"`
}

type androidExperiment struct {
	ClashAPI *androidClashAPI `json:"clash_api"`
}

type androidClashAPI struct {
	ExternalController string `json:"external_controller"`
	Secret             string `json:"secret"`
}

type androidRoutePreference struct {
	Schema int    `json:"schema"`
	Mode   string `json:"mode"`
	Exit   string `json:"exit,omitempty"`
}

type androidSavedSelections struct {
	Schema     int                     `json:"schema"`
	PlanScope  string                  `json:"plan_scope"`
	Selections []androidSavedSelection `json:"selections"`
}

type androidSavedSelection struct {
	Selector  string `json:"selector"`
	Candidate string `json:"candidate"`
}

type androidRouteApplication struct {
	Schema          int                       `json:"schema"`
	PlanScope       string                    `json:"plan_scope"`
	Mode            string                    `json:"mode"`
	Exit            string                    `json:"exit,omitempty"`
	Blocked         bool                      `json:"blocked"`
	BlockReason     string                    `json:"block_reason,omitempty"`
	DirectAvailable bool                      `json:"direct_available"`
	Exits           []string                  `json:"exits"`
	Selectors       []androidAppliedSelection `json:"selectors"`
}

type androidAppliedSelection struct {
	Selector  string   `json:"selector"`
	Candidate string   `json:"candidate"`
	Chain     []string `json:"chain,omitempty"`
}

type androidRoutingInputs struct {
	Schema      int                 `json:"schema"`
	Entries     []androidRouteEntry `json:"entries"`
	HopCarriers map[string][]string `json:"hop_carriers"`
}

type androidRouteEntry struct {
	Node    string `json:"node"`
	Address string `json:"address"`
}

// AndroidRoutingInputs 按 §5.1 从已验证 sing-box 数据面推导入口目标和服务器段承载。
// candidate tag 是不透明标识，Kotlin 不得按命名约定重建这些事实。
func AndroidRoutingInputs(singBox, routePlan []byte) ([]byte, error) {
	var plan androidRoutePlan
	if err := decodeStrictJSON(routePlan, maxBundleBytes, &plan); err != nil {
		return nil, fmt.Errorf("plan JSON: %w", err)
	}
	if err := validateAndroidRoutePlan(singBox, routePlan, plan.Node); err != nil {
		return nil, err
	}
	var config androidSingBox
	if err := json.Unmarshal(singBox, &config); err != nil {
		return nil, errors.New("sing-box routing input is invalid")
	}
	byTag := make(map[string]androidOutbound, len(config.Outbounds))
	for _, outbound := range config.Outbounds {
		if outbound.Tag != "" {
			if _, exists := byTag[outbound.Tag]; exists {
				return nil, errors.New("sing-box routing input contains duplicate outbound tags")
			}
			byTag[outbound.Tag] = outbound
		}
	}
	byNode := map[string]androidRouteEntry{}
	for _, declaration := range plan.Declarations {
		for _, candidate := range declaration.Candidates {
			if len(candidate.Chain) == 0 {
				continue
			}
			address, _, err := androidCandidateHops(candidate.Tag, byTag)
			if err != nil || address == "" {
				return nil, fmt.Errorf("candidate %q has no usable entry outbound", candidate.Tag)
			}
			node := candidate.Chain[0]
			if old, ok := byNode[node]; ok && old.Address != address {
				return nil, errors.New("one authorized entry maps to multiple addresses")
			}
			byNode[node] = androidRouteEntry{Node: node, Address: address}
		}
	}
	inputs := androidRoutingInputs{Schema: 1, HopCarriers: map[string][]string{}}
	for _, node := range sortedKeys(byNode) {
		inputs.Entries = append(inputs.Entries, byNode[node])
	}
	addresses := map[string]string{}
	for _, entry := range inputs.Entries {
		addresses[entry.Node] = entry.Address
	}
	for _, declaration := range plan.Declarations {
		for _, candidate := range declaration.Candidates {
			_, reverse, err := androidCandidateHops(candidate.Tag, byTag)
			if err != nil && len(candidate.Chain) > 0 {
				return nil, err
			}
			var carriers []string
			for index := 1; index < len(candidate.Chain); index++ {
				carrier := "unknown"
				if len(reverse) == len(candidate.Chain) {
					hop := reverse[len(reverse)-1-index]
					if public := addresses[candidate.Chain[index]]; public != "" {
						if hop.Server != public {
							carrier = "neighbor"
						} else if hop.Type == "hysteria2" {
							carrier = "public-hysteria2"
						}
					} else if ip := net.ParseIP(hop.Server); ip != nil && ip.IsPrivate() {
						carrier = "neighbor"
					}
				}
				carriers = append(carriers, carrier)
			}
			inputs.HopCarriers[candidate.Tag] = carriers
		}
	}
	return marshalCanonical(&inputs)
}

func androidCandidateHops(tag string, byTag map[string]androidOutbound) (string, []androidOutbound, error) {
	seen := map[string]bool{}
	var address string
	var reverse []androidOutbound
	for tag != "" {
		outbound, ok := byTag[tag]
		if !ok || seen[tag] {
			return "", nil, errors.New("entry outbound is missing or has a detour cycle")
		}
		seen[tag] = true
		if outbound.Type == "hysteria2" || outbound.Type == "trojan" {
			if outbound.Server == "" {
				return "", nil, errors.New("entry outbound has no server address")
			}
			address = outbound.Server
			reverse = append(reverse, outbound)
		}
		tag = outbound.Detour
	}
	return address, reverse, nil
}

// EvaluateAndroidRoute 把客户端唯一可写偏好应用到已验证移动计划。首次空偏好表示
// Auto；新版计划移除固定出口时保留偏好并返回阻断，不能静默退回 Direct 或 Auto。
func EvaluateAndroidRoute(routePlan, preference, savedSelections []byte) ([]byte, error) {
	var plan androidRoutePlan
	if err := decodeStrictJSON(routePlan, maxBundleBytes, &plan); err != nil {
		return nil, fmt.Errorf("route plan JSON: %w", err)
	}
	if err := validateStandaloneRoutePlan(&plan); err != nil {
		return nil, err
	}
	pref := androidRoutePreference{Schema: 1, Mode: androidRouteModeAuto}
	if len(preference) > 0 {
		if err := decodeStrictJSON(preference, maxInviteBytes, &pref); err != nil {
			return nil, fmt.Errorf("route preference JSON: %w", err)
		}
	}
	if err := validateAndroidPreference(pref); err != nil {
		return nil, err
	}
	scope, err := androidPlanScope(plan)
	if err != nil {
		return nil, err
	}
	remembered := map[string]string{}
	if len(savedSelections) > 0 {
		var saved androidSavedSelections
		if err := decodeStrictJSON(savedSelections, maxCurrentBytes, &saved); err != nil {
			return nil, fmt.Errorf("saved route selections JSON: %w", err)
		}
		if saved.Schema != 1 {
			return nil, fmt.Errorf("unsupported saved route selection schema %d", saved.Schema)
		}
		seen := map[string]bool{}
		for _, selection := range saved.Selections {
			if selection.Selector == "" || selection.Candidate == "" || seen[selection.Selector] {
				return nil, errors.New("saved route selections contain an empty or duplicate selector")
			}
			seen[selection.Selector] = true
			if saved.PlanScope == scope {
				remembered[selection.Selector] = selection.Candidate
			}
		}
	}
	directAvailable, exits := androidRouteCapabilities(plan.Selectors)
	application := androidRouteApplication{
		Schema: 1, PlanScope: scope, Mode: pref.Mode, Exit: pref.Exit,
		DirectAvailable: directAvailable, Exits: exits,
	}
	if pref.Mode == androidRouteModeDirect && !directAvailable {
		application.Blocked = true
		application.BlockReason = "当前签名配置没有覆盖全部 selector 的 Direct 候选"
		return marshalCanonical(&application)
	}
	if pref.Mode == androidRouteModeFixed && !containsString(exits, pref.Exit) {
		application.Blocked = true
		application.BlockReason = "已选择的固定出口不再获当前签名配置授权"
		return marshalCanonical(&application)
	}
	for _, selector := range plan.Selectors {
		candidate := selectAndroidCandidate(selector, pref, remembered[selector.Selector])
		if candidate == nil {
			return nil, fmt.Errorf("selector %q 无法应用路由偏好", selector.Selector)
		}
		application.Selectors = append(application.Selectors, androidAppliedSelection{
			Selector: selector.Selector, Candidate: candidate.Tag, Chain: append([]string(nil), candidate.Chain...),
		})
	}
	return marshalCanonical(&application)
}

func validateStandaloneRoutePlan(plan *androidRoutePlan) error {
	if plan.Schema != 1 || !validNodeID(plan.Node) || plan.API != "127.0.0.1:61800" ||
		plan.Probe != "127.0.0.1:61801" || strings.TrimSpace(plan.APISecret) == "" ||
		strings.TrimSpace(plan.ProbeSecret) == "" || len(plan.Selectors) == 0 {
		return errors.New("mobile route plan is incomplete")
	}
	if len(plan.Peers) != 0 || plan.SelfReport != "" || plan.PeerPeriod != "" || plan.AttestationCA != "" {
		return errors.New("mobile route plan contains Linux peer/report dependencies")
	}
	if len(plan.Selectors) > 256 || len(plan.Declarations) > 256 {
		return errors.New("mobile route plan exceeds the supported selector or declaration limit")
	}
	seenSelectors := map[string]bool{}
	selectorPlans := make(map[string]androidSelectorPlan, len(plan.Selectors))
	for _, selector := range plan.Selectors {
		if selector.Selector == "" || selector.Default == "" || len(selector.Candidates) == 0 || seenSelectors[selector.Selector] {
			return errors.New("mobile route plan has an empty or duplicate selector")
		}
		seenSelectors[selector.Selector] = true
		seenCandidates := map[string]bool{}
		defaultFound := false
		for _, candidate := range selector.Candidates {
			if candidate.Tag == "" || len(candidate.Tag) > 256 || candidate.ProbeUser == "" ||
				len(candidate.ProbeUser) > 256 || seenCandidates[candidate.Tag] {
				return fmt.Errorf("selector %q has an invalid candidate", selector.Selector)
			}
			seenCandidates[candidate.Tag] = true
			defaultFound = defaultFound || candidate.Tag == selector.Default
			for _, node := range candidate.Chain {
				if !validNodeID(node) {
					return fmt.Errorf("selector %q has an invalid chain", selector.Selector)
				}
			}
		}
		if !defaultFound {
			return fmt.Errorf("selector %q default is absent", selector.Selector)
		}
		selectorPlans[selector.Selector] = selector
	}
	seenDeclarations := map[string]bool{}
	scheduledSelectors := map[string]bool{}
	for _, declaration := range plan.Declarations {
		selector, selectorExists := selectorPlans[declaration.Selector]
		if declaration.ID == "" || declaration.Selector == "" || seenDeclarations[declaration.ID] ||
			scheduledSelectors[declaration.Selector] || len(declaration.Targets) == 0 || len(declaration.Targets) > 64 ||
			declaration.MinSamples <= 0 || declaration.SwitchThreshold < 0 || declaration.ProbeBudget < 0 ||
			!selectorExists || len(declaration.Candidates) != len(selector.Candidates) {
			return fmt.Errorf("declaration %q is invalid", declaration.ID)
		}
		seenDeclarations[declaration.ID] = true
		scheduledSelectors[declaration.Selector] = true
		switch declaration.Objective {
		case "latency", "stability", "throughput":
		default:
			return fmt.Errorf("declaration %q has unsupported objective %q", declaration.ID, declaration.Objective)
		}
		for _, target := range declaration.Targets {
			parsed, err := url.Parse(target)
			if err != nil || len(target) > 1024 || parsed.Scheme != "https" || parsed.Host == "" ||
				parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("declaration %q has an unsafe probe target", declaration.ID)
			}
		}
		for _, raw := range []string{declaration.TuningPeriod, declaration.Window, declaration.StaleAfter} {
			if duration, err := time.ParseDuration(raw); err != nil || duration <= 0 {
				return fmt.Errorf("declaration %q has an invalid duration", declaration.ID)
			}
		}
		for index := range declaration.Candidates {
			got, want := declaration.Candidates[index], selector.Candidates[index]
			if got.Tag != want.Tag || got.ProbeUser != want.ProbeUser || !equalStrings(got.Chain, want.Chain) {
				return fmt.Errorf("declaration %q candidate set differs from selector plan", declaration.ID)
			}
		}
	}
	return nil
}

func validateAndroidPreference(preference androidRoutePreference) error {
	if preference.Schema != 1 {
		return fmt.Errorf("unsupported route preference schema %d", preference.Schema)
	}
	switch preference.Mode {
	case androidRouteModeDirect, androidRouteModeAuto:
		if preference.Exit != "" {
			return fmt.Errorf("route mode %s must not carry an exit", preference.Mode)
		}
	case androidRouteModeFixed:
		if !validNodeID(preference.Exit) {
			return errors.New("fixed_exit requires a valid exit node id")
		}
	default:
		return fmt.Errorf("unsupported route mode %q", preference.Mode)
	}
	return nil
}

func androidPlanScope(plan androidRoutePlan) (string, error) {
	copy := plan
	copy.APISecret = ""
	copy.ProbeSecret = ""
	body, err := marshalCanonical(&copy)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("loom-android-route-plan-v1\x00"), body...))
	return hex.EncodeToString(digest[:]), nil
}

func androidRouteCapabilities(selectors []androidSelectorPlan) (bool, []string) {
	direct := len(selectors) > 0
	var common map[string]bool
	for _, selector := range selectors {
		exits := map[string]bool{}
		hasDirect := false
		for _, candidate := range selector.Candidates {
			if len(candidate.Chain) == 0 {
				hasDirect = true
				continue
			}
			exits[candidate.Chain[len(candidate.Chain)-1]] = true
		}
		direct = direct && hasDirect
		if common == nil {
			common = exits
			continue
		}
		for exit := range common {
			if !exits[exit] {
				delete(common, exit)
			}
		}
	}
	return direct, sortedKeys(common)
}

func selectAndroidCandidate(selector androidSelectorPlan, preference androidRoutePreference, remembered string) *androidRouteCandidate {
	eligible := func(candidate androidRouteCandidate) bool {
		switch preference.Mode {
		case androidRouteModeDirect:
			return len(candidate.Chain) == 0
		case androidRouteModeFixed:
			return len(candidate.Chain) > 0 && candidate.Chain[len(candidate.Chain)-1] == preference.Exit
		default:
			return true
		}
	}
	for index := range selector.Candidates {
		if selector.Candidates[index].Tag == remembered && eligible(selector.Candidates[index]) {
			return &selector.Candidates[index]
		}
	}
	if preference.Mode == androidRouteModeAuto {
		for index := range selector.Candidates {
			if selector.Candidates[index].Tag == selector.Default {
				return &selector.Candidates[index]
			}
		}
	}
	for index := range selector.Candidates {
		if eligible(selector.Candidates[index]) {
			return &selector.Candidates[index]
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func validateAndroidRoutePlan(singBox, routePlan []byte, owner string) error {
	var plan androidRoutePlan
	if err := decodeStrictJSON(routePlan, maxBundleBytes, &plan); err != nil {
		return fmt.Errorf("plan JSON: %w", err)
	}
	if plan.Schema != 1 || !validNodeID(plan.Node) || plan.Node != owner || plan.API != "127.0.0.1:61800" ||
		plan.Probe != "127.0.0.1:61801" || strings.TrimSpace(plan.APISecret) == "" ||
		strings.TrimSpace(plan.ProbeSecret) == "" {
		return errors.New("plan identity or loopback endpoints are invalid")
	}
	if len(plan.Peers) != 0 || plan.SelfReport != "" || plan.PeerPeriod != "" || plan.AttestationCA != "" {
		return errors.New("mobile plan contains Linux peer/report dependencies")
	}
	if len(plan.Selectors) == 0 {
		return errors.New("mobile plan has no selectors")
	}
	var configDocument map[string]json.RawMessage
	if err := decodeStrictJSON(singBox, maxBundleBytes, &configDocument); err != nil || configDocument == nil {
		return errors.New("sing-box config is not one strict JSON object")
	}
	var config androidSingBox
	if err := json.Unmarshal(singBox, &config); err != nil {
		return errors.New("sing-box selector projection is invalid")
	}
	if config.Experimental == nil || config.Experimental.ClashAPI == nil ||
		config.Experimental.ClashAPI.ExternalController != plan.API ||
		config.Experimental.ClashAPI.Secret != plan.APISecret {
		return errors.New("plan and sing-box controller do not match")
	}
	selectors := map[string]androidOutbound{}
	for _, outbound := range config.Outbounds {
		if outbound.Type != "selector" {
			continue
		}
		if outbound.Tag == "" || selectors[outbound.Tag].Tag != "" {
			return errors.New("sing-box contains an empty or duplicate selector")
		}
		selectors[outbound.Tag] = outbound
	}
	if len(selectors) != len(plan.Selectors) {
		return errors.New("plan does not cover every sing-box selector")
	}
	planSelectors := make(map[string]androidSelectorPlan, len(plan.Selectors))
	probeCandidates := map[string]string{}
	for _, selector := range plan.Selectors {
		outbound, ok := selectors[selector.Selector]
		if !ok || selector.Default != outbound.Default || len(selector.Candidates) != len(outbound.Outbounds) {
			return fmt.Errorf("selector %q differs from sing-box", selector.Selector)
		}
		if _, duplicate := planSelectors[selector.Selector]; duplicate {
			return fmt.Errorf("plan repeats selector %q", selector.Selector)
		}
		seen := map[string]bool{}
		for index, candidate := range selector.Candidates {
			if candidate.Tag == "" || candidate.ProbeUser == "" || candidate.Tag != outbound.Outbounds[index] || seen[candidate.Tag] {
				return fmt.Errorf("selector %q contains an invalid or reordered candidate", selector.Selector)
			}
			for _, node := range candidate.Chain {
				if !validNodeID(node) {
					return fmt.Errorf("selector %q contains an invalid chain node", selector.Selector)
				}
			}
			seen[candidate.Tag] = true
			if previous := probeCandidates[candidate.ProbeUser]; previous != "" && previous != candidate.Tag {
				return errors.New("one probe user maps to multiple candidates")
			}
			probeCandidates[candidate.ProbeUser] = candidate.Tag
		}
		if !seen[selector.Default] {
			return fmt.Errorf("selector %q default is not a candidate", selector.Selector)
		}
		planSelectors[selector.Selector] = selector
	}
	seenDeclarations := map[string]bool{}
	seenScheduledSelectors := map[string]bool{}
	for _, declaration := range plan.Declarations {
		selector, ok := planSelectors[declaration.Selector]
		if !ok || len(selector.Candidates) != len(declaration.Candidates) || declaration.ID == "" ||
			seenDeclarations[declaration.ID] || seenScheduledSelectors[declaration.Selector] || len(declaration.Targets) == 0 ||
			declaration.MinSamples <= 0 || declaration.SwitchThreshold < 0 || declaration.ProbeBudget < 0 {
			return fmt.Errorf("declaration %q is incomplete or has no selector", declaration.ID)
		}
		seenDeclarations[declaration.ID] = true
		seenScheduledSelectors[declaration.Selector] = true
		switch declaration.Objective {
		case "latency", "stability", "throughput":
		default:
			return fmt.Errorf("declaration %q has unsupported objective %q", declaration.ID, declaration.Objective)
		}
		for _, target := range declaration.Targets {
			parsed, parseErr := url.Parse(target)
			if parseErr != nil || len(target) > 1024 || parsed.Scheme != "https" || parsed.Host == "" ||
				parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("declaration %q has an unsafe probe target", declaration.ID)
			}
		}
		for _, raw := range []string{declaration.TuningPeriod, declaration.Window, declaration.StaleAfter} {
			if duration, err := time.ParseDuration(raw); err != nil || duration <= 0 {
				return fmt.Errorf("declaration %q has an invalid duration", declaration.ID)
			}
		}
		for index := range declaration.Candidates {
			got, want := declaration.Candidates[index], selector.Candidates[index]
			if got.Tag != want.Tag || got.ProbeUser != want.ProbeUser || !equalStrings(got.Chain, want.Chain) {
				return fmt.Errorf("declaration %q candidate set differs from selector plan", declaration.ID)
			}
		}
	}
	probeHost, probePort, err := net.SplitHostPort(plan.Probe)
	if err != nil || probeHost != "127.0.0.1" || probePort != "61801" {
		return errors.New("mobile probe endpoint is not the fixed loopback listener")
	}
	users := map[string]string{}
	for _, inbound := range config.Inbounds {
		if inbound.Tag != "probe-in" {
			continue
		}
		if inbound.Type != "mixed" || inbound.Listen != probeHost || inbound.ListenPort != 61801 {
			return errors.New("sing-box probe listener differs from mobile plan")
		}
		for _, user := range inbound.Users {
			users[user.Username] = user.Password
		}
	}
	for user, candidate := range probeCandidates {
		if users[user] != plan.ProbeSecret || !hasProbeRule(config.Route.Rules, user, candidate) {
			return fmt.Errorf("candidate %q has no authenticated probe path", candidate)
		}
	}
	return nil
}

func hasProbeRule(rules []androidRule, user, candidate string) bool {
	for _, rule := range rules {
		if len(rule.Inbound) == 1 && rule.Inbound[0] == "probe-in" && len(rule.AuthUser) == 1 &&
			rule.AuthUser[0] == user && rule.Outbound == candidate {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
