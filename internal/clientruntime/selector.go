package clientruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"sort"
	"strings"

	"loom/internal/agent"
	"loom/internal/clientcore"
	"loom/internal/model"
)

// §5.1、§7.3.3：本地偏好只裁剪签名候选，selector 的运行期写者只有共享 Agent。
type WindowsSelectorPlan struct {
	config           agent.Config
	policy           clientcore.Policy
	direct           bool
	internetSelector string
}

func BuildWindowsSelectorPlan(body, agentBody []byte, profile WindowsRuntimeProfile, caPath string) (*WindowsSelectorPlan, error) {
	if err := ValidateWindowsRuntimeConfig(body, profile, caPath); err != nil {
		return nil, err
	}
	return validateWindowsAgentPair(body, agentBody, "")
}

// §12：两个文件必须一起验证；opaque tag 只用于关联，绝不反解析节点链。
func validateWindowsAgentPair(body, agentBody []byte, node string) (*WindowsSelectorPlan, error) {
	if len(agentBody) == 0 || len(agentBody) > maxSingBoxBytes {
		return nil, errors.New("[§12] Agent plan 大小无效")
	}
	if err := rejectDuplicateJSONKeys(agentBody); err != nil {
		return nil, err
	}
	cfg, err := agent.Load(agentBody)
	if err != nil {
		return nil, err
	}
	if cfg.Schema != agent.ConfigSchema || !model.ValidNodeID(cfg.Node) || (node != "" && cfg.Node != node) || len(cfg.Declarations) == 0 {
		return nil, errors.New("[§12] Agent plan schema、节点或 Service 无效")
	}
	// §16.1.2：Windows 只用客户端完整路径测量，不引入服务器分段观测源。
	if len(cfg.Peers) > 0 || cfg.SelfReport != "" {
		return nil, errors.New("[§16.1.2] Windows Agent 不接受服务器观测源")
	}
	var sb singBoxConfig
	if err := json.Unmarshal(body, &sb); err != nil {
		return nil, err
	}
	if sb.Experimental == nil || sb.Experimental.ClashAPI == nil || cfg.API != "127.0.0.1:61800" || cfg.API != sb.Experimental.ClashAPI.ExternalController || cfg.APISecret == "" || cfg.APISecret != sb.Experimental.ClashAPI.Secret || cfg.Probe != "127.0.0.1:61801" || cfg.ProbeSecret == "" {
		return nil, errors.New("[§7.3.3] Agent API/probe 与 sing-box 不匹配")
	}
	outbounds := map[string]singBoxOutbound{}
	selectors := map[string]bool{}
	for _, o := range sb.Outbounds {
		outbounds[o.Tag] = o
		if o.Type == "selector" {
			selectors[o.Tag] = true
		}
	}
	// §12：新版共享计划的 selector 元数据也必须与同包数据面一致。
	// Windows 要求每个可写 selector 都有可执行的完整路径决策声明。
	if len(cfg.Selectors) > 0 {
		if len(cfg.Selectors) != len(cfg.Declarations) {
			return nil, errors.New("[§12] selector 计划未完整绑定 Agent 声明")
		}
		for _, selector := range cfg.Selectors {
			outbound := outbounds[selector.Selector]
			if outbound.Type != "selector" || outbound.Default != selector.Default {
				return nil, errors.New("[§12] selector 计划与 sing-box 默认候选不一致")
			}
		}
	}
	users := map[string]string{}
	probeTag := ""
	for _, in := range sb.Inbounds {
		if in.Listen == "127.0.0.1" && in.ListenPort == 61801 && in.Type == "mixed" {
			if probeTag != "" {
				return nil, errors.New("[§7.3.3] 重复探测入口")
			}
			probeTag = in.Tag
			for _, u := range in.Users {
				if _, ok := users[u.Username]; ok {
					return nil, errors.New("[§7.3.3] 重复探测用户")
				}
				users[u.Username] = u.Password
			}
		}
	}
	if probeTag == "" {
		return nil, errors.New("[§7.3.3] 缺少候选探测入口")
	}
	plan := &WindowsSelectorPlan{config: *cfg, policy: clientcore.Policy{Schema: clientcore.PolicySchema}, direct: true}
	ids, seenUsers := map[string]bool{}, map[string]bool{}
	exitsBySelector := map[string]map[string]bool{}
	for _, d := range cfg.Declarations {
		if d.ID == "" || ids[d.ID] || !selectors[d.Selector] {
			return nil, errors.New("[§5.1] 重复 Service 或缺失 selector")
		}
		ids[d.ID] = true
		delete(selectors, d.Selector)
		period, _ := d.Period()
		window, _ := d.Win()
		stale, _ := d.Stale()
		if d.MinSamples < 1 || int64(d.MinSamples) > int64(window/period) || stale < period || d.ProbeBudget < 0 || (d.ProbeBudget == 1 && len(d.Candidates) > 1) || math.IsNaN(d.SwitchThreshold) || math.IsInf(d.SwitchThreshold, 0) || d.SwitchThreshold < 0 || d.SwitchThreshold >= 1 {
			return nil, fmt.Errorf("[§5.5] Service %s 的窗口、门槛或探测预算不可执行", d.ID)
		}
		targets := map[string]bool{}
		for _, target := range d.Targets {
			u, e := url.Parse(target)
			if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || targets[target] {
				return nil, errors.New("[§7.3.3] 探测目标无效或重复")
			}
			targets[target] = true
		}
		members := outbounds[d.Selector].Outbounds
		if len(members) != len(d.Candidates) {
			return nil, errors.New("[§12] Agent 与 selector 候选集合不同")
		}
		seen := map[string]bool{}
		exits := map[string]bool{}
		direct := false
		for _, c := range d.Candidates {
			if c.Tag == "" || seen[c.Tag] || !slices.Contains(members, c.Tag) || c.ProbeUser == "" || strings.Contains(c.ProbeUser, ":") || seenUsers[c.ProbeUser] || users[c.ProbeUser] != cfg.ProbeSecret {
				return nil, errors.New("[§7.3.3] 候选或 probe user 不匹配")
			}
			seen[c.Tag] = true
			seenUsers[c.ProbeUser] = true
			if outbounds[c.Tag].Type == "selector" || outbounds[c.Tag].Type == "block" {
				return nil, errors.New("[§5.6] 候选不是完整路径出站")
			}
			hops := map[string]bool{}
			for _, hop := range c.Chain {
				if !model.ValidNodeID(hop) || hops[hop] || hop == cfg.Node {
					return nil, errors.New("[§5.6] 候选链非法")
				}
				hops[hop] = true
			}
			if len(c.Chain) == 0 {
				if outbounds[c.Tag].Type != "direct" || outbounds[c.Tag].Detour != "" {
					return nil, errors.New("[§5.6] direct 链与出站不一致")
				}
				direct = true
			} else {
				if outbounds[c.Tag].Type == "direct" && outbounds[c.Tag].Detour == "" {
					return nil, errors.New("[§5.6] 服务器链指向 direct")
				}
				exits[c.Chain[len(c.Chain)-1]] = true
			}
			// 首个能匹配该 probe user 的规则必须无目标限制地指向同一候选。
			matched := false
			for _, r := range sb.Route.Rules {
				if len(r.Inbound) > 0 && !slices.Contains(r.Inbound, probeTag) {
					continue
				}
				if len(r.AuthUser) > 0 && !slices.Contains(r.AuthUser, c.ProbeUser) {
					continue
				}
				if !slices.Equal(r.Inbound, []string{probeTag}) || !slices.Equal(r.AuthUser, []string{c.ProbeUser}) || r.Outbound != c.Tag || r.Action != "" || len(r.Domain)+len(r.DomainSuffix)+len(r.IPCIDR)+len(r.Port) > 0 {
					return nil, errors.New("[§7.3.3] 探测规则未唯一绑定完整候选")
				}
				matched = true
				break
			}
			if !matched {
				return nil, errors.New("[§7.3.3] 候选缺少探测规则")
			}
		}
		plan.direct = plan.direct && direct
		exitsBySelector[d.Selector] = exits
	}
	if len(selectors) > 0 || len(seenUsers) != len(users) {
		return nil, errors.New("[§12] 未纳入 Agent 的 selector 或 probe user")
	}
	plan.internetSelector, _, err = windowsInternetSelector(&sb)
	if err != nil {
		return nil, err
	}
	for exit := range exitsBySelector[plan.internetSelector] {
		plan.policy.Exits = append(plan.policy.Exits, clientcore.Exit{ID: exit})
	}
	sort.Slice(plan.policy.Exits, func(i, j int) bool { return plan.policy.Exits[i].ID < plan.policy.Exits[j].ID })
	if err := plan.policy.Validate(); err != nil {
		return nil, err
	}
	return plan, nil
}

func (p *WindowsSelectorPlan) Policy() clientcore.Policy {
	if p == nil {
		return clientcore.Policy{}
	}
	return clientcore.Policy{Schema: p.policy.Schema, Exits: append([]clientcore.Exit(nil), p.policy.Exits...)}
}
func (p *WindowsSelectorPlan) DirectAvailable() bool { return p != nil && p.direct }

// §5.1：固定末跳保留所有授权前缀；启动默认值也必须在裁剪后的集合内。
func (p *WindowsSelectorPlan) Derive(body []byte, preference clientcore.Preference) ([]byte, *agent.Config, error) {
	if p == nil {
		return nil, nil, errors.New("[§5.1] 缺少签名 Agent plan")
	}
	if err := clientcore.AuthorizeChange(preference, p.policy); err != nil {
		return nil, nil, err
	}
	if preference.Mode == clientcore.Direct && !p.direct {
		return nil, nil, errors.New("[§5.8] Service 无授权 direct 候选")
	}
	var sb singBoxConfig
	if err := json.Unmarshal(body, &sb); err != nil {
		return nil, nil, err
	}
	if preference.Mode == clientcore.FixedExit {
		cfg, err := p.fixedInternetConfig(&sb, preference)
		if err != nil {
			return nil, nil, err
		}
		derived, err := json.Marshal(&sb)
		return derived, cfg, err
	}
	cfg := p.config
	cfg.Declarations = make([]agent.Decl, len(p.config.Declarations))
	for i, d := range p.config.Declarations {
		d.Candidates = append([]agent.Cand(nil), d.Candidates...)
		d.Candidates = slices.DeleteFunc(d.Candidates, func(c agent.Cand) bool {
			switch preference.Mode {
			case clientcore.Direct:
				return len(c.Chain) != 0
			}
			return false
		})
		if len(d.Candidates) == 0 {
			return nil, nil, errors.New("[§5.8] 偏好裁剪后 Service 无候选")
		}
		cfg.Declarations[i] = d
		for j := range sb.Outbounds {
			o := &sb.Outbounds[j]
			if o.Tag != d.Selector {
				continue
			}
			o.Outbounds = nil
			for _, c := range d.Candidates {
				o.Outbounds = append(o.Outbounds, c.Tag)
			}
			if !slices.Contains(o.Outbounds, o.Default) {
				o.Default = o.Outbounds[0]
			}
		}
	}
	restrictWindowsAgentSelectors(&cfg)
	derived, err := json.Marshal(&sb)
	if preference.Mode == clientcore.Direct {
		return derived, nil, err
	}
	return derived, &cfg, err
}

// §7.3.1：Direct 不启动 Agent，但同样验证受限 selector 的实际默认值。
func (p *WindowsSelectorPlan) DirectReadinessConfig() *agent.Config {
	cfg := p.config
	cfg.Declarations = append([]agent.Decl(nil), p.config.Declarations...)
	for i := range cfg.Declarations {
		cfg.Declarations[i].Candidates = nil
		for _, c := range p.config.Declarations[i].Candidates {
			if len(c.Chain) == 0 {
				cfg.Declarations[i].Candidates = append(cfg.Declarations[i].Candidates, c)
			}
		}
	}
	restrictWindowsAgentSelectors(&cfg)
	return &cfg
}

// §5.1：保留同一份签名计划的两种投影一致，不让原候选元数据越过本地偏好。
func restrictWindowsAgentSelectors(cfg *agent.Config) {
	cfg.Selectors = append([]agent.SelectorPlan(nil), cfg.Selectors...)
	for i := range cfg.Selectors {
		selector := &cfg.Selectors[i]
		for _, declaration := range cfg.Declarations {
			if declaration.Selector != selector.Selector {
				continue
			}
			selector.Candidates = append([]agent.Cand(nil), declaration.Candidates...)
			if len(selector.Candidates) == 0 {
				selector.Default = ""
			} else if !slices.ContainsFunc(selector.Candidates, func(c agent.Cand) bool { return c.Tag == selector.Default }) {
				selector.Default = selector.Candidates[0].Tag
			}
		}
	}
}
