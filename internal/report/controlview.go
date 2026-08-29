package report

import (
	"fmt"
	"sort"

	"loom/internal/model"
	"loom/internal/webui"
)

// enrichControlView 把中控本地 SSOT 的期望态元数据并到运行态视图。它不修改
// Health/Applied/route state；配置刚保存、节点尚未应用时，两种事实仍可并排看。
func enrichControlView(v *webui.View, s *model.SSOT, controlNode string) {
	v.IntentSource = "current SSOT"
	enrichNodes(v, s, controlNode)
	// Desired topology must come from the same just-read SSOT as Nodes and
	// Services. Keeping cfg.Expected* here would mix the new SSOT with the
	// control node's previously applied snapshot and make topology lag a save by
	// an entire pull/apply cycle.
	desired := expectedConfigFromSSOT(s)
	v.Candidates = candidatePaths(desired, v.Routes)
	v.Links = topologyLinks(desired, v.Nodes)
	v.Services = serviceViews(s)
	v.Policies = policyViews(s)
	v.Ingresses = ingressViews(s)
	enrichRouteScopes(v, s)
}

func enrichNodes(v *webui.View, s *model.SSOT, controlNode string) {
	byID := make(map[string]int, len(v.Nodes))
	for i := range v.Nodes {
		// The applied report config may still contain a node that has just been
		// removed from the current SSOT. Re-establish declaration membership from
		// this exact SSOT read instead of carrying the old ExpectedNodes bit over.
		node := &v.Nodes[i]
		node.Declared = false
		// These fields are desired-state metadata, not node-owned observation. Clear
		// the previous enrichment before applying the current SSOT so a caller that
		// reuses a View cannot show a removed declaration's old endpoint or role.
		node.Name, node.City, node.Provider, node.PublicEndpoint = "", "", "", ""
		node.SSHPort = 0
		node.Roles = nil
		node.Direction = ""
		node.EgressCapable = false
		node.Drain, node.Decommission = false, false
		byID[v.Nodes[i].ID] = i
	}
	for i := range s.Nodes {
		declared := &s.Nodes[i]
		idx, ok := byID[declared.ID]
		if !ok {
			v.Nodes = append(v.Nodes, webui.NodeView{
				ID: declared.ID, Declared: true, Health: "unknown", Source: "中控 SSOT · 尚无观测",
			})
			idx = len(v.Nodes) - 1
			byID[declared.ID] = idx
		}
		got := &v.Nodes[idx]
		got.Declared = true
		got.Name = declared.Name
		got.City = declared.City
		got.Provider = declared.Provider
		got.PublicEndpoint = declared.PublicEndpoint
		got.SSHPort = declared.SSHPort
		if got.SSHPort == 0 {
			got.SSHPort = 22
		}
		got.Drain = declared.Drain
		got.Decommission = declared.Decommission
		got.Roles = got.Roles[:0]
		if declared.ID == controlNode {
			got.Roles = append(got.Roles, "control")
		}
		if declared.IsAccess() {
			got.Roles = append(got.Roles, "access")
		}
		if declared.IsServer() {
			got.Roles = append(got.Roles, "server")
			got.Direction = string(declared.Server.Direction)
			got.EgressCapable = declared.Server.EgressCapable
			if got.EgressCapable {
				got.Roles = append(got.Roles, "egress")
			}
		} else {
			got.Direction = ""
			got.EgressCapable = false
		}
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].ID < v.Nodes[j].ID })
}

func serviceViews(s *model.SSOT) []webui.ServiceView {
	out := make([]webui.ServiceView, 0, len(s.Services))
	for i := range s.Services {
		svc := &s.Services[i]
		v := webui.ServiceView{
			ID: svc.ID, Name: svc.Name, PolicyID: svc.Declaration,
			Addresses: append([]string(nil), svc.Addresses...),
		}
		for _, addr := range svc.Addresses {
			match := "exact"
			if model.IsSuffix(addr) {
				match = "suffix"
			}
			v.Hosts = append(v.Hosts, webui.HostRuleView{Host: addr, Match: match})
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func policyViews(s *model.SSOT) []webui.PolicyView {
	out := make([]webui.PolicyView, 0, len(s.Declarations))
	for i := range s.Declarations {
		d := &s.Declarations[i]
		v := webui.PolicyView{
			ID: d.ID, Name: d.Name, AddressAxis: d.AddressAxis, EgressAxis: d.EgressAxis,
			Matcher: d.Matcher, ProbeURL: d.ProbeURL, ProbeBudget: d.ProbeBudget,
			Objective: string(d.Objective), MaxHops: d.MaxHops,
			RankingPeriod: d.RankingPeriod, TuningPeriod: d.TuningPeriod,
			SwitchThreshold: d.SwitchThreshold, TopN: d.TopN,
			Window: d.Window, MinSamples: d.MinSamples, StaleAfter: d.StaleAfter,
			Fallback:       string(d.Fallback),
			AllowedServers: append([]string(nil), d.AllowedServers...),
		}
		for _, c := range d.Constraints {
			v.Constraints = append(v.Constraints, webui.ConstraintView{
				Kind: string(c.Kind), Expr: c.Expr,
			})
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func ingressViews(s *model.SSOT) []webui.IngressView {
	var out []webui.IngressView
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.IsAccess() {
			continue
		}
		platform := string(n.Access.Platform)
		if n.Access.Platform.UsesTUN() {
			policyID := effectiveTUNPolicy(s, n)
			out = append(out, webui.IngressView{
				Node: n.ID, Platform: platform, Kind: "tun", Mode: "default_policy",
				ScopeKind: webui.ScopePolicy, ScopeID: policyID, PolicyID: policyID,
				Declaration: n.Access.DefaultDeclaration, Default: true,
			})
		}
		for _, mp := range n.Access.MixedPorts {
			v := webui.IngressView{
				Node: n.ID, Platform: platform, Kind: "mixed", Port: mp.Port,
				Listen:      fmt.Sprintf("127.0.0.1:%d", mp.Port),
				Declaration: mp.Declaration,
			}
			if mp.ByService() {
				v.Mode = "services"
				v.ScopeKind = webui.ScopeServices
				v.Services = true
			} else {
				v.Mode = "policy"
				v.ScopeKind = webui.ScopePolicy
				v.ScopeID = mp.Declaration
				v.PolicyID = mp.Declaration
			}
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func accessPolicySet(s *model.SSOT, n *model.Node) map[string]bool {
	out := map[string]bool{}
	if n == nil || !n.IsAccess() {
		return out
	}
	credentials := s.CredentialByID()
	for _, id := range n.Access.Credentials {
		if c := credentials[id]; c != nil && c.Declaration != "" {
			out[c.Declaration] = true
		}
	}
	return out
}

func effectiveTUNPolicy(s *model.SSOT, n *model.Node) string {
	if n == nil || !n.IsAccess() || !n.Access.Platform.UsesTUN() {
		return ""
	}
	if n.Access.DefaultDeclaration != "" {
		return n.Access.DefaultDeclaration
	}
	policies := accessPolicySet(s, n)
	if len(policies) != 1 {
		return ""
	}
	for id := range policies {
		return id
	}
	return ""
}

func policyPinnedAtIngress(s *model.SSOT, n *model.Node, policyID string) bool {
	if n == nil || !n.IsAccess() {
		return false
	}
	for _, mp := range n.Access.MixedPorts {
		if !mp.ByService() && mp.Declaration == policyID {
			return true
		}
	}
	return effectiveTUNPolicy(s, n) == policyID
}

func enrichRouteScopes(v *webui.View, s *model.SSOT) {
	services := s.ServiceByID()
	policies := s.DeclarationByID()
	nodes := s.NodeByID()
	warned := map[string]bool{}
	warn := func(message string) {
		if message == "" || warned[message] {
			return
		}
		warned[message] = true
		v.Warnings = append(v.Warnings, message)
	}

	resolve := func(node, legacy, kind, id string, allowLegacy bool) (string, string, string) {
		if kind == "" {
			if allowLegacy {
				kind, id = legacyRouteScope(s, nodes[node], legacy)
				if kind == "" && legacy != "" {
					warn("无法判定候选路径 " + node + "/" + legacy + " 属于 service 还是 policy")
				}
			} else if legacy != "" {
				warn("无法从 Agent selector 判定运行路径作用域:" + node + "/" + legacy)
			}
		}
		switch kind {
		case webui.ScopeService:
			svc := services[id]
			if svc == nil {
				warn("运行态引用了 SSOT 中不存在的 service:" + id)
				return kind, id, ""
			}
			return kind, id, svc.Declaration
		case webui.ScopePolicy:
			if policies[id] == nil {
				warn("运行态引用了 SSOT 中不存在的 policy:" + id)
			}
			return kind, id, id
		default:
			return kind, id, ""
		}
	}

	for i := range v.Routes {
		r := &v.Routes[i]
		r.ScopeKind, r.ScopeID, r.PolicyID = resolve(
			r.Node, r.Declaration, r.ScopeKind, r.ScopeID, false)
		if r.ScopeID != "" && r.Declaration != "" && r.ScopeID != r.Declaration {
			warn("Agent selector 与兼容 declaration 不一致:" + r.Node + "/" + r.Selector)
		}
	}
	for i := range v.Candidates {
		p := &v.Candidates[i]
		p.ScopeKind, p.ScopeID, p.PolicyID = resolve(
			p.Node, p.Declaration, p.ScopeKind, p.ScopeID, true)
	}
}

// legacyRouteScope 只用于 ExpectedRoute 这类尚未携带 selector 的旧配置。
// 它按“该 access 真会生成哪个 selector”来判定；服务 ID 与策略 ID 若碰撞，
// 宁可留空并告警，也不猜错。
func legacyRouteScope(s *model.SSOT, access *model.Node, id string) (kind, scopeID string) {
	if access == nil || !access.IsAccess() || id == "" {
		return "", ""
	}
	allowed := accessPolicySet(s, access)
	service := s.ServiceByID()[id]
	servicePossible := service != nil && allowed[service.Declaration]
	policyPossible := s.DeclarationByID()[id] != nil && allowed[id] && policyPinnedAtIngress(s, access, id)
	switch {
	case servicePossible && !policyPossible:
		return webui.ScopeService, id
	case policyPossible && !servicePossible:
		return webui.ScopePolicy, id
	default:
		return "", ""
	}
}
