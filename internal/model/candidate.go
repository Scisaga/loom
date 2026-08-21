package model

import "fmt"

// RouteCandidate 是排序、选择与归因的单位(§5.6)。
//
// 目标与中继不分开排序:经广州最优的目标,经北京未必仍最优。评分的单位
// 是完整路径,因此这里把 relay_chain 与 target 绑在一起。
type RouteCandidate struct {
	Declaration string
	RelayChain  []string // 当前只枚举单跳
	Target      string
}

// Tag 是候选在 sing-box 配置与上报中的稳定标识。
func (c *RouteCandidate) Tag() string {
	chain := ""
	for _, r := range c.RelayChain {
		chain += r + ">"
	}
	return "cand:" + c.Declaration + ":" + chain + c.Target
}

// CandidateSkip 记录一个本该成为候选、但在 L4 数据平面无法表达的组合。
//
// 它必须被报出而不是静默丢弃:少了候选的 ranked list 看起来一样正常,
// 但调度会在一个残缺的集合里选优,而没有人知道。
type CandidateSkip struct {
	Declaration string
	Reason      string
}

// EnumerateCandidates 枚举一条访问声明在 L4 上可表达的全部路径候选。
//
// 策略过滤(§5.1)在这里只做"能否表达"这一层:方向约束、隧道是否存在、
// 端点是否可部署。合规、地域、SLA 属于调度层的过滤,不在渲染期生效。
func (s *SSOT) EnumerateCandidates(d *AccessDeclaration) ([]RouteCandidate, []CandidateSkip) {
	nodes := s.NodeByID()
	classes := s.ClassByID()
	var out []RouteCandidate
	var skips []CandidateSkip

	skip := func(format string, args ...any) {
		skips = append(skips, CandidateSkip{Declaration: d.ID, Reason: fmt.Sprintf(format, args...)})
	}

	// 目标集合。模式 A 是常量,模式 B 取等价类成员。
	var targets []string
	switch d.Mode {
	case PinnedTarget:
		targets = []string{d.TargetNode}
	case ByService:
		c, ok := classes[d.EquivalenceClass]
		if !ok {
			return nil, skips
		}
		// §4.4:只有 l4_direct 的等价类能由数据平面直接换端点。
		// 其余承载方式要经 L7 网关或调用方 SDK,而那不是本渲染器的产物。
		if c.Carrier != L4Direct {
			skip("等价类 %q 的 carrier 是 %s,换端点不由 L4 完成;"+
				"该声明在数据平面没有候选,需要 %s 承载(§4.4)", c.ID, c.Carrier, c.Carrier)
			return nil, skips
		}
		for _, m := range c.Members {
			targets = append(targets, m.Node)
		}
	}

	// §3.2:实践中 ≤2 跳。当前只实现单跳。
	if d.MaxHops >= 2 {
		skip("max_hops=%d,但当前只枚举单跳候选 —— 两跳链尚未实现", d.MaxHops)
	}

	for _, rid := range d.AllowedRelays {
		relay, ok := nodes[rid]
		if !ok || !relay.Has(Relay) {
			continue // 引用错误已由校验器报出
		}
		if relay.InboundPort == 0 {
			skip("中继 %q 没有 inbound_port,接入节点无处可连", rid)
			continue
		}
		for _, tid := range targets {
			t, ok := nodes[tid]
			if !ok {
				continue
			}
			if !t.IsManaged() {
				skip("目标 %q 是 managed: false 的第三方端点,无法在其上运行 inbound,"+
					"不能作为 L4 下一跳(§9.2)", tid)
				continue
			}
			if t.InboundPort == 0 {
				skip("目标 %q 没有 inbound_port", tid)
				continue
			}
			if s.TunnelAddrOn(tid, rid) == "" {
				skip("中继 %q 与目标 %q 之间没有隧道", rid, tid)
				continue
			}
			out = append(out, RouteCandidate{Declaration: d.ID, RelayChain: []string{rid}, Target: tid})
		}
	}
	return out, dedupSkips(skips)
}

// dedupSkips 合并重复原因。枚举是 relay × target 的笛卡尔积,同一个原因
// 会被撞上很多次,原样报出会淹没其他信息。
func dedupSkips(in []CandidateSkip) []CandidateSkip {
	seen := map[string]bool{}
	var out []CandidateSkip
	for _, s := range in {
		if seen[s.Reason] {
			continue
		}
		seen[s.Reason] = true
		out = append(out, s)
	}
	return out
}
