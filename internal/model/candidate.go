package model

import (
	"fmt"
	"sort"
	"strings"
)

// RouteCandidate 是排序、选择与归因的唯一单位(§5.6)。
//
// 地址与服务器链不分开排序:经广州最优的地址,经北京未必仍最优。评分的
// 单位是完整路径,因此这里把两者绑在一起。
type RouteCandidate struct {
	Declaration string

	// Service 非空时,这条候选属于某个服务(§4.5)。
	//
	// **服务是选择的单位,不是选择的对象**:服务把一组地址归到一起走同一
	// 条路,而不是从中挑一个。挑一个是等价类的事(§4.3),那时用 Address。
	Service string

	// ServerChain 有序。**最后一台就是这次的出口**(§1.1)。
	// 长度为 0 表示直连 —— 零跳是一等公民(§3.1)。
	ServerChain []string

	// Address 是最终地址。地址轴为 from_request 时为空,
	// 表示由客户端请求决定。
	Address string
}

// Egress 返回这条候选的出口服务器 id;直连时返回空串。
func (c *RouteCandidate) Egress() string {
	if len(c.ServerChain) == 0 {
		return ""
	}
	return c.ServerChain[len(c.ServerChain)-1]
}

// Tag 是候选在 sing-box 配置与上报中的稳定标识。
func (c *RouteCandidate) Tag() string {
	key := c.Declaration
	if c.Service != "" {
		// 同一条声明治理的多个服务**各自独立选路**(D43),所以 tag 必须
		// 带上服务 —— 否则它们会共用一个 selector,又回到"一个候选服务
		// 所有目标"的老问题。
		key = c.Service
	}
	t := "cand:" + key + ":"
	if len(c.ServerChain) == 0 {
		t += "direct"
	}
	for i, sv := range c.ServerChain {
		if i > 0 {
			t += ">"
		}
		t += sv
	}
	if c.Address != "" {
		t += "@" + c.Address
	}
	return t
}

// CandidateSkip 记录一个本该成为候选、但在 L4 数据平面无法表达的组合。
//
// 它必须被报出而不是静默丢弃:少了候选的 ranked list 看起来一样正常,
// 但调度会在一个残缺的集合里选优,而没有人知道。
type CandidateSkip struct {
	Declaration string
	Reason      string
}

// EnumerateCandidates 枚举某个接入节点在一条访问声明下可表达的全部路径候选。
//
// **候选集因接入节点而异。** 第一跳能不能到达,取决于这个接入节点与那台
// 服务器之间有没有隧道 —— access-a 与境外机建了反连隧道,就能一跳直达;
// 别的接入节点没建,就只能经国内中继中转。
//
// 这里只做"能否表达"这一层过滤:出口能力、可达性、方向约束。合规、地域、
// SLA 属于调度层的过滤(§5.1),不在渲染期生效。
func (s *SSOT) EnumerateCandidates(access *Node, d *AccessDeclaration) ([]RouteCandidate, []CandidateSkip) {
	nodes := s.NodeByID()
	var skips []CandidateSkip
	skip := func(format string, args ...any) {
		skips = append(skips, CandidateSkip{Declaration: d.ID, Reason: fmt.Sprintf(format, args...)})
	}

	addrs, ok := s.candidateAddresses(d, skip)
	if !ok {
		return nil, dedupSkips(skips)
	}
	chains := s.candidateChains(access, d, nodes, skip)

	var out []RouteCandidate
	for _, chain := range chains {
		for _, a := range addrs {
			out = append(out, RouteCandidate{Declaration: d.ID, ServerChain: chain, Address: a})
		}
	}
	return out, dedupSkips(skips)
}

// candidateAddresses 返回地址轴的取值。返回 ok=false 表示这条声明在 L4 上
// 完全没有候选。
func (s *SSOT) candidateAddresses(d *AccessDeclaration, skip func(string, ...any)) ([]string, bool) {
	if d.AddressFromRequest() {
		// 地址由客户端请求决定,地址轴退化为常量:一个空地址代表"随请求走"。
		return []string{""}, true
	}
	c, ok := s.ClassByID()[d.ClassID()]
	if !ok {
		return nil, false // 引用错误已由校验器报出
	}
	// §4.4:只有 l4_direct 的等价类能由数据平面直接换地址。其余承载方式
	// 要经 L7 网关或调用方 SDK,而那不是本渲染器的产物。
	if c.Carrier != L4Direct {
		skip("等价类 %q 的 carrier 是 %s,换地址不由 L4 完成;"+
			"该声明在数据平面没有候选,需要 %s 承载(§4.4)", c.ID, c.Carrier, c.Carrier)
		return nil, false
	}
	var out []string
	for i := range c.Members {
		out = append(out, c.Members[i].Address)
	}
	return out, len(out) > 0
}

// candidateChains 枚举服务器链。长度 0..max_hops,链末尾即出口。
func (s *SSOT) candidateChains(access *Node, d *AccessDeclaration, nodes map[string]*Node, skip func(string, ...any)) [][]string {
	pinned := d.PinnedEgress()
	maxHops := d.MaxHops
	if maxHops > 2 {
		skip("max_hops=%d,但当前只枚举到两跳", maxHops)
		maxHops = 2
	}

	allowed := make([]*Node, 0, len(d.AllowedServers))
	var drained []string
	for _, id := range d.AllowedServers {
		n, ok := nodes[id]
		if !ok || !n.IsServer() {
			continue // 引用错误已由校验器报出
		}
		// 排空的机器不进候选(隧道和配置照旧,迁移期间还要观测它);
		// 下线的更不进 —— 它正在停机。
		if n.Drain || n.Decommission {
			drained = append(drained, id)
			continue
		}
		allowed = append(allowed, n)
	}
	if len(drained) > 0 {
		// 说出来:一条声明的候选突然少了几个,不该让人去猜。
		skip("已排空(drain)的服务器不参与候选:%s", strings.Join(drained, " "))
	}

	var chains [][]string
	// 记录每台被允许的服务器最终有没有进到某条链里。只在"完全用不上"时
	// 才报出原因 —— reverse_only 拨不到第一跳是正常架构行为,它照样能当
	// 第二跳,每次都报会淹没真正的问题。
	used := map[string]bool{}

	// 零跳:接入节点直接连目标地址。§3.1 —— 直连是一等公民,与多跳同台竞争。
	// 出口钉死时不适用,因为直连没有出口服务器。
	if pinned == "" {
		chains = append(chains, nil)
	}

	usableEgress := func(n *Node) bool {
		if !n.Server.EgressCapable {
			return false
		}
		return pinned == "" || n.ID == pinned
	}

	// 一跳。第一跳必须能被这个接入节点到达 —— 公网可拨,或者两者之间
	// 已经有隧道(reverse_only 靠后者,见 AccessHopAddr)。
	if maxHops >= 1 {
		for _, n := range allowed {
			if !usableEgress(n) || s.AccessHopAddr(access, n) == "" {
				continue
			}
			chains = append(chains, []string{n.ID})
			used[n.ID] = true
		}
	}

	// 两跳。第一跳必须能被接入节点到达,第二跳必须从第一跳可达且能出公网。
	if maxHops >= 2 {
		for _, a := range allowed {
			if s.AccessHopAddr(access, a) == "" {
				continue
			}
			for _, b := range allowed {
				if a.ID == b.ID || !usableEgress(b) {
					continue
				}
				if !s.ServerReachable(a, b) {
					continue
				}
				if b.Server.InboundPort == 0 {
					skip("服务器 %q 没有 inbound_port,前一跳无处转发", b.ID)
					continue
				}
				chains = append(chains, []string{a.ID, b.ID})
				used[a.ID], used[b.ID] = true, true
			}
		}
	}

	for _, n := range allowed {
		if used[n.ID] {
			continue
		}
		switch {
		case pinned != "" && n.ID != pinned && maxHops < 2:
			skip("服务器 %q 用不上:出口钉死在 %q,而 max_hops=%d 不允许它作为中间一跳",
				n.ID, pinned, maxHops)
		case !n.Server.EgressCapable && maxHops < 2:
			skip("服务器 %q 用不上:没有 egress_capable,而 max_hops=%d 不允许它作为中间一跳",
				n.ID, maxHops)
		case s.AccessHopAddr(access, n) == "":
			skip("服务器 %q 用不上:接入节点既拨不到它(direction=%s),"+
				"与它之间也没有隧道,而且没有任何一台可达的服务器能转发到它",
				n.ID, n.Server.Direction)
		default:
			skip("服务器 %q 在这条声明里产生不了任何候选", n.ID)
		}
	}
	return chains
}

// dedupSkips 合并重复原因。枚举是笛卡尔积,同一个原因会被撞上很多次,
// 原样报出会淹没其他信息。
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

// EnumerateServiceCandidates 枚举一个服务的候选。
//
// 与按声明枚举的区别只有一处:**地址不是选择的维度**。服务把它的地址集合
// 归到一起走同一条路,所以候选就是服务器链本身。
func (s *SSOT) EnumerateServiceCandidates(access *Node, d *AccessDeclaration, svc *Service) ([]RouteCandidate, []CandidateSkip) {
	var skips []CandidateSkip
	skip := func(f string, a ...any) {
		skips = append(skips, CandidateSkip{Declaration: d.ID, Reason: fmt.Sprintf(f, a...)})
	}
	nodes := s.NodeByID()
	var out []RouteCandidate
	for _, chain := range s.candidateChains(access, d, nodes, skip) {
		out = append(out, RouteCandidate{
			Declaration: d.ID, Service: svc.ID,
			ServerChain: append([]string(nil), chain...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tag() < out[j].Tag() })
	return out, dedupSkips(skips)
}
