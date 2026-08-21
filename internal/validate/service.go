package validate

import (
	"fmt"

	"loom/internal/model"
)

// checkService 校验服务与调度模型。
//
// 这里实现的是 §19"校验器必须拒绝的矛盾配置"表里依赖等价类与访问声明的
// 那几条 —— 它们无法在只有拓扑的阶段实现,因此曾长期缺失。
func checkService(s *model.SSOT, nodes map[string]*model.Node, fs *findings) {
	classes := checkClasses(s, nodes, fs)
	decls := checkDeclarations(s, nodes, classes, fs)
	creds := checkCredentials(s, decls, fs)
	checkProfiles(s, decls, creds, fs)
}

func checkClasses(s *model.SSOT, nodes map[string]*model.Node, fs *findings) map[string]*model.EquivalenceClass {
	idx := map[string]*model.EquivalenceClass{}
	for i := range s.EquivalenceClasses {
		c := &s.EquivalenceClasses[i]
		where := "class:" + c.ID
		if c.ID == "" {
			where = fmt.Sprintf("equivalence_classes[%d]", i)
			fs.add("§19 schema", where, "等价类缺少 id")
		}
		if _, dup := idx[c.ID]; dup && c.ID != "" {
			fs.add("§19 schema", where, "等价类 id 重复")
		}
		if c.ID != "" {
			idx[c.ID] = c
		}

		if !c.Carrier.Valid() {
			fs.add("§4.4 carrier", where, "未知 carrier:%q(只能是 l4_direct/l7_gateway/sdk)", c.Carrier)
		}
		if !c.ObservationPoint.Valid() {
			fs.add("§16.2 观测点", where, "未知 observation_point:%q", c.ObservationPoint)
		}
		if len(c.Members) == 0 {
			fs.add("§4.3 等价类", where, "成员为空")
		}

		seenMember := map[string]bool{}
		for _, m := range c.Members {
			n, ok := nodes[m.Node]
			if !ok {
				fs.add("§4.3 等价类", where, "成员引用了不存在的节点 %q", m.Node)
				continue
			}
			if seenMember[m.Node] {
				fs.add("§4.3 等价类", where, "成员 %q 重复", m.Node)
			}
			seenMember[m.Node] = true
			if !n.Has(model.Target) {
				fs.add("§4.3 等价类", where, "成员 %q 不持有 target 能力", m.Node)
			}
		}

		// §19 必拒规则:carrier: l4_direct 但成员 access_contract 不同构。
		//
		// 这是 §4.4 的不变量在校验层的落点。数据平面只做 L4 选路、不改写
		// 连接内容,所以契约不同构时换端点会在 TLS 或鉴权层直接失败 ——
		// 而那是运行时才会暴露的失败。
		if c.Carrier == model.L4Direct && len(c.Members) > 1 {
			base := c.Members[0]
			for _, m := range c.Members[1:] {
				if !base.Contract.SameAs(m.Contract) {
					fs.add("§4.4 契约同构", where,
						"carrier 是 l4_direct,但成员 %q 与 %q 的 access_contract 不同构 —— "+
							"L4 换端点会在 TLS 或鉴权层失败,这类成员需要 l7_gateway 承载",
						m.Node, base.Node)
					break
				}
			}
		}
	}
	return idx
}

func checkDeclarations(
	s *model.SSOT,
	nodes map[string]*model.Node,
	classes map[string]*model.EquivalenceClass,
	fs *findings,
) map[string]*model.AccessDeclaration {
	idx := map[string]*model.AccessDeclaration{}
	for i := range s.Declarations {
		d := &s.Declarations[i]
		where := "decl:" + d.ID
		if d.ID == "" {
			where = fmt.Sprintf("declarations[%d]", i)
			fs.add("§19 schema", where, "访问声明缺少 id")
		}
		if _, dup := idx[d.ID]; dup && d.ID != "" {
			fs.add("§19 schema", where, "访问声明 id 重复")
		}
		if d.ID != "" {
			idx[d.ID] = d
		}

		if !d.Mode.Valid() {
			fs.add("§4 mode", where, "未知 mode:%q", d.Mode)
		}
		if !d.Objective.Valid() {
			fs.add("§5.3 objective", where, "未知 objective:%q", d.Objective)
		}
		if !d.Fallback.Valid() {
			fs.add("§5.8 fallback", where, "未知 fallback:%q", d.Fallback)
		}
		if d.MaxHops < 0 {
			fs.add("§3.2 max_hops", where, "max_hops 不能为负:%d", d.MaxHops)
		}
		if d.TuningPeriod == "" {
			fs.add("§5.5 周期", where, "缺少 tuning_period —— 中继轴始终需要度量(§4)")
		}
		for _, c := range d.Constraints {
			if !c.Kind.Valid() {
				fs.add("§5.1 约束", where, "未知约束类别:%q", c.Kind)
			}
		}
		for _, r := range d.AllowedRelays {
			n, ok := nodes[r]
			if !ok {
				fs.add("§5.1 约束", where, "allowed_relays 引用了不存在的节点 %q", r)
				continue
			}
			if !n.Has(model.Relay) {
				fs.add("§5.1 约束", where, "allowed_relays 中的 %q 不持有 relay 能力", r)
			}
		}

		checkModeShape(d, where, nodes, classes, fs)

		// §19 必拒规则:有合规约束但 fallback ≠ fail_closed。
		//
		// §5.1 规定合规是约束不是评分项。候选集若因合规过滤而变空,
		// 任何"退而求其次"的自动回退都等于绕过约束。
		if d.HasCompliance() && d.Fallback != model.FailClosed {
			fs.add("§5.8 fallback", where,
				"带合规约束却把 fallback 设成 %q —— 合规是约束不是评分项(§5.1),"+
					"空候选集时自动回退等于绕过它;必须是 fail_closed", d.Fallback)
		}

		// §19 必拒规则:模式 A 声明配置了 ranking_period。
		//
		// 模式 A 的候选集里 target 是常量,排序周期无意义。允许它存在
		// 会让人以为配了就生效。
		if d.Mode == model.PinnedTarget && d.RankingPeriod != "" {
			fs.add("§5.5 周期", where,
				"模式 A 配置了 ranking_period=%q,但目标轴已退化为常量,排序周期无意义;"+
					"只需 tuning_period", d.RankingPeriod)
		}

		checkObjectiveFeasible(d, where, classes, fs)
	}
	return idx
}

// checkModeShape 检查模式 A/B 各自该有和不该有的字段。
func checkModeShape(
	d *model.AccessDeclaration,
	where string,
	nodes map[string]*model.Node,
	classes map[string]*model.EquivalenceClass,
	fs *findings,
) {
	switch d.Mode {
	case model.PinnedTarget:
		if d.TargetNode == "" {
			fs.add("§4.1 模式A", where, "模式 A 缺少 target_node")
		} else if n, ok := nodes[d.TargetNode]; !ok {
			fs.add("§4.1 模式A", where, "target_node 引用了不存在的节点 %q", d.TargetNode)
		} else if !n.Has(model.Target) {
			fs.add("§4.1 模式A", where, "target_node %q 不持有 target 能力", d.TargetNode)
		}
		if d.EquivalenceClass != "" {
			fs.add("§4 mode", where, "模式 A 不应声明 equivalence_class —— 目标轴已钉死")
		}
	case model.ByService:
		if d.EquivalenceClass == "" {
			fs.add("§4.2 模式B", where, "模式 B 缺少 equivalence_class")
		} else if _, ok := classes[d.EquivalenceClass]; !ok {
			fs.add("§4.2 模式B", where, "equivalence_class 引用了不存在的等价类 %q", d.EquivalenceClass)
		}
		if d.TargetNode != "" {
			fs.add("§4 mode", where, "模式 B 不应声明 target_node —— 目标由度量在候选集内选")
		}
		if d.TopN <= 0 {
			fs.add("§5.6 top_n", where, "模式 B 需要显式声明 top_n(下发给接入节点的候选数)")
		}
	}
}

// checkObjectiveFeasible 检查目标函数要的量是否真有人产出。
//
// §19 必拒规则:objective: ttft 但候选缺少 L7 观测点。
// §5.3 补注:ttft 与 cost 都不是 L4 能自己测出来的。
func checkObjectiveFeasible(
	d *model.AccessDeclaration,
	where string,
	classes map[string]*model.EquivalenceClass,
	fs *findings,
) {
	if d.Mode != model.ByService || d.EquivalenceClass == "" {
		// 模式 A 的目标轴是常量,不在目标轴上做应用层选优。
		return
	}
	c, ok := classes[d.EquivalenceClass]
	if !ok {
		return // 引用错误已在别处报出
	}

	if d.Objective.NeedsL7() && !c.ObservationPoint.IsL7() {
		fs.add("§16.2 观测点", where,
			"objective 是 %s,但等价类 %q 的 observation_point 是 l4_tunnel —— "+
				"tokens/s 与响应结构不是 L4 能被动观测的量;"+
				"首字节返回时间只是 TTFT 的近似,不能当它用",
			d.Objective, c.ID)
	}
	if d.Objective.NeedsPrice() && c.PriceSource == "" {
		fs.add("§5.2 声明值", where,
			"objective 是 cost,但等价类 %q 没有 price_source —— 价格是声明值,"+
				"不会从度量里长出来", c.ID)
	}
}

func checkCredentials(
	s *model.SSOT,
	decls map[string]*model.AccessDeclaration,
	fs *findings,
) map[string]*model.Credential {
	idx := map[string]*model.Credential{}
	for i := range s.Credentials {
		c := &s.Credentials[i]
		where := "cred:" + c.ID
		if c.ID == "" {
			where = fmt.Sprintf("credentials[%d]", i)
			fs.add("§19 schema", where, "凭据缺少 id")
		}
		if _, dup := idx[c.ID]; dup && c.ID != "" {
			fs.add("§19 schema", where, "凭据 id 重复")
		}
		if c.ID != "" {
			idx[c.ID] = c
		}

		if c.SecretRef == "" {
			fs.add("§13.1 密钥", where, "缺少 secret_ref")
		}
		if c.Declaration == "" {
			fs.add("§8.2 凭据", where, "凭据未绑定访问声明 —— 凭据即访问声明")
		} else if _, ok := decls[c.Declaration]; !ok {
			fs.add("§8.2 凭据", where, "引用了不存在的访问声明 %q", c.Declaration)
		}
	}
	return idx
}

func checkProfiles(
	s *model.SSOT,
	decls map[string]*model.AccessDeclaration,
	creds map[string]*model.Credential,
	fs *findings,
) {
	seen := map[string]bool{}
	for i := range s.Profiles {
		p := &s.Profiles[i]
		where := "profile:" + p.ID
		if p.ID == "" {
			where = fmt.Sprintf("profiles[%d]", i)
			fs.add("§19 schema", where, "客户端档案缺少 id")
		}
		if seen[p.ID] && p.ID != "" {
			fs.add("§19 schema", where, "客户端档案 id 重复")
		}
		seen[p.ID] = true

		if !p.Platform.Valid() {
			fs.add("§7.2 平台", where, "未知 platform:%q", p.Platform)
			continue
		}

		if len(p.Credentials) == 0 {
			fs.add("§8.2 凭据", where, "档案未持有任何凭据")
		}
		for _, id := range p.Credentials {
			c, ok := creds[id]
			if !ok {
				fs.add("§8.2 凭据", where, "引用了不存在的凭据 %q", id)
				continue
			}
			if c.Revoked() {
				fs.add("§18 凭据", where, "引用了已吊销的凭据 %q(revoked_at=%s)", id, c.RevokedAt)
			}
		}

		// §7.2 / §18:Android 绝大多数 App 不能单独设代理,因此必须 TUN
		// 且只带一把凭据 —— 没有"按端口选声明"这回事。
		if p.Platform == model.Android {
			if len(p.MixedPorts) > 0 {
				fs.add("§7.2 平台", where,
					"Android 档案不应声明 mixed_ports —— 绝大多数 App 不能单独设代理,只能走 TUN")
			}
			if len(p.Credentials) > 1 {
				fs.add("§18 模板", where,
					"Android 档案持有 %d 把凭据,但只有 TUN 一个出口,无法按端口区分声明",
					len(p.Credentials))
			}
		}
		// §7.2:Linux 服务器不开 TUN,流量全靠 mixed 端口接管。
		if p.Platform == model.LinuxServer && len(p.MixedPorts) == 0 {
			fs.add("§7.2 平台", where,
				"linux-server 档案没有 mixed_ports —— 它不开 TUN,没有端口就接管不到任何流量")
		}

		seenPort := map[int]bool{}
		for _, mp := range p.MixedPorts {
			if mp.Port <= 0 || mp.Port > 65535 {
				fs.add("§7.3 端口", where, "mixed 端口非法:%d", mp.Port)
			}
			if seenPort[mp.Port] {
				fs.add("§7.3 端口", where, "mixed 端口 %d 重复", mp.Port)
			}
			seenPort[mp.Port] = true
			if _, ok := decls[mp.Declaration]; !ok {
				fs.add("§7.3 端口", where,
					"端口 %d 绑定了不存在的访问声明 %q", mp.Port, mp.Declaration)
			}
		}
	}
}
