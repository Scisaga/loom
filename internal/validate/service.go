package validate

import (
	"fmt"
	"strings"
	"time"

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
	checkAccessNodes(s, decls, creds, fs)
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
		for i := range c.Members {
			m := &c.Members[i]
			if m.Address == "" {
				fs.add("§4.3 等价类", where, "成员缺少 address")
				continue
			}
			if seenMember[m.Address] {
				fs.add("§4.3 等价类", where, "成员地址 %q 重复", m.Address)
			}
			seenMember[m.Address] = true
			// 目标是地址,不是节点(§1)。把节点 id 写进 members 是把模型
			// 层次搞混的典型症状,单独报出来。
			if _, isNode := nodes[m.Address]; isNode {
				fs.add("§1 目标不是节点", where,
					"成员 %q 是一个节点 id —— members 里应当是**地址**(如 https://…)。"+
						"目标不是节点,不进拓扑、不参与渲染(§9)", m.Address)
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
							"L4 换地址会在 TLS 或鉴权层失败,这类成员需要 l7_gateway 承载",
						m.Address, base.Address)
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

		addrOK, egressOK := d.AxesValid()
		if !addrOK {
			fs.add("§4 地址轴", where,
				"address_axis 非法:%q —— 只能是 from_request 或 class:<等价类 id>", d.AddressAxis)
		}
		if !egressOK {
			fs.add("§4 出口轴", where,
				"egress_axis 非法:%q —— 只能是 any 或 pinned:<节点 id>", d.EgressAxis)
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
		if d.ProbeURL == "" {
			fs.add("§16.2 探测", where,
				"没有 probe_url —— 探测目标不代表这条声明承载的流量时,"+
					"会把根本不通的候选排在第一位(实测:同一条直连候选到 gstatic "+
					"55ms、到 Cloudflare 超时 10 秒)")
		}
		if d.TuningPeriod == "" {
			fs.add("§5.5 周期", where, "缺少 tuning_period —— 中继轴始终需要度量(§4)")
		}
		checkTuningLoop(fs, where, d)
		// 把声明钉死的出口排空了,这条声明就一个候选都没有 —— 流量直接
		// 被阻断。排空的本意是"迁移期间先别用它",而不是"把这条声明关掉";
		// 真要关,该改 egress_axis 或者删掉声明。
		if p := d.PinnedEgress(); p != "" {
			if n, ok := nodes[p]; ok && n.Decommission {
				fs.add("§14.4 下线", where,
					"egress_axis 钉死在 %q,而 %q 已标记下线 —— 这条声明将没有任何候选。"+
						"下线一台机器之前,先把指向它的声明改掉", p, p)
			}
			if n, ok := nodes[p]; ok && n.Drain {
				fs.add("§5.8 排空", where,
					"egress_axis 钉死在 %q,而 %q 已排空(drain)—— 这条声明将没有任何候选,"+
						"流量会被阻断。迁移时应当先把 egress_axis 改指向新节点,再排空旧的", p, p)
			}
		}
		for _, c := range d.Constraints {
			if !c.Kind.Valid() {
				fs.add("§5.1 约束", where, "未知约束类别:%q", c.Kind)
			}
		}
		allowedSet := map[string]bool{}
		for _, r := range d.AllowedServers {
			allowedSet[r] = true
			n, ok := nodes[r]
			if !ok {
				fs.add("§5.1 约束", where, "allowed_servers 引用了不存在的节点 %q", r)
				continue
			}
			if !n.IsServer() {
				fs.add("§5.1 约束", where, "allowed_servers 中的 %q 不持有 server 能力", r)
			}
		}

		checkAxes(d, where, nodes, classes, allowedSet, fs)

		// §19 必拒规则:有合规约束但 fallback ≠ fail_closed。
		//
		// §5.1 规定合规是约束不是评分项。候选集若因合规过滤而变空,
		// 任何"退而求其次"的自动回退都等于绕过约束。
		if d.HasCompliance() && d.Fallback != model.FailClosed {
			fs.add("§5.8 fallback", where,
				"带合规约束却把 fallback 设成 %q —— 合规是约束不是评分项(§5.1),"+
					"空候选集时自动回退等于绕过它;必须是 fail_closed", d.Fallback)
		}

		// §19 必拒规则:地址由请求决定却配置了 ranking_period。
		//
		// 那时地址轴是常量,排序周期无意义。允许它存在会让人以为配了就生效。
		if d.AddressFromRequest() && d.RankingPeriod != "" {
			fs.add("§5.5 周期", where,
				"address_axis 是 from_request 却配置了 ranking_period=%q —— "+
					"地址轴已是常量,排序周期无意义;只需 tuning_period", d.RankingPeriod)
		}

		checkObjectiveFeasible(d, where, classes, fs)
	}
	return idx
}

// checkAxes 检查两个轴各自的取值是否自洽(§4)。
func checkAxes(
	d *model.AccessDeclaration,
	where string,
	nodes map[string]*model.Node,
	classes map[string]*model.EquivalenceClass,
	allowed map[string]bool,
	fs *findings,
) {
	if cid := d.ClassID(); cid != "" {
		if _, ok := classes[cid]; !ok {
			fs.add("§4 地址轴", where, "address_axis 引用了不存在的等价类 %q", cid)
		}
		if d.TopN <= 0 {
			fs.add("§5.6 top_n", where,
				"地址从等价类里选时需要显式声明 top_n(下发给接入节点的候选数)")
		}
	}

	pinned := d.PinnedEgress()
	if pinned == "" {
		return
	}
	n, ok := nodes[pinned]
	switch {
	case !ok:
		fs.add("§4 出口轴", where, "egress_axis 钉死了不存在的节点 %q", pinned)
	case !n.IsServer():
		fs.add("§4 出口轴", where, "钉死的出口 %q 不持有 server 能力", pinned)
	case !n.Server.EgressCapable:
		fs.add("§4 出口轴", where,
			"钉死的出口 %q 没有 egress_capable —— 它出不了公网", pinned)
	}
	// 钉死一个不在允许集合里的出口,是自相矛盾的声明。
	if len(allowed) > 0 && !allowed[pinned] {
		fs.add("§5.1 约束", where,
			"egress_axis 钉死了 %q,但它不在 allowed_servers 里", pinned)
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
	cid := d.ClassID()
	if cid == "" {
		// 地址由请求决定时地址轴是常量,不在地址轴上做应用层选优。
		return
	}
	c, ok := classes[cid]
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
		// 一张凭据只能属于一个接入节点 —— 服务器要按凭据反查候选集,
		// 共用会让它查到错误的那一份。
		var owners []string
		for _, a := range s.AccessNodes() {
			for _, id := range a.Access.Credentials {
				if id == c.ID {
					owners = append(owners, a.ID)
				}
			}
		}
		if len(owners) > 1 {
			fs.add("§8.2 凭据", where,
				"被多个接入节点共用(%v)—— 候选集因接入节点而异,共用会让服务器"+
					"查到错误的那一份", owners)
		}

		if c.Declaration == "" {
			fs.add("§8.2 凭据", where, "凭据未绑定访问声明 —— 凭据即访问声明")
		} else if _, ok := decls[c.Declaration]; !ok {
			fs.add("§8.2 凭据", where, "引用了不存在的访问声明 %q", c.Declaration)
		}
	}
	return idx
}

// checkAccessNodes 校验接入节点特有的字段(§7、§18)。
func checkAccessNodes(
	s *model.SSOT,
	decls map[string]*model.AccessDeclaration,
	creds map[string]*model.Credential,
	fs *findings,
) {
	for _, p := range s.AccessNodes() {
		where := p.ID

		if !p.Access.Platform.Valid() {
			fs.add("§7.2 平台", where, "接入节点缺少或写错 platform:%q", p.Access.Platform)
			continue
		}

		if len(p.Access.Credentials) == 0 {
			fs.add("§8.2 凭据", where, "接入节点未持有任何凭据")
		}
		for _, id := range p.Access.Credentials {
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
		if p.Access.Platform == model.Android {
			if len(p.Access.MixedPorts) > 0 {
				fs.add("§7.2 平台", where,
					"Android 不应声明 mixed_ports —— 绝大多数 App 不能单独设代理,只能走 TUN")
			}
			if len(p.Access.Credentials) > 1 {
				fs.add("§18 模板", where,
					"Android 持有 %d 把凭据,但只有 TUN 一个出口,无法按端口区分声明",
					len(p.Access.Credentials))
			}
		}
		// §7.2:Linux 服务器不开 TUN,流量全靠 mixed 端口接管。
		if p.Access.Platform == model.LinuxServer && len(p.Access.MixedPorts) == 0 {
			fs.add("§7.2 平台", where,
				"linux-server 没有 mixed_ports —— 它不开 TUN,没有端口就接管不到任何流量")
		}

		// §7.2:用 TUN 的平台必须说清兜底流量走哪条声明。
		if p.Access.Platform.UsesTUN() {
			switch {
			case p.Access.DefaultDeclaration == "" && len(p.Access.Credentials) > 1:
				fs.add("§7.2 平台", where,
					"用 TUN 但未声明 default_declaration,且持有 %d 把凭据 —— "+
						"兜底流量走哪条声明是歧义的,必须显式写出", len(p.Access.Credentials))
			case p.Access.DefaultDeclaration != "":
				if _, ok := decls[p.Access.DefaultDeclaration]; !ok {
					fs.add("§7.2 平台", where,
						"default_declaration 引用了不存在的访问声明 %q", p.Access.DefaultDeclaration)
				}
			}
		} else if p.Access.DefaultDeclaration != "" {
			fs.add("§7.2 平台", where,
				"%s 不使用 TUN,声明 default_declaration 不会生效", p.Access.Platform)
		}

		// 端口桶要覆盖同一台机器上的全部监听,不只是 mixed 之间。
		// 一个节点同时有 server 块时,inbound_port 也在这台机器上 ——
		// 两个进程抢同一个端口,后起的那个静默失败。
		seenPort := map[int]string{}
		if p.IsServer() && p.Server.InboundPort > 0 {
			seenPort[p.Server.InboundPort] = "server 的 inbound_port"
		}
		for _, mp := range p.Access.MixedPorts {
			if mp.Port <= 0 || mp.Port > 65535 {
				fs.add("§7.3 端口", where, "mixed 端口非法:%d", mp.Port)
			}
			if owner, dup := seenPort[mp.Port]; dup {
				fs.add("§7.3 端口冲突", where, "mixed 端口 %d 已被%s占用", mp.Port, owner)
			}
			seenPort[mp.Port] = "另一个 mixed 端口"
			if _, ok := decls[mp.Declaration]; !ok && !mp.ByService() {
				// 按服务分流的端口不绑声明,由 checkServicePorts 管(§4.5)。
				fs.add("§7.3 端口", where,
					"端口 %d 绑定了不存在的访问声明 %q", mp.Port, mp.Declaration)
			}
		}
	}
}

// checkTuningLoop 检查这条声明描述的调参回路能不能真的转起来。
//
// 主动探测的采样率就是 tuning_period(一轮一条候选一个样本),所以窗口里
// 最多装得下 window/tuning_period 个样本。这个数小于 min_samples 时,**没有
// 任何候选能达到参选门槛,排序永远不会启动** —— 配置看着完整,回路却是死的,
// 而且从日志上只能看到"没有候选达到 min_samples",看不出是配置本身不可能满足。
//
// 实测踩过:tuning_period=5m、window=5m、min_samples=20 —— 窗口里只装得下
// 1 个样本,却要求 20 个。
func checkTuningLoop(fs *findings, where string, d *model.AccessDeclaration) {
	period, perr := time.ParseDuration(d.TuningPeriod)
	window, werr := time.ParseDuration(d.Window)
	if d.TuningPeriod != "" && perr != nil {
		fs.add("§5.5 周期", where, "tuning_period 无法解析:%q", d.TuningPeriod)
	}
	if d.Window != "" && werr != nil {
		fs.add("§5.4 窗口", where, "window 无法解析:%q", d.Window)
	}
	if d.StaleAfter != "" {
		st, err := time.ParseDuration(d.StaleAfter)
		if err != nil {
			fs.add("§5.8 陈旧", where, "stale_after 无法解析:%q", d.StaleAfter)
		} else if perr == nil && period > 0 && st < period {
			// 数据比 tuning_period 老就算陈旧的话,每一轮探测完的下一刻
			// 全部候选都是陈旧的 —— 等于关掉了排序。
			fs.add("§5.8 陈旧", where,
				"stale_after=%s 小于 tuning_period=%s —— 每轮探测的结果立刻就过期,排序拿不到任何数据",
				d.StaleAfter, d.TuningPeriod)
		}
	}
	if d.SwitchThreshold < 0 || d.SwitchThreshold >= 1 {
		fs.add("§5.5 阻尼", where,
			"switch_threshold=%v 不在 [0,1) 内 —— 它是相对改善幅度,不是绝对值",
			d.SwitchThreshold)
	}
	if d.MinSamples < 0 {
		fs.add("§5.4 窗口", where, "min_samples 不能为负:%d", d.MinSamples)
	}
	if perr != nil || werr != nil || period <= 0 || window <= 0 {
		return
	}
	if cap := int(window / period); cap < d.MinSamples {
		fs.add("§5.4 窗口", where,
			"window=%s 按 tuning_period=%s 采样最多装 %d 个样本,达不到 min_samples=%d —— "+
				"排序永远不会启动。要么把 window 放大到 %s 以上,要么把 min_samples 调到 %d 以内",
			d.Window, d.TuningPeriod, cap, d.MinSamples,
			(time.Duration(d.MinSamples) * period).String(), cap)
	}
}

// checkDrain 检查排空是否把系统推到了不可用的状态。
//
// 排空是"先别用它",不是"把它关掉"。区别在于:排空之后应当**还有别的路**。
// 一台机器被排空而它是某条声明唯一的出口,那不是排空,是断服。
func checkDrain(fs *findings, s *model.SSOT) {
	// 下线的节点还挂着隧道,说明删除只做了一半 —— 对端会继续尝试连一台
	// 正在停机的机器,而 `loom status` 上会一直挂着一条查不出原因的告警。
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		for _, id := range []string{t.From, t.To} {
			if n, ok := s.NodeByID()[id]; ok && n.Decommission {
				fs.add("§14.4 下线", "tunnel:"+t.Pair(),
					"%q 已标记下线,却仍有隧道引用它 —— 下线之后应当把相关隧道一并删掉", id)
			}
		}
	}

	var drained []string
	for i := range s.Nodes {
		if s.Nodes[i].Drain {
			drained = append(drained, s.Nodes[i].ID)
			if !s.Nodes[i].IsServer() {
				fs.add("§5.8 排空", "node:"+s.Nodes[i].ID,
					"drain 只对服务器有意义 —— 接入节点不出现在候选里,排空它什么也不改变")
			}
		}
	}
	if len(drained) == 0 {
		return
	}
	// 全部服务器都排空了,等于全网停服。这大概率是手误(比如复制粘贴时
	// 多带了一行),值得单独喊一声。
	live := 0
	for i := range s.Nodes {
		if s.Nodes[i].IsServer() && s.Nodes[i].Server.EgressCapable && !s.Nodes[i].Drain {
			live++
		}
	}
	if live == 0 {
		fs.add("§5.8 排空", "全局",
			"所有能当出口的服务器都被排空了(%s)—— 全网没有任何可用候选",
			strings.Join(drained, " "))
	}
}
