package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"loom/internal/events"
	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/report"
	"loom/internal/version"
)

// status 是上报者的人看入口:从某个节点出发,把够得到的节点全拉一遍。
//
// 覆盖面由拓扑决定 —— AllowedIPs 是 /32,只能拉到隧道对端。够不到的节点会被
// **明确列出来**,而不是从表里悄悄消失:一张只有三行的表,看不出是"三台机器
// 都好"还是"还有两台没查"。
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	from := fs.String("from", "", "从哪个节点出发(默认取唯一的接入节点)")
	timeout := fs.Duration("timeout", 5*time.Second, "单个节点的拉取超时")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("需要一个 SSOT 文件路径")
	}
	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}

	vantage := *from
	if vantage == "" {
		acc := s.AccessNodes()
		if len(acc) != 1 {
			return fmt.Errorf("有 %d 个接入节点,需要 -from 指定从哪台出发", len(acc))
		}
		vantage = acc[0].ID
	}
	if s.NodeByID()[vantage] == nil {
		return fmt.Errorf("SSOT 里没有叫 %q 的节点", vantage)
	}

	// 够得到的 = 有隧道直连的对端。本机自己走本地文件,不必绕网络。
	reach := map[string]string{}
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		peer := ""
		switch vantage {
		case t.From:
			peer = t.To
		case t.To:
			peer = t.From
		default:
			continue
		}
		if a := s.TunnelAddrOn(peer, vantage); a != "" {
			reach[peer] = fmt.Sprintf("%s:%d", a, render.ReportPort)
		}
	}

	var unreachable []string
	for i := range s.Nodes {
		id := s.Nodes[i].ID
		if id != vantage && reach[id] == "" {
			unreachable = append(unreachable, id)
		}
	}
	sort.Strings(unreachable)

	ids := make([]string, 0, len(reach)+1)
	ids = append(ids, vantage)
	for id := range reach {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	fmt.Printf("从 %s 看到的状态\n\n", vantage)
	// 先说有没有未解决的、多久了。**"没有"也要说出来** —— 一片安静
	// 分不出"一切正常"和"这功能没在跑"。
	unresolved := printUnresolved(report.StatePath, report.EventsPath, time.Now())
	printLifecycle(s)
	bad := 0
	// obs 汇总全网观测:自己量的、拉到的、以及**别人转述的** ——
	// 转述让够不到的节点也进得来(§16.1.2)。
	obs := map[string]report.Observation{}
	snap := map[string]string{}
	// vcs 只装**直接问到的**节点。转述里没有版本坐标 —— 转述的是观测,
	// 不是身份。谁没问到下面会明说,不靠这张表的沉默去暗示。
	vcs := map[string]*version.Coordinate{}
	keep := func(o *report.Observation) {
		if o == nil || o.Node == "" {
			return
		}
		if old, ok := obs[o.Node]; ok && old.TS >= o.TS {
			return
		}
		obs[o.Node] = *o
	}

	for _, id := range ids {
		var st *report.Status
		var ferr error
		if id == vantage {
			st, ferr = localStatus()
		} else {
			st, ferr = report.Fetch(reach[id], *timeout)
		}
		if ferr != nil {
			bad++
			fmt.Printf("  %-7s ❌ 拉不到:%v\n", id, ferr)
			continue
		}
		keep(st.Observation)
		for i := range st.Learned {
			keep(&st.Learned[i])
		}
		mark := "✅"
		if !st.OK() {
			mark = "⚠️ "
			bad++
		}
		snap[id] = st.Applied
		if st.Version != nil {
			vcs[id] = st.Version
		}
		fmt.Printf("  %-7s %s %s\n", id, mark, tunnelLine(st))
		for _, l := range problemLines(st) {
			fmt.Printf("          %s\n", l)
		}
	}

	// 全网是不是同一版。落后的那台往往正是出问题的那台,而这件事以前
	// 只能逐台 ssh 去查。
	vers := snapshotSpread(obs, snap)
	if len(vers) > 1 {
		fmt.Printf("\n  ⚠️ 全网不是同一个快照:\n")
		var keys []string
		for k := range vers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sort.Strings(vers[k])
			fmt.Printf("      %-14s %s\n", short(k), strings.Join(vers[k], " "))
		}
		bad++
	} else if len(vers) == 1 {
		for k := range vers {
			fmt.Printf("\n  快照 %s(全网一致)\n", short(k))
		}
	}

	// 快照一致不等于版本一致。**旧二进制配新配置正是发布器崩掉的那类
	// 故障**(§15.4),而它在只看快照的表上完全看不出来。
	bad += printVersionSpread(vcs, ids)

	printMatrix(obs, s)

	var silent []string
	for _, id := range unreachable {
		if _, ok := obs[id]; !ok {
			silent = append(silent, id)
		}
	}
	if len(unreachable) > 0 {
		fmt.Printf("\n  与 %s 没有隧道、只能靠转述听到的:%s\n",
			vantage, strings.Join(unreachable, " "))
		fmt.Printf("  它们的配置自检仍然要本机跑:ssh <节点> loom report\n")
	}
	if len(silent) > 0 {
		fmt.Printf("  ⚠️ 完全没听到消息的:%s —— 转述链断了,或者它们的上报者没跑\n",
			strings.Join(silent, " "))
		bad += len(silent)
	}
	if bad > 0 || unresolved > 0 {
		return fmt.Errorf("%d 个节点有发现,%d 个未解决的问题", bad, unresolved)
	}
	return nil
}

// printUnresolved 打出**现在**还没解决的问题,以及各自持续了多久。
//
// **问题清单来自当前状态,时长来自事件历史。** 两个问题各问各的来源 ——
// 这是这一版与上一版的全部区别,而上一版两个都问事件历史,于是第一个
// 答错了:事件按定义只有变化,而上报者重启是静默播种的,所以**播种那一刻
// 已经坏掉的东西永远不会产生事件**,面板也就永远看不见它。
//
// **时长仍然是这里最有价值的信息。** "链路断了"看一眼节点表也知道;
// "断了两天了"只有事件历史能回答 —— 而那正是会让人立刻动手的那个数字。
// 事件历史里查不到起点时,给出下界并明确标成下界:"至少 9 小时"远比
// "未知"有用,而假装精确才是说谎。
func printUnresolved(statePath, eventsPath string, now time.Time) int {
	st, err := report.LoadTrackedState(statePath)
	if err != nil {
		fmt.Printf("  (读不到当前状态:%v)\n\n", err)
		return 0
	}
	if st == nil {
		// 中控之外的节点不记这些,这不是问题,只是这台机器不记。
		return 0
	}
	evs, err := events.Load(eventsPath)
	if err != nil {
		// 事件历史读不到只影响时长,不影响"有什么问题"。
		fmt.Printf("  (读不到事件历史,时长只能给下界:%v)\n", err)
	}

	all := report.UnresolvedNow(st, evs, now)
	var live, pending []report.Unresolved
	for _, u := range all {
		if u.Level == string(events.LevelPending) {
			pending = append(pending, u)
		} else {
			live = append(live, u)
		}
	}
	if len(live) == 0 && len(pending) == 0 {
		fmt.Printf("  ✅ 没有未解决的问题\n\n")
		return 0
	}
	for i, u := range live {
		if i == 0 {
			fmt.Printf("  ⚠️ 未解决(%d)\n", len(live))
		}
		fmt.Printf("     %-7s %-9s %-14s %-14s %s\n",
			u.Node, u.Kind, u.Subject, u.State, lastedText(u))
	}
	for _, u := range pending {
		fmt.Printf("  ⏳ %s %s %s —— %s\n", u.Node, u.Kind, u.Subject, u.Detail)
	}
	fmt.Println()
	return len(live)
}

// lastedText 把时长写成一句话。**下界必须标出来** —— 把"至少 9 小时"
// 写成"已 9 小时"就是在假装知道起点,而那正是面板说谎的方式。
func lastedText(u report.Unresolved) string {
	if u.AtLeast {
		return "至少 " + u.Lasted + "(上报者启动时已如此)"
	}
	return "已 " + u.Lasted
}

// printMatrix 打全网观测:谁能到哪个目标、节点之间多快。
//
// 这张表是链路状态测量的产出 —— 每台机器只量自己那几段,合起来就是全网视图。
// 接入时不必把每条完整路线跑一遍,照着它算就行。
func printMatrix(obs map[string]report.Observation, s *model.SSOT) {
	if len(obs) == 0 {
		fmt.Printf("\n  (还没有任何观测 —— 上报者刚起来?)\n")
		return
	}
	ids := make([]string, 0, len(obs))
	targets := map[string]bool{}
	for id, o := range obs {
		ids = append(ids, id)
		for _, r := range o.Targets {
			targets[r.Target] = true
		}
	}
	sort.Strings(ids)
	ts := make([]string, 0, len(targets))
	for t := range targets {
		ts = append(ts, t)
	}
	sort.Strings(ts)

	now := time.Now()
	for _, t := range ts {
		fmt.Printf("\n  各节点直接访问 %s\n", t)
		for _, id := range ids {
			o := obs[id]
			var line string
			for _, r := range o.Targets {
				if r.Target != t {
					continue
				}
				if r.OK() {
					line = fmt.Sprintf("✅ %dms", r.FirstByteMs)
				} else {
					line = "❌ " + shorten(r.Error)
				}
			}
			if line == "" {
				line = "(没量)"
			}
			fmt.Printf("    %-7s %-28s %s\n", id, line, ageNote(&o, now))
		}
	}

	fmt.Printf("\n  节点之间(隧道内 RTT)\n")
	for _, id := range ids {
		o := obs[id]
		if len(o.Edges) == 0 {
			continue
		}
		var parts []string
		for _, e := range o.Edges {
			if e.Error != "" {
				parts = append(parts, e.To+"=❌")
			} else {
				parts = append(parts, fmt.Sprintf("%s=%dms", e.To, e.RTTMs))
			}
		}
		fmt.Printf("    %-7s %s\n", id, strings.Join(parts, "  "))
	}
}

func ageNote(o *report.Observation, now time.Time) string {
	a := o.Age(now)
	if a < time.Minute {
		return ""
	}
	return fmt.Sprintf("(%d 分钟前的观测)", int(a.Minutes()))
}

func shorten(s string) string {
	if i := strings.LastIndex(s, ": "); i > 0 && len(s) > 30 {
		s = s[i+2:]
	}
	if len(s) > 26 {
		s = s[:26] + "…"
	}
	return s
}

func localStatus() (*report.Status, error) {
	b, err := os.ReadFile("/etc/loom/report/config.json")
	if err != nil {
		return nil, err
	}
	cfg, err := report.Load(b)
	if err != nil {
		return nil, err
	}
	return report.Collect(cfg, time.Now()), nil
}

func tunnelLine(st *report.Status) string {
	var parts []string
	for i := range st.Tunnels {
		t := &st.Tunnels[i]
		switch {
		case t.Down:
			parts = append(parts, t.Interface+"=down")
		case t.HandshakeAgeSec < 0:
			parts = append(parts, t.Interface+"=未握手")
		default:
			parts = append(parts, fmt.Sprintf("%s=%ds", t.Interface, t.HandshakeAgeSec))
		}
	}
	if len(parts) == 0 {
		return "(无隧道)"
	}
	return strings.Join(parts, "  ")
}

func problemLines(st *report.Status) []string {
	var out []string
	for i := range st.Tunnels {
		if t := &st.Tunnels[i]; t.Stale {
			out = append(out, fmt.Sprintf("⚠️ %s 握手已 %d 秒前", t.Interface, t.HandshakeAgeSec))
		}
	}
	if d := st.Drift; d != nil {
		for _, f := range d.Modified {
			out = append(out, "⚠️ 配置被改过:"+f)
		}
		for _, f := range d.Missing {
			out = append(out, "⚠️ 配置缺失:"+f)
		}
		for _, f := range d.Unreadable {
			out = append(out, "⚠️ 配置读不到:"+f)
		}
	}
	for _, e := range st.Errors {
		out = append(out, "⚠️ 采集错误:"+e)
	}
	return out
}

// printLifecycle 打出不在"正常"状态的节点,以及各自的下一步(§14.4)。
//
// 四个状态里有两个是**过渡态** —— 排空和下线都不该长期停在那儿。而"停在
// 那儿"没有任何症状:机器还在跑、隧道还通、校验也过。只有把"下一步是什么"
// 摆在眼前,才不会忘。
func printLifecycle(s *model.SSOT) {
	var drained, decom []*model.Node
	for i := range s.Nodes {
		n := &s.Nodes[i]
		switch {
		case n.Decommission:
			decom = append(decom, n)
		case n.Drain:
			drained = append(drained, n)
		}
	}
	if len(drained) == 0 && len(decom) == 0 {
		return
	}
	fmt.Printf("  ⏳ 生命周期\n")
	for _, n := range drained {
		fmt.Printf("     %-7s 已排空 —— 不再参与选路,但配置和隧道都还在(还能观测它)\n", n.ID)
		fmt.Printf("             下一步:确认替代节点在承载流量,再**同时**标 decommission、\n")
		fmt.Printf("                     删掉引用它的隧道(校验器要求这两件一起做)\n")
	}
	for _, n := range decom {
		fmt.Printf("     %-7s 已标记下线 —— 它读到停机指令后会自己停服务、禁自启\n", n.ID)
		fmt.Printf("             下一步:确认它停了,把节点本身从 SSOT 删掉;\n")
		held := credentialsHeldBy(s, n)
		if len(held) == 0 {
			fmt.Printf("                     它没配过任何凭据,不用轮换\n")
			continue
		}
		fmt.Printf("                     然后轮换它硬盘上留过明文的这几张凭据:\n")
		for _, c := range held {
			fmt.Printf("                     loom secrets rotate <ssot> -cred %s -secrets <总表>\n", c)
		}
	}
	fmt.Println()
}

// credentialsHeldBy 列出一台服务器硬盘上留过哪些凭据的明文。
//
// **这是移除节点之后必须轮换的清单**(§14.4)。忘了轮换不会有任何症状,
// 直到有人拿捡到的凭据连进来。
//
// 判据跟渲染器一致:一张凭据配在哪台机器上,取决于**候选链是否经过它**,
// 不是声明的 allowed_servers —— 后者只是"允许",经过才会真配上 user。
//
// 排空和下线的机器已经不进候选了,所以要按"假如它还在服役"来枚举 ——
// 问的是它硬盘上曾经有什么,不是现在还路由什么。
func credentialsHeldBy(s *model.SSOT, n *model.Node) []string {
	if !n.IsServer() {
		return nil
	}
	drain, decom := n.Drain, n.Decommission
	n.Drain, n.Decommission = false, false
	defer func() { n.Drain, n.Decommission = drain, decom }()

	decls := s.DeclarationByID()
	var out []string
	for i := range s.Credentials {
		c := &s.Credentials[i]
		if c.Revoked() {
			continue
		}
		d, ok := decls[c.Declaration]
		if !ok {
			continue
		}
		owner := s.AccessNodeForCredential(c.ID)
		if owner == nil {
			continue
		}
		cands, _ := s.EnumerateCandidates(owner, d)
		for j := range cands {
			if slices.Contains(cands[j].ServerChain, n.ID) {
				out = append(out, c.ID)
				break
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// snapshotSpread 把"哪台机器在哪个快照上"归并成 快照 -> 节点列表。
//
// **转述来的节点也要算进去。** 它们的 applied 就在观测里,以前却只统计了
// 直接拉到的那几台 —— 于是这张表少列了几行,而少列的方式是**静默的**:
// 落后的那台如果恰好够不到,你在这张表上根本看不见它,只会以为全网一致。
//
// direct 覆盖 obs:直接问到的比转听来的权威。
func snapshotSpread(obs map[string]report.Observation, direct map[string]string) map[string][]string {
	all := map[string]string{}
	for id, o := range obs {
		all[id] = o.Applied
	}
	for id, v := range direct {
		all[id] = v
	}
	vers := map[string][]string{}
	for id, v := range all {
		if v == "" {
			v = "(未记录)"
		}
		vers[v] = append(vers[v], id)
	}
	return vers
}

// printVersionSpread 报告全网跑的是不是同一版二进制,返回要计入 bad 的条数。
//
// 它和 snapshotSpread 是一对,但**不能合并**:快照说配置是哪一版,版本说
// 读这份配置的程序是哪一版。二者错配(旧程序 + 新配置)是已经发生过两次
// 的故障 —— services 字段一次,retired_ports 字段一次 —— 而只看快照的表
// 对这类故障完全是盲的。
//
// missing 单独列出来,因为**问不到与"一致"必须分得开**:如果把没答上的
// 节点当成沉默的同意,一台跑着老二进制却够不到的机器会以为它没问题。
func printVersionSpread(vcs map[string]*version.Coordinate, ids []string) int {
	if len(vcs) == 0 {
		return 0
	}
	byCommit := map[string][]string{}
	var dirty, unknown []string
	for id, c := range vcs {
		k := c.Commit
		if k == "" {
			k = "(认不出 commit)"
			unknown = append(unknown, id)
		}
		byCommit[k] = append(byCommit[k], id)
		if c.Dirty {
			dirty = append(dirty, id)
		}
	}

	bad := 0
	keys := make([]string, 0, len(byCommit))
	for k := range byCommit {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if len(keys) > 1 {
		fmt.Printf("\n  ⚠️ 全网不是同一个 commit:\n")
		for _, k := range keys {
			sort.Strings(byCommit[k])
			fmt.Printf("      %-14s %s\n", version.Short(k), strings.Join(byCommit[k], " "))
		}
		bad++
	} else {
		fmt.Printf("\n  commit %s(问到的都一致)\n", version.Short(keys[0]))
	}

	if len(dirty) > 0 {
		sort.Strings(dirty)
		fmt.Printf("  ⚠️ 构建自脏工作区,对不上任何 commit:%s\n", strings.Join(dirty, " "))
		bad++
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		fmt.Printf("  ⚠️ 认不出自己 commit 的节点:%s —— 追溯不回 git\n", strings.Join(unknown, " "))
	}

	var missing []string
	for _, id := range ids {
		if _, ok := vcs[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		fmt.Printf("  (没问到版本的:%s —— 拉不到,或者它跑的上报者还不带版本坐标)\n",
			strings.Join(slices.Compact(missing), " "))
	}
	return bad
}
