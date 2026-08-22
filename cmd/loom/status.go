package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/report"
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
	bad := 0
	// obs 汇总全网观测:自己量的、拉到的、以及**别人转述的** ——
	// 转述让够不到的节点也进得来(§16.1.2)。
	obs := map[string]report.Observation{}
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
		fmt.Printf("  %-7s %s %s\n", id, mark, tunnelLine(st))
		for _, l := range problemLines(st) {
			fmt.Printf("          %s\n", l)
		}
	}

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
	if bad > 0 {
		return fmt.Errorf("%d 个节点有发现", bad)
	}
	return nil
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
