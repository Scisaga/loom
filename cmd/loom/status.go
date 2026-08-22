package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

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

	if len(unreachable) > 0 {
		fmt.Printf("\n  够不到(与 %s 之间没有隧道,AllowedIPs 是 /32):%s\n",
			vantage, strings.Join(unreachable, " "))
		fmt.Printf("  它们的隧道健康仍然是覆盖到的 —— 每条隧道的另一端都在上面的节点里。\n")
		fmt.Printf("  没覆盖到的是它们各自的配置自检:ssh <节点> loom report\n")
	}
	if bad > 0 {
		return fmt.Errorf("%d 个节点有发现", bad)
	}
	return nil
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
