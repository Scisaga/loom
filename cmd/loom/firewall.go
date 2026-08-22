package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"

	"loom/internal/model"
)

// 防火墙规则和配置文件一样,是 SSOT 的纯函数。手抄一遍等于把 §20.1 说的
// 那类错误换个地方再犯一次 —— 而且防火墙配错的表现同样是"静默不通"。

type fwRule struct {
	Port  string
	Proto string
	From  []string
	Why   string
}

func cmdFirewall(args []string) error {
	fs := flag.NewFlagSet("firewall", flag.ExitOnError)
	access := fs.String("access", "<你的接入设备>", "接入节点的来源地址,用于生成入站规则")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("需要一个 SSOT 文件路径")
	}
	s, err := model.LoadFile(rest[0])
	if err != nil {
		return err
	}
	nodes := s.NodeByID()

	byNode := map[string][]fwRule{}
	add := func(node string, r fwRule) { byNode[node] = append(byNode[node], r) }

	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.Has(model.Server) {
			continue
		}
		add(n.ID, fwRule{Port: "22", Proto: "TCP", From: []string{"<你的运维来源>"}, Why: "SSH"})
	}

	// 隧道端口只在接受方生效,来源就是发起方那一个 IP —— reverse_only 顺带
	// 带来的好处:这个端口对全世界都是关的,只对一台机器开一条缝。
	tunnels, err := s.ResolveAll()
	if err != nil {
		return err
	}
	for _, t := range tunnels {
		add(t.Acceptor.ID, fwRule{
			Port: fmt.Sprint(t.ListenPort), Proto: "UDP",
			From: []string{t.Initiator.PublicEndpoint},
			Why:  fmt.Sprintf("WireGuard 隧道,%s 拨进来", t.Initiator.ID),
		})
	}

	// inbound_port 的来源:接入节点,加上所有可能把流量转发给它的服务器。
	upstream := map[string]map[string]bool{}
	for i := range s.Declarations {
		cands, _ := s.EnumerateCandidates(&s.Declarations[i])
		for j := range cands {
			chain := cands[j].ServerChain
			for k := range chain {
				if upstream[chain[k]] == nil {
					upstream[chain[k]] = map[string]bool{}
				}
				if k == 0 {
					upstream[chain[k]]["access"] = true
					continue
				}
				upstream[chain[k]][chain[k-1]] = true
			}
		}
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.Has(model.Server) || n.InboundPort == 0 {
			continue
		}
		var from []string
		viaTunnelOnly := true
		for src := range upstream[n.ID] {
			if src == "access" {
				from = append(from, *access)
				viaTunnelOnly = false
				continue
			}
			// 经隧道到达的不需要公网放行 —— 它走的是隧道内地址。
			if s.TunnelAddrOn(n.ID, src) != "" {
				continue
			}
			from = append(from, fmt.Sprintf("%s(%s)", nodes[src].PublicEndpoint, src))
			viaTunnelOnly = false
		}
		if viaTunnelOnly || len(from) == 0 {
			proto := "UDP"
			if !n.InboundProtocol.IsUDP() {
				proto = "TCP"
			}
			add(n.ID, fwRule{
				Port: fmt.Sprint(n.InboundPort), Proto: proto, From: nil,
				Why: "只经隧道内地址到达,**公网无需放行**",
			})
			continue
		}
		sort.Strings(from)
		proto, why := "UDP", "Hysteria2 入站(QUIC)"
		if !n.InboundProtocol.IsUDP() {
			proto, why = "TCP", string(n.InboundProtocol.Or())+" 入站"
		}
		add(n.ID, fwRule{Port: fmt.Sprint(n.InboundPort), Proto: proto, From: from, Why: why})
	}

	ids := make([]string, 0, len(byNode))
	for id := range byNode {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		n := nodes[id]
		fmt.Printf("\n### %s  %s(%s)\n\n", id, n.PublicEndpoint, n.City)
		rules := byNode[id]
		sort.Slice(rules, func(i, j int) bool { return rules[i].Port < rules[j].Port })
		fmt.Printf("  %-8s %-6s %-46s %s\n", "端口", "协议", "来源", "用途")
		for _, r := range rules {
			src := strings.Join(r.From, ", ")
			if src == "" {
				src = "—"
			}
			fmt.Printf("  %-8s %-6s %-46s %s\n", r.Port, r.Proto, src, r.Why)
		}
		if n.Direction == model.ReverseOnly {
			fmt.Printf("\n  ↑ 这台是 reverse_only:所有连接都由它主动发起,\n")
			fmt.Printf("    除 SSH 外公网入站可以全关。\n")
		}
	}
	fmt.Printf("\n出站:全部放行(做出口时要连任意公网地址)。\n")
	fmt.Printf("ICMP:建议放行,L2 测 RTT 与丢包要用。\n")
	fmt.Printf("\n注意云厂商安全组与机器内 firewalld/ufw 是两层,两层都要开。\n")
	return nil
}
