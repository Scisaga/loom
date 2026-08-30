package render

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"loom/internal/model"
	"loom/internal/report"
)

// report 与 Agent 必须用同一观测过期上限：前者停止转述时，后者也应停止
// 用那条旧事实剪枝。不要在两个渲染器里各写一个时长。
const observationStale = "10m"

// 本文件渲染**上报者**的配置(§16.1)。它和 Agent 是两个角色:
// Agent 做决策、只在接入节点上;上报者只观测和自检、**每个节点都有**。
//
// 服务器上没有 selector 可切,所以不装 Agent —— 但这不等于服务器不需要跑
// 任何东西。DDNS 重解析、隧道断连、有人手工改配置,这些只有节点自己知道。

// ReportPort 是上报接口的端口。沿用 618xx 这一段的约定:
// 61800 控制端点、61801 探测入口、61802 上报接口。
//
// 它是 **TCP、且只绑隧道内地址**,与 61617-61799 那段对外放行的 UDP
// 隧道端口不冲突,也不需要在防火墙上开任何东西。
const ReportPort = 61802

// ManifestPath 是 loom hydrate 产出的清单在机器上的位置。
const ManifestPath = "/etc/loom/report/manifest.json"

const reportUnit = `# 由 loom render 生成 —— 不要手工编辑(§12)
[Unit]
Description=Loom 上报者(隧道健康与配置自检 %s)
# 隧道接口不在时没有地址可绑。
After=network-online.target
Wants=network-online.target
%s

[Service]
Type=simple
ExecStart=/usr/local/bin/loom report -c /etc/loom/report/config.json -serve
Restart=on-failure
RestartSec=10s
# 要跑 wg show,但不需要别的特权。
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`

// renderReport 生成一个节点的上报者配置与 unit。
//
// 没有任何隧道的节点不渲染:上报接口只绑隧道内地址,没有隧道就无处可绑。
func renderReport(s *model.SSOT, n *model.Node) ([]File, []Skip) {
	var addrs, ifaces []string
	var neighbors []report.Neighbor
	var after string
	var units string
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		peer := ""
		switch n.ID {
		case t.From:
			peer = t.To
		case t.To:
			peer = t.From
		default:
			continue
		}
		if a := s.TunnelAddrOn(n.ID, peer); a != "" {
			addrs = append(addrs, fmt.Sprintf("%s:%d", a, ReportPort))
		}
		ifaces = append(ifaces, model.IfaceName(peer))
		// 邻居的上报地址 = 对端在这条隧道里的地址。写成自己那一头的话,
		// 它会去连自己、拿回自己的观测,看起来一切正常。
		if pa := s.TunnelAddrOn(peer, n.ID); pa != "" {
			neighbors = append(neighbors, report.Neighbor{
				Node: peer, Addr: fmt.Sprintf("%s:%d", pa, ReportPort)})
		}
		units += " wg-quick@" + model.IfaceName(peer) + ".service"
	}
	var skips []Skip
	if len(addrs) == 0 {
		skips = append(skips, Skip{
			Where:  "report:" + n.ID,
			Reason: "该节点没有隧道,上报接口只绑回环 —— 配置自检可用,但远端拉不到隧道健康",
		})
	}
	// **回环永远绑上。** 进入路径只有两条:在 loom 网里(隧道地址),
	// 或者 ssh 端口转发到回环。后者是隧道断掉时唯一还能用的那条 ——
	// 而那正是最需要看它的时候。不开任何公网面。
	addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", ReportPort))
	sort.Strings(addrs)
	sort.Strings(ifaces)
	sort.Slice(neighbors, func(i, j int) bool { return neighbors[i].Node < neighbors[j].Node })
	if units != "" {
		after = "After=" + trimLead(units) + "\nWants=" + trimLead(units)
	}

	cfg := report.Config{
		Node:       n.ID,
		Listen:     addrs,
		Interfaces: ifaces,
		Neighbors:  neighbors,
		// 每台机器都试一遍全部目标地址。"某台服务器到不了某个目标"是关于
		// 那台机器的事实,量一次全网复用 —— 按整条路线去测的话,同一个
		// 事实会在每条经过它的链上各被发现一次。
		Targets:       probeTargets(s),
		UplinkTargets: append([]string(nil), n.ProbeTargets...),
		DNS:           append([]string(nil), s.DNSFor(n)...),
		GossipPeriod:  "1m",
		// 超过这段时间的尽力观测不再转述；Agent 使用同一个值做剪枝。
		ObservationStale:      observationStale,
		AttestationMinVersion: s.AttestationMinVersion(),
		Manifest:              ManifestPath,
		// 发起方设了 PersistentKeepalive=25,健康隧道的握手年龄不会超过
		// 约 180 秒。5 分钟留足余量,又能在一个 Agent 周期内发现真断连。
		HandshakeStale: "5m",
	}
	for _, plan := range hy2LinkProbePlans(s) {
		cfg.ExpectedDirectLinks = append(cfg.ExpectedDirectLinks, report.ExpectedDirectLink{
			From: plan.From, To: plan.To, Transport: "hysteria2", Carrier: "public",
		})
		if plan.From == n.ID {
			cfg.LinkProbes = append(cfg.LinkProbes, report.LinkProbe{
				Peer: plan.To, ProxyAddr: plan.proxyAddr(),
				Transport: "hysteria2", Carrier: "public",
			})
		}
		if plan.To == n.ID {
			cfg.LinkReflector = true
		}
	}
	versions := s.VersionsFor(n)
	if runsSingBox(n) {
		cfg.ExpectedComponents.SingBox = versions.SingBox
	}
	if len(ifaces) > 0 {
		cfg.ExpectedComponents.WireGuard = versions.WireGuard
	}
	// components.tailscale 只有版本坐标，没有“该节点启用 Tailscale”的真值；
	// 版本字段不能冒充 workload activation。校验器会拒绝非空值，直到模型
	// 有明确启用语义。
	if runsAgent(s, n) {
		cfg.ExpectedComponents.Agent = versions.Agent
	}
	for i := range s.Nodes {
		cfg.ExpectedNodes = append(cfg.ExpectedNodes, s.Nodes[i].ID)
	}
	for i := range s.Tunnels {
		cfg.ExpectedTunnels = append(cfg.ExpectedTunnels, report.ExpectedTunnel{
			From: s.Tunnels[i].From, To: s.Tunnels[i].To,
		})
	}
	sort.Strings(cfg.ExpectedNodes)
	sort.Slice(cfg.ExpectedTunnels, func(i, j int) bool {
		a := cfg.ExpectedTunnels[i].From + "\x00" + cfg.ExpectedTunnels[i].To
		b := cfg.ExpectedTunnels[j].From + "\x00" + cfg.ExpectedTunnels[j].To
		return a < b
	})
	if runsAgent(s, n) {
		cfg.AgentState = "/var/lib/loom/agent-state.json"
	}
	for _, access := range s.AccessNodes() {
		cfg.ExpectedRoutes = append(cfg.ExpectedRoutes, report.ExpectedRoutesForAccess(s, access)...)
	}
	sort.Slice(cfg.ExpectedRoutes, func(i, j int) bool {
		a := cfg.ExpectedRoutes[i].Access + "\x00" + cfg.ExpectedRoutes[i].Declaration + "\x00" + strings.Join(cfg.ExpectedRoutes[i].Chain, "\x00")
		b := cfg.ExpectedRoutes[j].Access + "\x00" + cfg.ExpectedRoutes[j].Declaration + "\x00" + strings.Join(cfg.ExpectedRoutes[j].Chain, "\x00")
		return a < b
	})
	b, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return nil, append(skips, Skip{Where: "report:" + n.ID, Reason: err.Error()})
	}
	return []File{
		{Path: "report/config.json", Content: string(b) + "\n"},
		{Path: "systemd/loom-report.service", Content: fmt.Sprintf(reportUnit, n.ID, after)},
	}, skips
}

func runsAgent(s *model.SSOT, n *model.Node) bool {
	if n == nil || !n.IsAccess() {
		return false
	}
	decls, _ := renderAgentDeclarations(s, n)
	return len(decls) > 0
}

// expectedReportRoutes 把真实的 RouteCandidate.ServerChain 降成不含地址和
// secret 的候选路径。按 declaration/service + chain 去重；地址轴的多个候选
// 可能共享一条链，拓扑层不应重复画。
func expectedReportRoutes(s *model.SSOT, n *model.Node) []report.ExpectedRoute {
	return report.ExpectedRoutesForAccess(s, n)
}

// probeTargets 收集 SSOT 里全部去重后的探测目标。
func probeTargets(s *model.SSOT) []string {
	seen := map[string]bool{}
	var out []string
	for i := range s.Declarations {
		if u := s.Declarations[i].ProbeURL; u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	sort.Strings(out)
	return out
}
