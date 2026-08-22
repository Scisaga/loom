package render

import (
	"encoding/json"
	"fmt"
	"sort"

	"loom/internal/model"
	"loom/internal/report"
)

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
		units += " wg-quick@" + model.IfaceName(peer) + ".service"
	}
	var skips []Skip
	if len(addrs) == 0 {
		// 没有隧道的节点(纯接入,走 hysteria2 / trojan)没有隧道内地址可绑。
		// 但**配置自检不该因此消失** —— 那是每台机器都要做的事。绑回环:
		// 远端拉不到,本机 `loom report` 仍然能用。
		addrs = []string{fmt.Sprintf("127.0.0.1:%d", ReportPort)}
		skips = append(skips, Skip{
			Where:  "report:" + n.ID,
			Reason: "该节点没有隧道,上报接口只绑回环 —— 配置自检可用,但远端拉不到隧道健康",
		})
	}
	sort.Strings(addrs)
	sort.Strings(ifaces)
	if units != "" {
		after = "After=" + trimLead(units) + "\nWants=" + trimLead(units)
	}

	cfg := report.Config{
		Node:       n.ID,
		Listen:     addrs,
		Interfaces: ifaces,
		Manifest:   ManifestPath,
		// 发起方设了 PersistentKeepalive=25,健康隧道的握手年龄不会超过
		// 约 180 秒。5 分钟留足余量,又能在一个 Agent 周期内发现真断连。
		HandshakeStale: "5m",
	}
	b, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return nil, append(skips, Skip{Where: "report:" + n.ID, Reason: err.Error()})
	}
	return []File{
		{Path: "report/config.json", Content: string(b) + "\n"},
		{Path: "systemd/loom-report.service", Content: fmt.Sprintf(reportUnit, n.ID, after)},
	}, skips
}
