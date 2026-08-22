package render

import (
	"fmt"

	"loom/internal/model"
)

// systemd unit 也是渲染产物,不该手写。
//
// §12 说"所有节点上的配置文件都是 SSOT 的渲染输出";手写 unit 会立刻带来
// 两个问题:各机器的启动参数悄悄分叉,以及 §15.3 的漂移检测覆盖不到它。

const singBoxUnit = `# 由 loom render 生成 —— 不要手工编辑(§12)
[Unit]
Description=sing-box (Loom %s)
After=network-online.target
Wants=network-online.target
%s

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/loom/sing-box/config.json
Restart=on-failure
RestartSec=5s
# 配置里含凭据,只允许 root 读
UMask=0077
%s

[Install]
WantedBy=multi-user.target
`

// renderSingBoxUnit 生成 sing-box 的 systemd unit。
//
// 服务器要等隧道起来才有意义:它的出站要绑到 wg 接口上(§8.2),接口不在
// 时 sing-box 会启动失败并进入重启循环。用 After/Requires 把顺序钉死,
// 比靠 Restart 兜底干净。
func renderSingBoxUnit(s *model.SSOT, n *model.Node) File {
	var after, hardening string
	if n.IsServer() {
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
			units += " wg-quick@" + model.IfaceName(peer) + ".service"
		}
		if units != "" {
			after = "After=" + trimLead(units) + "\nWants=" + trimLead(units)
		}
		// 服务器要绑 443 这类特权端口。
		hardening = "AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE"
	} else {
		// 接入节点只监听 127.0.0.1 的高位端口,不需要任何特权。
		hardening = "NoNewPrivileges=true\nPrivateTmp=true"
	}

	role := "接入节点"
	if n.IsServer() {
		role = "服务器节点"
	}
	return File{
		Path:    "systemd/sing-box.service",
		Content: fmt.Sprintf(singBoxUnit, role, after, hardening),
	}
}

func trimLead(s string) string {
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	return s
}
