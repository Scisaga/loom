package render

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"loom/internal/model"
)

// WireGuard 的 Endpoint 只在接口启动时解析一次,之后不再重解析。
//
// 对端是固定 IP 时无所谓;对端走 DDNS 时,IP 一变隧道就断,而且**不报错**
// —— 又是"只是不通"那一类。wireguard-tools 自带 reresolve-dns.sh 来补这个:
// 它检查每个 peer 最近有没有握手,没有就重新解析并重设 endpoint。
//
// **只给真正需要的节点渲染。** 判据是"这条隧道的对端 endpoint 是域名而非
// IP" —— 给固定 IP 的节点也装一个定时器是白跑。
const reresolveScript = "/usr/share/doc/wireguard-tools/examples/reresolve-dns/reresolve-dns.sh"

const reresolveUnit = `# 由 loom render 生成 —— 不要手工编辑(§12)
# 需要它是因为这些对端走 DDNS:%s
[Unit]
Description=重解析 WireGuard 对端域名(Loom)
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for c in %s; do [ -f "$c" ] && %s "$c"; done'
`

const reresolveTimer = `# 由 loom render 生成 —— 不要手工编辑(§12)
[Unit]
Description=定时重解析 WireGuard 对端域名(Loom)

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
`

// renderReresolve 为"有 DDNS 对端"的节点生成重解析定时器;不需要则返回 nil。
func renderReresolve(s *model.SSOT, n *model.Node) []File {
	tunnels, err := s.ResolveAll()
	if err != nil {
		return nil
	}
	var confs, peers []string
	for _, t := range tunnels {
		// 只有发起方写 Endpoint,所以只有发起方需要重解析。
		if t.Initiator.ID != n.ID {
			continue
		}
		if net.ParseIP(t.Acceptor.PublicEndpoint) != nil {
			continue // 固定 IP,不用管
		}
		confs = append(confs, "/etc/wireguard/"+model.IfaceName(t.Acceptor.ID)+".conf")
		peers = append(peers, fmt.Sprintf("%s(%s)", t.Acceptor.ID, t.Acceptor.PublicEndpoint))
	}
	if len(confs) == 0 {
		return nil
	}
	sort.Strings(confs)
	sort.Strings(peers)

	return []File{
		{Path: "systemd/loom-wg-reresolve.service",
			Content: fmt.Sprintf(reresolveUnit, strings.Join(peers, "、"),
				strings.Join(confs, " "), reresolveScript)},
		{Path: "systemd/loom-wg-reresolve.timer", Content: reresolveTimer},
	}
}
