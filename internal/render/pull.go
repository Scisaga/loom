package render

import (
	"fmt"

	"loom/internal/model"
)

// 本文件渲染节点侧的控制通道(§14.2):定时向分发点取配置、验签、本地填
// 秘密、安装。
//
// 这是设计里一直写着、而实现一直缺的那一半 —— 在它之前,部署只能从工作站
// ssh 推,于是"谁能部署"取决于"谁能 ssh 到全部机器"。

const (
	// TrustedKeyPath 是钉在节点上的平台公钥。**信任的全部起点。**
	TrustedKeyPath = "/etc/loom/trust/platform.pub"
	// NodeSecretsPath 是本机秘密层。分发出去的包里全是占位符,在这里合并。
	NodeSecretsPath = "/etc/loom/secrets/node.env"
)

const pullUnit = `# 由 loom render 生成 —— 不要手工编辑(§12)
[Unit]
Description=Loom 取配置(%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/loom pull%s -node %s%s
# 配置落盘时含凭据
UMask=0077
StateDirectory=loom
`

const pullTimer = `# 由 loom render 生成 —— 不要手工编辑(§12)
[Unit]
Description=Loom 取配置的节奏(%s)

[Timer]
# OnActiveSec 相对于**这个 timer 被激活的时刻**,不是开机时刻。
# 用 OnBootSec 的话,机器已经开了很久时 enable 它会立刻触发一次 ——
# 而 enable 这个动作本身往往就发生在一次 pull 的安装阶段里,于是
# pull 套 pull。Persistent 也去掉,同样的理由(它会补跑"错过的"那次)。
OnActiveSec=2min
OnUnitActiveSec=%s
# 五台机器同时去拉会在分发点上撞一起,也会让全网在同一秒重启同一个服务。
# **抖动必须小于周期**,否则它不是错峰而是把周期变得没有意义。
RandomizedDelaySec=15s

[Install]
WantedBy=timers.target
`

// renderPull 生成节点的取配置 unit 与定时器。
func renderPull(s *model.SSOT, n *model.Node) ([]File, []Skip) {
	urls := s.DistributionURLsFor(n)
	if len(urls) == 0 {
		return nil, []Skip{{
			Where:  "pull:" + n.ID,
			Reason: "没有配置 distribution_urls,不渲染取配置的 unit —— 该节点只能被 loom apply 推",
		}}
	}
	urlFlags := ""
	for _, url := range urls {
		urlFlags += " -url " + url
	}

	// 解析分发点用**本节点声明的** DNS,不用机器的全局解析器。
	//
	// access-a 上有个与 Loom 无关的 WireGuard 接口声明了 `DNS Domain: ~.`,
	// 把所有域名劫到 8.8.8.8 —— 在境内等于解析不了任何国内域名。那是别人的
	// 配置,不该去改;但也不该依赖它。每个节点用哪个解析器,SSOT 里有(§7.3.2)。
	extra := ""
	if dns := s.DNSFor(n); len(dns) > 0 {
		extra = " -dns " + dns[0]
	}

	return []File{
		{Path: "systemd/loom-pull.service",
			Content: fmt.Sprintf(pullUnit, n.ID, urlFlags, n.ID, extra)},
		{Path: "systemd/loom-pull.timer",
			Content: fmt.Sprintf(pullTimer, n.ID, pullPeriod)},
	}, nil
}

// pullPeriod 是取配置的间隔。
//
// **原来是 10min,理由是"配置变更是人发起的,太频繁只是刷日志"。**
// 那个理由把成本估高了、把代价估低了:
//
//	成本 —— 一次无变化的 pull 只有几个小 JSON 请求；二进制哈希对上就不下载。
//	代价 —— 全网收敛要等一个周期，期间可能处于"新二进制 + 旧配置"。
//
// 45 秒 + 15 秒抖动 → 最坏 60 秒发现变化。加上发布器那 30 秒,
// 纯配置变更端到端 90 秒以内(D80)。
const pullPeriod = "45s"
