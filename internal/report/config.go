package report

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Config 是上报者在节点上读到的输入,由 loom render 产出。
type Config struct {
	Node string `json:"node"`

	// Listen 是监听地址,**只能是隧道内地址**。上报接口没有自己的认证 ——
	// 它靠 WireGuard 兜住:能连上这个地址,就已经持有隧道密钥了。绑到公网
	// 地址上等于把拓扑白送。
	Listen []string `json:"listen"`

	// Interfaces 是本节点应有的隧道接口。
	//
	// **必须显式列出,不能拿 `wg show` 看到的当准。** 机器上可能有与 Loom
	// 无关的 WireGuard 接口(access-a 上就有一个 wg5),把它们算进来有两个后果:
	// 报告里全是噪声,以及别人的接口一断,这台机器就整体报不健康。
	//
	// 反过来也重要:列在这里却在 `wg show` 里找不到的接口,是**隧道没起来**,
	// 这正是最该被看见的状态,而它在"只报看得见的"那种实现里完全隐形。
	Interfaces []string `json:"interfaces"`

	// Neighbors 是隧道对端的上报地址。两个用途:量到它们的 RTT,以及
	// 从它们那里收别人的观测(转述)。
	Neighbors []Neighbor `json:"neighbors,omitempty"`

	// Targets 是本节点要直接试访问的目标地址。
	//
	// **这是链路状态测量里最值钱的一项。** "cn-a 到不了 Cloudflare"是关于
	// cn-a 这台机器的一个事实,量一次就够了 —— 而按整条路线去测的话,
	// 同一个事实会在 6 条不同的链上各被发现一次,换个接入设备再来一轮。
	Targets []string `json:"targets,omitempty"`

	// UplinkTargets 是本节点**本该**够得到的地址,用来自检直连出网。
	//
	// **和 Targets 分开,因为它们的失败含义相反。** Targets 里的失败是
	// 有用的数据(喂 Agent 剪枝),UplinkTargets 里的失败是需要人管的问题。
	// 合成一个列表的话,面板只能二选一:要么对结构性的"够不到"刷屏,
	// 要么对真正的直连故障装瞎 —— 实测两个都踩过。
	UplinkTargets []string `json:"uplink_targets,omitempty"`

	// DNS 是本节点解析探测目标用的服务器,来自 SSOT 里这个节点的 dns。
	//
	// **必须显式配,不能用系统解析器。** 与 model.Node.DNS 同一个理由:
	// 大陆机器的系统解析器可能指向被污染的上游。实测踩过 —— jm24 的
	// systemd-resolved 上游是 8.8.8.8,于是上报者报"够不到 baidu",
	// 而同一台机器换 223.5.5.5 解析后直连是 200/59ms。
	//
	// 症状特别误导:它长得像"这台机器出网坏了",而实际只是解析坏了,
	// 真实流量(sing-box 自己配了 DNS)一直好着。
	DNS []string `json:"dns,omitempty"`

	// GossipPeriod 是量一轮并与邻居交换的间隔。
	GossipPeriod string `json:"gossip_period,omitempty"`

	// ObservationStale 是别人的观测多久算过期。过期的直接丢弃 ——
	// 一份两小时前的"能到"比没有更危险,它看起来是数据,实际是回忆。
	ObservationStale string `json:"observation_stale,omitempty"`

	// AttestationMinVersion=5 是双阶段升级的收口闸门。为 0 时兼容旧 v3；
	// 全网 reader 已升级后由 SSOT 改成 5，防止 relay 通过剥离扩展字段降级。
	AttestationMinVersion int `json:"attestation_min_version,omitempty"`

	// Manifest 是 loom hydrate 产出的清单路径,空则不做配置自检。
	Manifest string `json:"manifest"`

	// HandshakeStale 是握手年龄的告警阈值。发起方设了
	// PersistentKeepalive=25,健康隧道的握手年龄不会超过约 180 秒。
	HandshakeStale string `json:"handshake_stale"`

	// AgentState 只在有 Agent 的接入节点设置。空表示本节点没有 Agent，
	// Collect 不得去读进程机器上的默认路径（测试和服务器都靠这条隔离）。
	AgentState string `json:"agent_state,omitempty"`

	// ExpectedComponents 是 renderer 从 SSOT 按本节点实际角色裁出的版本期望。
	// 上报者必须读取真实运行版本并并排上报：sing-box 同时核 MainPID 对应
	// inode 与磁盘文件；WireGuard 字段明确核 wireguard-tools，数据面另看握手。
	ExpectedComponents ComponentVersions `json:"expected_components,omitempty"`

	// ExpectedNodes / ExpectedTunnels 是不含地址和秘密的 SSOT 拓扑底图。
	// 完全失联的节点不会出现在 gossip 里，但仍必须在中控图上以 unknown
	// 留着，不能把“没听见”画成“已不存在”。
	ExpectedNodes   []string         `json:"expected_nodes,omitempty"`
	ExpectedTunnels []ExpectedTunnel `json:"expected_tunnels,omitempty"`
	// ExpectedRoutes 是接入节点从 RouteCandidate.ServerChain 派生的业务
	// 候选路径。它只含节点 ID，不含候选地址或秘密；声明存在不等于在线。
	ExpectedRoutes []ExpectedRoute `json:"expected_routes,omitempty"`

	// PublisherHealth 由 Serve 在确认本机是中控后注入，不来自渲染配置。
	// 这样服务器节点和测试不会误读控制机的 /var/lib/loom。
	PublisherHealth string `json:"-"`

	// componentProbe 是进程内短缓存。页面、/status、gossip 和事件检测共享
	// 同一个 Config；把它留在这里才能做真正的 singleflight，而不是每个入口
	// 各自缓存一份、仍然同时 fork 外部命令。
	componentProbe componentProbeCache
}

type ExpectedTunnel struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type ExpectedRoute struct {
	Access      string   `json:"access"`
	Declaration string   `json:"declaration"`
	Chain       []string `json:"chain,omitempty"`
}

// Neighbor 是一个隧道对端。
type Neighbor struct {
	Node string `json:"node"`
	Addr string `json:"addr"`
}

func (c *Config) Gossip() (time.Duration, error) {
	return optDur(c.GossipPeriod, "gossip_period", time.Minute)
}

func (c *Config) ObsStale() (time.Duration, error) {
	return optDur(c.ObservationStale, "observation_stale", 10*time.Minute)
}

func optDur(v, name string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s 无法解析:%q", name, v)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s 必须为正:%q", name, v)
	}
	return d, nil
}

func (c *Config) Stale() (time.Duration, error) {
	if c.HandshakeStale == "" {
		return 5 * time.Minute, nil
	}
	d, err := time.ParseDuration(c.HandshakeStale)
	if err != nil {
		return 0, fmt.Errorf("handshake_stale 无法解析:%q", c.HandshakeStale)
	}
	if d <= 0 {
		return 0, fmt.Errorf("handshake_stale 必须为正:%q", c.HandshakeStale)
	}
	return d, nil
}

// Load 解析节点上的 report/config.json。
func Load(b []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("解析 report 配置:%w", err)
	}
	if c.Node == "" {
		return nil, fmt.Errorf("report 配置缺少 node")
	}
	if c.AttestationMinVersion != 0 && c.AttestationMinVersion != 5 {
		return nil, fmt.Errorf("attestation_min_version 只能是 0 或 5，收到 %d", c.AttestationMinVersion)
	}
	for _, f := range []func() (time.Duration, error){c.Stale, c.Gossip, c.ObsStale} {
		if _, err := f(); err != nil {
			return nil, err
		}
	}
	// 绑到公网地址上,拓扑和隧道健康就成了公开信息。这是硬错误 ——
	// 一个"只在内网可见"的接口悄悄暴露在外,是最不该靠人记住的事。
	for _, a := range c.Listen {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			return nil, fmt.Errorf("监听地址 %q 不是 host:port", a)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("监听地址 %q 的主机部分不是 IP —— 必须是隧道内地址", a)
		}
		if !ip.IsPrivate() && !ip.IsLoopback() {
			return nil, fmt.Errorf("监听地址 %q 不是私有地址 —— 上报接口只能绑隧道内地址", a)
		}
	}
	return &c, nil
}
