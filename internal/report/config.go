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

	// Manifest 是 loom hydrate 产出的清单路径,空则不做配置自检。
	Manifest string `json:"manifest"`

	// HandshakeStale 是握手年龄的告警阈值。发起方设了
	// PersistentKeepalive=25,健康隧道的握手年龄不会超过约 180 秒。
	HandshakeStale string `json:"handshake_stale"`
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
	if _, err := c.Stale(); err != nil {
		return nil, err
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
