// Package model 是 SSOT 的内存表示。
//
// 命名遵循 design.md 附录 B:项目名不向下渗透,内部一律用通用词。
package model

// Capability 是节点能力。能力是集合而非枚举 —— 一个节点可以同时是
// 中继与目标(§1.1)。
type Capability string

const (
	Access Capability = "access"
	Relay  Capability = "relay"
	Target Capability = "target"
)

func (c Capability) Valid() bool {
	switch c {
	case Access, Relay, Target:
		return true
	}
	return false
}

// Protocol 是隧道协议。协议按跳选择,不做全局统一(§6)。
type Protocol string

const (
	// WG 是跨受限链路的默认选择(§6.1)。
	WG Protocol = "wg"
	// AWG 是 AmneziaWG,需抗 DPI 时替换 WG(§17)。
	AWG Protocol = "awg"
	// HY2 是 Hysteria2,用于无约束链路(§6.2)。
	HY2 Protocol = "hy2"
)

func (p Protocol) Valid() bool {
	switch p {
	case WG, AWG, HY2:
		return true
	}
	return false
}

// TargetKind 区分 target 的两种可部署形态(§1.3)。
type TargetKind string

const (
	Landing  TargetKind = "landing"
	Endpoint TargetKind = "endpoint"
)

// Node 是拓扑中的一个节点。
//
// 注意这里没有 mesh_eligible,也没有任何"隧道发起方"字段:它们由
// direction 推导(§2.2)。SSOT 以 KnownFields 严格解码,因此在 YAML 里
// 手工写出这些键会直接报错 —— 这是 §19"校验器应拒绝矛盾值"的第一道闸。
type Node struct {
	ID           string       `yaml:"id"`
	Name         string       `yaml:"name,omitempty"`
	City         string       `yaml:"city,omitempty"`
	Provider     string       `yaml:"provider,omitempty"`
	Capabilities []Capability `yaml:"capabilities"`
	ServiceTags  []string     `yaml:"service_tags,omitempty"`
	Direction    Direction    `yaml:"direction"`

	// Managed 为 false 表示第三方端点:没有 Agent、不上报状态、
	// 不参与配置渲染(§1.3、§9.2)。零值 false 与"未声明"无法区分,
	// 所以用指针,由 Defaults 填充。
	Managed *bool `yaml:"managed,omitempty"`

	TargetKind TargetKind `yaml:"target_kind,omitempty"`

	// PublicEndpoint 是入站可达的主机名或 IP,不含端口 —— 端口在
	// Tunnel.ListenPort 上,一个节点可为不同隧道监听不同端口。
	PublicEndpoint string `yaml:"public_endpoint,omitempty"`

	// WGPublicKey 由节点上报。平台永不持有私钥(§13.1)。
	WGPublicKey string `yaml:"wg_public_key,omitempty"`
}

func (n *Node) IsManaged() bool { return n.Managed == nil || *n.Managed }

func (n *Node) Has(c Capability) bool {
	for _, x := range n.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// Tunnel 是隧道矩阵中的一条边(§6.3)。
//
// 同样没有 initiator 字段 —— 它由两端 direction 推导(§2.2)。
type Tunnel struct {
	From     string   `yaml:"from"`
	To       string   `yaml:"to"`
	Protocol Protocol `yaml:"protocol"`

	// ListenPort 是接受方监听的端口。哪一端是接受方由 direction 推导,
	// 因此这里只需要一个值。
	ListenPort int `yaml:"listen_port"`

	// FromAddr/ToAddr 是隧道两端的地址,含掩码(如 10.99.0.1/32)。
	// 渲染时互为对端的 AllowedIPs。
	FromAddr string `yaml:"from_addr"`
	ToAddr   string `yaml:"to_addr"`

	// Obfuscation 引用一个 ObfuscationSet(§17)。按隧道而非按节点,
	// 因为 AmneziaWG 参数是接口级的。
	Obfuscation string `yaml:"obfuscation,omitempty"`
}

// Pair 返回这条隧道的稳定标识,用于报错与排序。
func (t *Tunnel) Pair() string { return t.From + "→" + t.To }

// SSOT 是唯一事实来源的根(§12)。
type SSOT struct {
	Nodes   []Node   `yaml:"nodes"`
	Tunnels []Tunnel `yaml:"tunnels"`
}

// NodeByID 建立索引。调用方需保证 ID 已去重(validate 会查)。
func (s *SSOT) NodeByID() map[string]*Node {
	m := make(map[string]*Node, len(s.Nodes))
	for i := range s.Nodes {
		m[s.Nodes[i].ID] = &s.Nodes[i]
	}
	return m
}
