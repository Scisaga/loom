// Package model 是 SSOT 的内存表示。
//
// 命名遵循 design.md 附录 B:项目名不向下渗透,内部一律用通用词。
package model

// Capability 是节点能力。能力是集合而非枚举 —— 笔记本既可以是接入节点,
// 也可以给同网段另一台设备当服务器(§1.3)。
//
// 这里**没有 target**。目标不是节点(§1),出口是路径上的位置而非节点类型
// (§1.1)—— 链上最后一台服务器就是这次的出口。
type Capability string

const (
	// Access 是你的设备:接管本机流量,按调度结果送出。
	Access Capability = "access"
	// Server 是你的机器:转发流量;排在链末尾时负责出公网。
	Server Capability = "server"
)

func (c Capability) Valid() bool { return c == Access || c == Server }

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

// Node 是 Loom 管的一台机器。目标地址不在这里 —— 它不是节点(§1、§9)。
//
// 没有 mesh_eligible,也没有任何"隧道发起方"字段:它们由 direction 推导
// (§2.2)。SSOT 以 KnownFields 严格解码,在 YAML 里手工写出这些键会直接
// 报错 —— 这是 §19"校验器应拒绝矛盾值"的第一道闸。
type Node struct {
	ID           string       `yaml:"id"`
	Name         string       `yaml:"name,omitempty"`
	City         string       `yaml:"city,omitempty"`
	Provider     string       `yaml:"provider,omitempty"`
	Capabilities []Capability `yaml:"capabilities"`
	Direction    Direction    `yaml:"direction"`

	// PublicEndpoint 是入站可达的主机名或 IP,不含端口。
	PublicEndpoint string `yaml:"public_endpoint,omitempty"`

	// InboundPort 是接受上游连接的端口(§8.1)。上游可能是接入节点,
	// 也可能是链上的前一台服务器。
	InboundPort int `yaml:"inbound_port,omitempty"`

	// InboundProtocol 是这个 inbound 说什么协议。
	//
	// §6 说"协议按跳选择,不做全局统一"。这里是那条原则在接入侧的落点:
	// **决定因素是上游的网络放行什么,不是想伪装成什么。** 实测发现有的
	// 客户端网络只放行 TCP(企业网常见的封 QUIC 策略),那条链路上
	// Hysteria2 与 WireGuard 都用不了 —— 两者都是 UDP。
	//
	// 留空按 Hysteria2 处理。
	InboundProtocol InboundProtocol `yaml:"inbound_protocol,omitempty"`

	// EgressCapable 表示这台机器能否作为出口出公网(ip_forward + MASQUERADE)。
	// 它不是一种节点类型 —— 同一台机器这次是出口,下次可能只是中间一跳(§1.1)。
	EgressCapable bool `yaml:"egress_capable,omitempty"`

	// WGPublicKey 由节点上报。平台永不持有私钥(§13.1)。
	WGPublicKey string `yaml:"wg_public_key,omitempty"`

	// SecretGeneration 是本机秘密层的代次,由节点上报。
	//
	// 快照只记这个数字和公钥,不含私钥本身(§12.1)。它的用途是让回滚
	// 知道"当时那一版配置配的是哪一代密钥" —— 但回滚**不回滚秘密层**,
	// 代次对不上时应当告警而不是悄悄换密钥。
	SecretGeneration int `yaml:"secret_generation,omitempty"`

	// SSHPort 是 bootstrap 阶段用的 SSH 端口(§14.1)。留空按 22。
	SSHPort int `yaml:"ssh_port,omitempty"`

	// Components 是这台机器上该跑哪些版本。为空则用 SSOT 的全局默认。
	Components *ComponentVersions `yaml:"components,omitempty"`

	// ---- 以下只对持有 access 能力的节点有意义(§7)----
	//
	// 这些字段原本在一个独立的 ClientProfile 实体里。那与 §1"只有两类节点"
	// 矛盾:接入节点本来就是节点,不该另起一张表。合并后也不再需要
	// "档案 id 不能与节点 id 重名"那条为规避目录冲突而发明的规则。

	Platform    Platform    `yaml:"platform,omitempty"`
	Credentials []string    `yaml:"credentials,omitempty"`
	MixedPorts  []MixedPort `yaml:"mixed_ports,omitempty"`

	// DefaultDeclaration 是 TUN 兜底流量走的声明(§7.2)。
	DefaultDeclaration string `yaml:"default_declaration,omitempty"`
}

// ComponentVersions 是节点上各组件的版本(§15.4)。
//
// **版本是期望态的一部分,并入同一条收敛回路。** 版本必须显式钉住,
// 永不使用 latest —— 自动的是下载,不是升级决策;上游一次不兼容发布可以
// 在一个轮询周期内打挂全部节点。
type ComponentVersions struct {
	SingBox   string `yaml:"sing_box,omitempty"`
	WireGuard string `yaml:"wireguard,omitempty"`
	Tailscale string `yaml:"tailscale,omitempty"`
	Agent     string `yaml:"agent,omitempty"`
}

// VersionsFor 返回某个节点最终生效的组件版本:节点覆盖优先,否则用全局默认。
func (s *SSOT) VersionsFor(n *Node) ComponentVersions {
	v := ComponentVersions{}
	if s.Defaults != nil && s.Defaults.Components != nil {
		v = *s.Defaults.Components
	}
	if n.Components == nil {
		return v
	}
	for _, f := range []struct{ dst, src *string }{
		{&v.SingBox, &n.Components.SingBox},
		{&v.WireGuard, &n.Components.WireGuard},
		{&v.Tailscale, &n.Components.Tailscale},
		{&v.Agent, &n.Components.Agent},
	} {
		if *f.src != "" {
			*f.dst = *f.src
		}
	}
	return v
}

// Defaults 是全网默认值,目前只有组件版本。
type SSOTDefaults struct {
	Components *ComponentVersions `yaml:"components,omitempty"`
}

func (n *Node) Has(c Capability) bool {
	for _, x := range n.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// TunnelCapable 报告这个节点是否参与隧道矩阵。
//
// direction 约束"能不能被连接",只对参与隧道的节点有意义。纯接入节点不建
// 隧道 —— 它经 Hysteria2 拨出去。
func (n *Node) TunnelCapable() bool { return n.Has(Server) }

// MeshEligible 由 direction 推导,不是独立配置项(§2.2)。
//
// 能进 mesh 的服务器由 Headscale 自动分发密钥与 peer,**一份隧道配置都不
// 渲染**(§6.3、§8.3)。这条推导直接决定隧道矩阵有多大。
func (n *Node) MeshEligible() bool { return n.Direction != ReverseOnly }

// DialableFromAccess 报告接入节点能否直接拨这台服务器。
//
// reverse_only 的服务器拨不到 —— 它只能自己连出来。因此它**永远不能是链上
// 第一跳**,必须由前一跳经反连隧道把流量推给它(§2.2)。
func (n *Node) DialableFromAccess() bool {
	return n.Direction != ReverseOnly && n.PublicEndpoint != "" && n.InboundPort > 0
}

// 隧道端口的保留范围。
//
// 挑在这里有两个理由:一是它**高于 Linux 默认的临时端口范围**
// (32768-60999),不会被内核分配给出站连接的源端口;二是避开 51820 ——
// 那是公认的 WireGuard 端口,扫描器直接对着它扫。
//
// 但要清楚这只防端口扫描,**不防 DPI**:WireGuard 包本身的指纹(148/92
// 字节握手、消息类型 1-4)没有任何变化。真要对付那个得上 §17 的 AmneziaWG。
const (
	TunnelPortMin = 61617
	TunnelPortMax = 61799
)

// InboundProtocol 是服务器接受上游连接时说的协议。
type InboundProtocol string

const (
	// Hysteria2 走 QUIC,即 UDP。网络放行 UDP 时的首选:丢包链路上更快。
	Hysteria2 InboundProtocol = "hysteria2"
	// Trojan 走 TCP + TLS。上游网络封 UDP 时唯一能用的。
	Trojan InboundProtocol = "trojan"
)

func (p InboundProtocol) Valid() bool {
	return p == "" || p == Hysteria2 || p == Trojan
}

// Or 返回实际生效的协议,留空时取默认。
func (p InboundProtocol) Or() InboundProtocol {
	if p == "" {
		return Hysteria2
	}
	return p
}

// IsUDP 报告该协议是否依赖 UDP 出网。
func (p InboundProtocol) IsUDP() bool { return p.Or() == Hysteria2 }

// Tunnel 是隧道矩阵中的一条边(§6.3)。
//
// **只有 reverse_only 的服务器才需要它。** 能进 mesh 的由 Headscale 自动
// 分发,写进这里会被校验器拒绝。
//
// 同样没有 initiator 字段 —— 它由两端 direction 推导(§2.2)。
type Tunnel struct {
	From     string   `yaml:"from"`
	To       string   `yaml:"to"`
	Protocol Protocol `yaml:"protocol"`

	// ListenPort 是接受方监听的端口。哪一端是接受方由 direction 推导。
	ListenPort int `yaml:"listen_port"`

	// FromAddr/ToAddr 是隧道两端的地址,含掩码(如 10.99.0.1/32)。
	// 渲染时互为对端的 AllowedIPs。
	FromAddr string `yaml:"from_addr"`
	ToAddr   string `yaml:"to_addr"`

	// Obfuscation 引用一个 ObfuscationSet(§17)。
	Obfuscation string `yaml:"obfuscation,omitempty"`
}

// Pair 返回这条隧道的稳定标识,用于报错与排序。
func (t *Tunnel) Pair() string { return t.From + "→" + t.To }

// SSOT 是唯一事实来源的根(§12)。
type SSOT struct {
	// Defaults 是全网默认值(目前只有组件版本)。
	Defaults *SSOTDefaults `yaml:"defaults,omitempty"`

	// 拓扑 —— Loom 管的机器
	Nodes   []Node   `yaml:"nodes"`
	Tunnels []Tunnel `yaml:"tunnels"`

	// 服务与调度 —— 目标地址活在等价类里,不在 Nodes 里
	EquivalenceClasses []EquivalenceClass  `yaml:"equivalence_classes,omitempty"`
	Declarations       []AccessDeclaration `yaml:"declarations,omitempty"`
	Credentials        []Credential        `yaml:"credentials,omitempty"`
}

// AccessNodes 返回全部接入节点,按 id 排序。
func (s *SSOT) AccessNodes() []*Node {
	var out []*Node
	for i := range s.Nodes {
		if s.Nodes[i].Has(Access) {
			out = append(out, &s.Nodes[i])
		}
	}
	return out
}

// NodeByID 建立索引。调用方需保证 ID 已去重(validate 会查)。
func (s *SSOT) NodeByID() map[string]*Node {
	m := make(map[string]*Node, len(s.Nodes))
	for i := range s.Nodes {
		m[s.Nodes[i].ID] = &s.Nodes[i]
	}
	return m
}

// DeclarationByID 建立访问声明索引。
func (s *SSOT) DeclarationByID() map[string]*AccessDeclaration {
	m := make(map[string]*AccessDeclaration, len(s.Declarations))
	for i := range s.Declarations {
		m[s.Declarations[i].ID] = &s.Declarations[i]
	}
	return m
}

// ClassByID 建立等价类索引。
func (s *SSOT) ClassByID() map[string]*EquivalenceClass {
	m := make(map[string]*EquivalenceClass, len(s.EquivalenceClasses))
	for i := range s.EquivalenceClasses {
		m[s.EquivalenceClasses[i].ID] = &s.EquivalenceClasses[i]
	}
	return m
}

// CredentialByID 建立凭据索引。
func (s *SSOT) CredentialByID() map[string]*Credential {
	m := make(map[string]*Credential, len(s.Credentials))
	for i := range s.Credentials {
		m[s.Credentials[i].ID] = &s.Credentials[i]
	}
	return m
}

// TunnelAddrOn 返回本节点在与 peer 的隧道中使用的地址(不含掩码)。
// 找不到对应隧道时返回空串。
func (s *SSOT) TunnelAddrOn(nodeID, peerID string) string {
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		switch {
		case t.From == nodeID && t.To == peerID:
			return stripMask(t.FromAddr)
		case t.To == nodeID && t.From == peerID:
			return stripMask(t.ToAddr)
		}
	}
	return ""
}

// ServerReachable 报告 from 能否把流量交给 to。
//
// 两条路子:有点对点隧道,或者两端都能进 mesh(Headscale 组网,§8.3)。
func (s *SSOT) ServerReachable(from, to *Node) bool {
	if s.TunnelAddrOn(to.ID, from.ID) != "" {
		return true
	}
	return from.MeshEligible() && to.MeshEligible()
}

// NextHopAddr 返回 from 该往哪个地址转发给 to。
//
// 走隧道时是隧道内地址;走 mesh 时用对方的公网地址(mesh 内亦可达)。
func (s *SSOT) NextHopAddr(from, to *Node) string {
	if a := s.TunnelAddrOn(to.ID, from.ID); a != "" {
		return a
	}
	if from.MeshEligible() && to.MeshEligible() {
		return to.PublicEndpoint
	}
	return ""
}

func stripMask(addr string) string {
	for i := 0; i < len(addr); i++ {
		if addr[i] == '/' {
			return addr[:i]
		}
	}
	return addr
}
