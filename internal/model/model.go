// Package model 是 SSOT 的内存表示。
//
// 命名遵循 design.md 附录 B:项目名不向下渗透,内部一律用通用词。
package model

// 节点能力由**哪个角色块存在**推导,不是一个单独的 capabilities 列表。
//
// 两者本是同一个事实的两次编码:写了 capabilities: [server] 却不给 server
// 块(或反过来)就是自相矛盾,而那正是 D4 说的"推导值不进结构体"要消灭的
// 东西。改成角色块之后,把 direction 写在接入节点上**根本无处可写** ——
// 不是被校验拒绝,是不可表达。
//
// 能力仍然是集合(§1.3):一台机器可以同时有 access 与 server 两个块,
// 比如笔记本自己上网、同时给同网段另一台设备当出口。
//
// 这里**没有 target**。目标不是节点(§1),出口是路径上的位置而非节点类型
// (§1.1)—— 链上最后一台服务器就是这次的出口。

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
// 角色字段分在 Server / Access 两个块里。哪个块存在,就持有哪种能力;
// 两个都有也合法(§1.3)。这样"把 direction 写在接入节点上"这件事在
// schema 层面就不成立。
type Node struct {
	// Drain 为真时:这台机器**照常渲染、隧道照常建**,但**不参与候选枚举**。
	//
	// 它是迁移和下线的前提。没有它,想把流量从一台机器上挪开只有两个选择:
	// 留在候选里(流量还往上走),或者直接从 SSOT 删掉(隧道也没了,于是
	// 没法拿新旧的实测数据做对比)。排空让新旧并存,由测量决定什么时候切。
	//
	// **它不影响别人到它的隧道** —— 这是有意的:排空期间你仍然要能观测它。
	Drain bool `yaml:"drain,omitempty"`

	// Decommission 为真时:这台机器**停掉全部 Loom 服务并禁用自启**。
	//
	// 它与"从 SSOT 里删掉"是两回事,而且必须先于后者:
	//
	//	删掉    → 别人不再配到它的隧道,但**它自己什么都不知道**。
	//	          sing-box 继续监听、继续用旧凭据接客 —— 而那些凭据是跨节点
	//	          共享的,不轮换的话它就是一台没人管的出口。
	//	下线    → 它从签名过的快照里读到一条**明确的**停机指令,自己停。
	//
	// 为什么不用"不在 manifest 里"当停机信号:那是**歧义**的。可能是下线,
	// 也可能是有人渲染时漏了一个节点。对歧义信号采取不可逆动作是危险的 ——
	// 所以缺席只报警,停机要明说。
	//
	// **秘密不自动销毁。** 销毁不可逆,而误签一次就全没了。它要停,不要自毁。
	Decommission bool `yaml:"decommission,omitempty"`

	ID       string `yaml:"id"`
	Name     string `yaml:"name,omitempty"`
	City     string `yaml:"city,omitempty"`
	Provider string `yaml:"provider,omitempty"`

	// PublicEndpoint 是这台机器对外的主机名或 IP,不含端口。
	// 服务器用它接受上游连接;接入节点通常只用于 SSH 与排障标注。
	PublicEndpoint string `yaml:"public_endpoint,omitempty"`

	// SSHPort 是 bootstrap 阶段用的 SSH 端口(§14.1)。留空按 22。
	SSHPort int `yaml:"ssh_port,omitempty"`

	// Components 是这台机器上该跑哪些版本。为空则用 SSOT 的全局默认。
	Components *ComponentVersions `yaml:"components,omitempty"`

	// DNS 是这台机器本地解析用的服务器,为空则用全局默认。
	//
	// **必须显式配,不能依赖系统解析器。** 走代理的流量由出口解析(§7.4 的
	// socks5h),不经过这里;但**直连**那条候选要本地解析 —— 系统解析器坏掉
	// 时,表现是"直连候选永远失败",而代理候选一切正常,极难往 DNS 上想。
	//
	// 解析器要按机器所在地选:大陆机器用 8.8.8.8 会被污染,境外机器用
	// 223.5.5.5 又绕远。
	DNS []string `yaml:"dns,omitempty"`

	Server *ServerRole `yaml:"server,omitempty"`
	Access *AccessRole `yaml:"access,omitempty"`
}

// ServerRole 是"这台机器转发流量"这件事需要的全部字段(§8)。
type ServerRole struct {
	// Direction 约束这个节点在隧道里能扮演什么角色(§2.1)。
	Direction Direction `yaml:"direction"`

	// InboundPort 是接受上游连接的端口(§8.1)。上游可能是接入节点,
	// 也可能是链上的前一台服务器。
	InboundPort int `yaml:"inbound_port"`

	// InboundProtocol 决定这个 inbound 说什么协议(§6.2.1)。
	// 留空按 Hysteria2 处理。
	InboundProtocol InboundProtocol `yaml:"inbound_protocol,omitempty"`

	// EgressCapable 表示这台机器能否作为出口出公网。
	// 它不是一种节点类型 —— 同一台机器这次是出口,下次可能只是中间一跳(§1.1)。
	EgressCapable bool `yaml:"egress_capable,omitempty"`

	// WGPublicKey 由节点上报。平台永不持有私钥(§13.1)。
	WGPublicKey string `yaml:"wg_public_key,omitempty"`

	// SecretGeneration 是本机秘密层的代次,由节点上报。
	// 快照只记这个数字和公钥,不含私钥本身(§12.1)。
	SecretGeneration int `yaml:"secret_generation,omitempty"`
}

// AccessRole 是"这台机器接管本机流量"这件事需要的全部字段(§7)。
type AccessRole struct {
	Platform    Platform    `yaml:"platform"`
	Credentials []string    `yaml:"credentials"`
	MixedPorts  []MixedPort `yaml:"mixed_ports,omitempty"`

	// DefaultDeclaration 是 TUN 兜底流量走的声明(§7.2)。
	DefaultDeclaration string `yaml:"default_declaration,omitempty"`
}

// IsServer / IsAccess 就是"能力"本身 —— 由块是否存在推导。
func (n *Node) IsServer() bool { return n.Server != nil }
func (n *Node) IsAccess() bool { return n.Access != nil }

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

// SSOTDefaults 是全网默认值。
type SSOTDefaults struct {
	Components *ComponentVersions `yaml:"components,omitempty"`

	// DNS 是节点本地解析用的服务器。见 Node.DNS。
	DNS []string `yaml:"dns,omitempty"`

	// DistributionURL 是节点自取配置的地方(§14.2)。
	//
	// **它不需要被信任。** 分发的是带 Ed25519 签名的快照,节点用本地钉住的
	// 公钥验;改一个字节就装不上去。所以放哪儿、经过谁,都不影响安全性 ——
	// 一个静态目录足矣。
	//
	// 留空则不渲染 pull 的 unit,节点只能被推(loom apply)。
	DistributionURL string `yaml:"distribution_url,omitempty"`
}

// DistributionURL 返回分发点地址;没有配置时返回空。
func (s *SSOT) DistributionURL() string {
	if s.Defaults != nil {
		return s.Defaults.DistributionURL
	}
	return ""
}

// DNSFor 返回某个节点最终生效的解析器:节点覆盖优先,否则用全局默认。
func (s *SSOT) DNSFor(n *Node) []string {
	if len(n.DNS) > 0 {
		return n.DNS
	}
	if s.Defaults != nil {
		return s.Defaults.DNS
	}
	return nil
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

// MeshEligible 由 direction 推导,不是独立配置项(§2.2)。
//
// 能进 mesh 的服务器由 Headscale 自动分发密钥与 peer,**一份隧道配置都不
// 渲染**(§6.3、§8.3)。这条推导直接决定隧道矩阵有多大。
func (n *Node) MeshEligible() bool { return n.IsServer() && n.Server.Direction != ReverseOnly }

// PubliclyDialable 报告能否从公网直接拨这台服务器。
//
// reverse_only 的服务器拨不到 —— 它只能自己连出来(§2.2)。
func (n *Node) PubliclyDialable() bool {
	return n.IsServer() && n.Server.Direction != ReverseOnly &&
		n.PublicEndpoint != "" && n.Server.InboundPort > 0
}

// AccessHopAddr 返回接入节点该拨哪个地址才能到达这台服务器;不可达时返回空。
//
// **reverse_only 也可以是第一跳 —— 只要它和这个接入节点之间有隧道。**
// "拨不到"说的是公网:一旦它主动连过来建起了隧道,接入节点用隧道内地址
// 就能直接找到它,不需要再往公网拨。这把两跳压成一跳。
//
// 公网可达时优先走公网:隧道多一层加密,而 Hysteria2/Trojan 本身已经加密了。
func (s *SSOT) AccessHopAddr(access, target *Node) string {
	if !target.IsServer() {
		return ""
	}
	if target.PubliclyDialable() {
		return target.PublicEndpoint
	}
	return s.TunnelAddrOn(target.ID, access.ID)
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
		if s.Nodes[i].IsAccess() {
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

// AccessNodeForCredential 反查一张凭据属于哪个接入节点。
//
// 服务器要按凭据决定放行哪些下一跳,而候选集因接入节点而异 —— 所以它必须
// 先知道这张凭据是谁的。凭据被多个接入节点共用是配置错误,校验器会报。
func (s *SSOT) AccessNodeForCredential(credID string) *Node {
	for _, n := range s.AccessNodes() {
		for _, c := range n.Access.Credentials {
			if c == credID {
				return n
			}
		}
	}
	return nil
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
