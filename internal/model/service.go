package model

// 本文件是 §4、§5、§7.3、§8.2、§18 涉及的服务与调度模型。
// 拓扑模型在 model.go,两者共用同一份 SSOT。

// Mode 是访问模式(§4)。它决定度量作用在哪个轴上,也决定决策位置(§5.6)。
type Mode string

const (
	// PinnedTarget 是模式 A:目标钉死,只在中继轴上选。
	PinnedTarget Mode = "pinned_target"
	// ByService 是模式 B:目标轴与中继轴都要选。
	ByService Mode = "by_service"
)

func (m Mode) Valid() bool { return m == PinnedTarget || m == ByService }

// Objective 是单一优化目标(§5.3)。对外表达用约束 + 单一目标,
// 不用加权求和 —— 客户给不出权重。
type Objective string

const (
	Latency    Objective = "latency"
	TTFT       Objective = "ttft"
	Throughput Objective = "throughput"
	Stability  Objective = "stability"
	Cost       Objective = "cost"
)

func (o Objective) Valid() bool {
	switch o {
	case Latency, TTFT, Throughput, Stability, Cost:
		return true
	}
	return false
}

// NeedsL7 报告该目标是否只能由 L7 观测点产出(§16.2 不变量)。
// tokens/s 与响应结构不是 L4 能被动观测的量。
func (o Objective) NeedsL7() bool { return o == TTFT }

// NeedsPrice 报告该目标是否需要价格数据源(§5.2 声明值)。
func (o Objective) NeedsPrice() bool { return o == Cost }

// Fallback 是候选集为空时的行为(§5.8)。它是显式字段,只有三个取值。
type Fallback string

const (
	// FailClosed 拒绝新连接并告警。默认值 —— 空候选集是需要人介入的
	// 事件,不是需要自动兜底的事件。
	FailClosed Fallback = "fail_closed"
	// FallbackDirect 回退到零跳直连。
	FallbackDirect Fallback = "direct"
	// LastKnownGood 沿用最后一个可用候选,标记降级并告警。
	LastKnownGood Fallback = "last_known_good"
)

func (f Fallback) Valid() bool {
	switch f {
	case FailClosed, FallbackDirect, LastKnownGood:
		return true
	}
	return false
}

// ConstraintKind 区分约束的性质。合规约束在 §5.1 是"允许/不允许",
// 绝不能被高分挤掉,也绝不能被空候选集的自动回退绕过(§5.8)。
type ConstraintKind string

const (
	Compliance ConstraintKind = "compliance"
	Region     ConstraintKind = "region"
	SLA        ConstraintKind = "sla"
)

func (k ConstraintKind) Valid() bool {
	switch k {
	case Compliance, Region, SLA:
		return true
	}
	return false
}

// Constraint 是过滤条件,不是评分项(§5.1)。
type Constraint struct {
	Kind ConstraintKind `yaml:"kind"`
	Expr string         `yaml:"expr"`
}

// Carrier 是模式 B 的承载方式(§4.4)。它由成员的访问契约是否同构决定,
// l4_direct 是有前提的,不是默认可行。
type Carrier string

const (
	// L4Direct:成员共用域名、证书、凭据与接口,Loom 在代理侧解析时选端点。
	L4Direct Carrier = "l4_direct"
	// L7Gateway:契约不同构,由网关改写 Host、换鉴权、做协议转换。
	L7Gateway Carrier = "l7_gateway"
	// SDK:调用方自己带对应凭据去调,Loom 只回答用哪个端点。
	SDK Carrier = "sdk"
)

func (c Carrier) Valid() bool {
	switch c {
	case L4Direct, L7Gateway, SDK:
		return true
	}
	return false
}

// ObservationPoint 是应用层指标的产出位置(§16.2)。
// 它决定哪些指标拿得到 —— 不同观测点的数据不可直接比较。
type ObservationPoint string

const (
	// L4Tunnel 只能给出连接级指标:建连耗时、首字节返回时间、字节数。
	L4Tunnel ObservationPoint = "l4_tunnel"
	// EndpointProbe 是自有端点埋点,最准。
	EndpointProbe ObservationPoint = "endpoint"
	// GatewayProbe 是 L7 网关埋点。
	GatewayProbe ObservationPoint = "l7_gateway"
	// SDKProbe 是调用方 SDK / OpenTelemetry。
	SDKProbe ObservationPoint = "sdk"
)

func (p ObservationPoint) Valid() bool {
	switch p {
	case L4Tunnel, EndpointProbe, GatewayProbe, SDKProbe:
		return true
	}
	return false
}

// IsL7 报告该观测点能否产出应用层指标(TTFT、tokens/s、响应结构)。
func (p ObservationPoint) IsL7() bool { return p != L4Tunnel }

// AccessContract 是 §4.4 的转发前提:客户端已经发出的那一个请求,
// 原样送到新端点也能被接受。它与输出等价是两件不同的事。
type AccessContract struct {
	Domain      string `yaml:"domain"`                 // 共用域名,TLS SNI 与证书校验依赖它
	CertCA      string `yaml:"cert_ca"`                // 签发证书的 CA 标识
	Credential  string `yaml:"credential"`             // 凭据来源标识(不是凭据本身)
	PathPrefix  string `yaml:"path_prefix,omitempty"`  // 请求路径前缀
	ProtocolVer string `yaml:"protocol_ver,omitempty"` // 如 http/1.1、h2
}

// SameAs 报告两份访问契约是否同构。carrier: l4_direct 要求成员之间
// 全部同构 —— 否则换端点会在 TLS 或鉴权层直接失败。
func (a AccessContract) SameAs(b AccessContract) bool { return a == b }

// EquivalenceClass 定义可互换性(§4.3、§4.4)。
//
// 只有真正可互换的端点才能进同一个候选集。可互换需要两个条件:
// 输出等价(算出来的东西一样)与契约同构(请求送过去能被接受)。
type EquivalenceClass struct {
	ID string `yaml:"id"` // 如 llm:qwen3-32b-int8@openai-v1

	// OutputContract 是 §4.3 的输出等价:参数、上下文长度、流式行为。
	OutputContract string `yaml:"output_contract"`

	// AccessContract 是 §4.4 的转发前提。members 各自声明,
	// l4_direct 要求它们全部相同。
	Carrier Carrier `yaml:"carrier"`

	// ObservationPoint 决定这个等价类能产出哪些指标(§16.2)。
	ObservationPoint ObservationPoint `yaml:"observation_point"`

	// PriceSource 是价格数据的来源标识(附录 C #13)。为空表示没有价格
	// 数据源,此时 objective: cost 无法成立。
	PriceSource string `yaml:"price_source,omitempty"`

	Members []Member `yaml:"members"`
}

// Member 是等价类的一个成员端点。
type Member struct {
	Node     string         `yaml:"node"`
	Contract AccessContract `yaml:"access_contract"`
}

// AccessDeclaration 是选路的单位(§4)。
//
// 没有单个 adjustment_period —— §5.5 要求排序周期与微调周期分别配置,
// 合成一个值会强迫在"端点切太频"和"链路反应太慢"之间二选一。
type AccessDeclaration struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name,omitempty"`
	Mode Mode   `yaml:"mode"`

	TargetNode       string `yaml:"target_node,omitempty"`       // 模式 A 用
	EquivalenceClass string `yaml:"equivalence_class,omitempty"` // 模式 B 用

	Matcher     string       `yaml:"matcher,omitempty"`
	Objective   Objective    `yaml:"objective"`
	Constraints []Constraint `yaml:"constraints,omitempty"`

	AllowedRelays []string `yaml:"allowed_relays,omitempty"`
	MaxHops       int      `yaml:"max_hops"`

	// RankingPeriod 是控制平面重算 ranked list 的周期(§5.5)。
	// 模式 A 的候选集里 target 是常量,这个周期无意义。
	RankingPeriod string `yaml:"ranking_period,omitempty"`
	// TuningPeriod 是接入节点在 top-N 内本地重选的周期(§5.5)。
	TuningPeriod string `yaml:"tuning_period"`

	SwitchThreshold float64 `yaml:"switch_threshold"`
	TopN            int     `yaml:"top_n,omitempty"`

	// §5.8 的度量窗口与样本数。它们必须显式声明,而不是"取最近的值"。
	Window     string   `yaml:"window,omitempty"`
	MinSamples int      `yaml:"min_samples,omitempty"`
	StaleAfter string   `yaml:"stale_after,omitempty"`
	Fallback   Fallback `yaml:"fallback"`
}

// HasCompliance 报告该声明是否带合规约束。合规约束存在时,空候选集
// 的任何自动回退都等于绕过约束(§5.8)。
func (d *AccessDeclaration) HasCompliance() bool {
	for _, c := range d.Constraints {
		if c.Kind == Compliance {
			return true
		}
	}
	return false
}

// Platform 决定接入节点用什么方式接管流量(§7.2)。
type Platform string

const (
	Android     Platform = "android"
	Desktop     Platform = "desktop"
	LinuxServer Platform = "linux-server"
)

func (p Platform) Valid() bool {
	switch p {
	case Android, Desktop, LinuxServer:
		return true
	}
	return false
}

// UsesTUN 由平台推导,不是独立配置项 —— 同 mesh_eligible 的处理方式。
//
// Android 必须 TUN 是因为绝大多数 App 不能单独设代理;Linux 服务器不开
// TUN 恰恰因为它能设,而开 TUN 需 root、要改路由表,配错一次可能把自己
// 的 SSH 锁在外面(§7.2)。
func (p Platform) UsesTUN() bool { return p == Android || p == Desktop }

// UsesMixed 报告该平台是否使用本地 mixed 端口。
func (p Platform) UsesMixed() bool { return p == Desktop || p == LinuxServer }

// MixedPort 是"端口即访问声明"(§7.3):端口号本身编码了模式与参数。
type MixedPort struct {
	Port        int    `yaml:"port"`
	Declaration string `yaml:"declaration"`
}

// Credential 是接入节点表达"它要什么"的方式(§8.2)。
//
// 这里只有对秘密层的引用,没有明文。凭据本身由控制平面持有并经 §18
// 的一次性链接下发,不进渲染层。
type Credential struct {
	ID          string `yaml:"id"`
	Owner       string `yaml:"owner,omitempty"`
	Declaration string `yaml:"declaration"`

	// SecretRef 指向秘密层中的条目,渲染时展开成占位符而非明文。
	SecretRef string `yaml:"secret_ref"`

	ExpiresAt string `yaml:"expires_at,omitempty"` // RFC3339,空 = 不过期
	// RevokedAt 非空即已吊销。所有中继在下一轮询周期移除该 user(§18)。
	RevokedAt string `yaml:"revoked_at,omitempty"`
}

func (c *Credential) Revoked() bool { return c.RevokedAt != "" }

// ClientProfile 是一台接入设备的配置模板(§18)。
type ClientProfile struct {
	ID         string   `yaml:"id"`
	DeviceName string   `yaml:"device_name,omitempty"`
	Platform   Platform `yaml:"platform"`

	Credentials []string    `yaml:"credentials"`
	MixedPorts  []MixedPort `yaml:"mixed_ports,omitempty"`

	// DefaultDeclaration 是 TUN 兜底流量走的声明(§7.2)。
	//
	// 桌面同时有 TUN 和 mixed 端口:端口是精确控制,TUN 是兜底。兜底走
	// 哪条声明必须显式写出 —— 让渲染器"挑一条"会得到一个看起来正常、
	// 实际把全部未匹配流量送错地方的配置。
	// Android 只有一把凭据,可省略。
	DefaultDeclaration string `yaml:"default_declaration,omitempty"`
}
