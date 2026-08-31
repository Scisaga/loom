// Package webui 是节点上的操作界面。
//
// **每个节点都跑一份,但权限不一样。**
//
//	看 + 本机操作   每个节点都有。因为有转述(§16.1.2),随便打开哪一台看到的
//	                都是整张网,不是它自己那一角 —— 于是没有单点,也没有
//	                "控制面所在的机器挂了就看不见它挂了"的循环。
//	签发            恰好一台。它拿着签名私钥;两个签发者等于两份真相,
//	                和 D11 是同一个道理。
//
// 进入路径只有两条:在 loom 网里(隧道地址),或者 ssh 端口转发到回环。
// **不开任何公网面。**
package webui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"
)

// Deps 是界面需要外界提供的东西。用接口而不是具体类型,是为了让 report
// 包不必反过来依赖这里的实现细节。
type Deps struct {
	Node string
	// Now 由调用方注入,便于测试。
	Now func() time.Time

	// Operator 是写操作的口令。空则**所有写操作一律拒绝** ——
	// 不是"不需要认证",是"没配就不许写"。
	Operator string

	// Snapshot 返回当前的全网视图。
	Snapshot func() View
	// TrafficSnapshot returns a gossip-cycle cache for /traffic.json. Scrapers
	// must not trigger Collect, signature verification and a retention query on
	// every request. When nil, the handler falls back to Snapshot for backwards
	// compatibility with small tests/embedders.
	TrafficSnapshot func() View

	// Actions 是本机能执行的动作。键是动作名,值是执行函数。
	// 只列白名单里的 —— 让界面能跑任意命令,等于把 root 挂到网上。
	Actions map[string]func() (string, error)

	// Control 非 nil 时,这台机器是中控,界面多出改 SSOT 的能力。
	Control *ControlDeps

	// Events 非 nil 时,界面多一页事件历史。只有中控有 —— 事件记在
	// 中控上,因为那是人会去看的地方。
	Events func(limit int) []EventView
	// Unresolved 是"现在有什么问题"。
	//
	// **它和 Events 是两个不同的问题,别用前者筛出后者。** 事件按定义只有
	// 变化,而上报者重启是静默播种的 —— 播种那一刻已经坏掉的东西不会产生
	// 任何事件。旧版面板从事件里筛,于是对这类问题完全瞎。
	Unresolved func() []UnresolvedView
}

// EventView 是一次状态变化在界面上的样子。
// UnresolvedView 是面板上"现在还没解决"的一行。
type UnresolvedView struct {
	Node, Kind, Subject string
	State, Detail       string
	Level, Lasted       string
	// AtLeast 为真时 Lasted 只是下界:这个问题在上报者开始记之前就存在。
	AtLeast bool
}

// LastedText 把时长写成一句话。**下界必须标出来** —— 把"至少 9 小时"
// 写成"已 9 小时"就是在假装知道起点,而那正是面板说谎的方式。
func (u *UnresolvedView) LastedText() string {
	if u.AtLeast {
		return "至少 " + u.Lasted + "(上报者启动时已如此)"
	}
	return "已 " + u.Lasted
}

type EventView struct {
	TS, Node, Kind, Subject string
	From, To, Detail        string
	// Bad 表示变成了有问题的状态,Recovered 表示从有问题变回正常。
	Bad, Recovered bool
	// Level 是 info / problem / ok / pending。**发布新快照、Agent 换路
	// 都是 info** —— 把它们混进"待处理"里,真的问题就被淹没了。
	Level string
	// Lasted / Ongoing:这个状态持续了多久,以及是不是还在持续。
	// **"断了 20 分钟后恢复"和"断了 20 分钟还没好"是两件事。**
	Lasted  string
	Ongoing bool
}

// ControlDeps 只有中控需要(§14.2.3、D36)。
//
// **界面上没有"发布"按钮。** 发布是自动的:改完存盘,发布器 30 秒内校验、
// 渲染、签名、分发。界面能做的只有改 SSOT —— 于是不存在"对某台机器执行
// 某某"这种旁路,而那正是 §12 想要的。
type ControlDeps struct {
	SSOTPath string
	// Enrich 用中控本地的 SSOT 给同一份运行态 View 补期望态元数据。
	// 它只读，不改变采集结果；普通节点没有这项能力，也不会收到这些元数据。
	Enrich func(*View) error
	// Read 返回当前 SSOT 原文。
	Read func() (string, error)
	// Revision 返回 SSOT 原文的内容摘要。结构化编辑和原文编辑都用它做
	// 乐观并发控制，避免浏览器里的旧表单覆盖刚被 git/editor 改过的文件。
	Revision func() (string, error)
	// Validate 校验一段内容,返回人可读的发现(空表示通过)。
	Validate func(content string) (string, error)
	// Save 写回。**实现方必须自己再校验一次** —— 界面上的校验按钮只是
	// 给人看的,不能当成守卫。
	Save func(content string) error
	// SaveIfRevision 在校验之外还要求磁盘内容仍是 expectedRevision。
	// 老调用方可以只提供 Save；中控 UI 有这项时必须优先使用。
	SaveIfRevision func(content, expectedRevision string) error
	// Services 是保留 YAML 注释/顺序的结构化 Service 事务。Policy 仍通过
	// 完整 SSOT 编辑器修改，避免用一个不完整表单悄悄丢约束字段。
	Services *ServiceControlDeps
	// DefaultExits 是设备默认出口的中控事务。当前 HTTP 边界只接受运维会话；
	// Windows/Android 设备身份尚未落地前，不能把它直接暴露成客户端写接口。
	DefaultExits *DefaultExitControlDeps
	// BootstrapIdentity 是中控范围唯一的 SSH bootstrap 身份。节点接入只
	// 复用其公钥；私钥永不通过这个接口返回。
	BootstrapIdentity *BootstrapIdentityDeps
	// Enrollment 把节点接入限制在一条可审计的事务路径：先独立扫描并人工
	// 确认 SSH host key，再从受信会话发现 hostname/能力，最后在同一份
	// revision 上准备节点本地 WG 身份并原子写入节点与隧道。webui 不执行
	// shell，也不接受操作者手填 Node ID、public_endpoint 或 egress。
	Enrollment *NodeEnrollmentDeps
	// Clients is the control-local device identity registry. It is deliberately
	// separate from topology Nodes: routes, credentials and generated configs
	// still come only from SSOT and the publisher.
	Clients *ClientControlDeps
	// Distributed 返回分发点当前指向的快照 id,用来看发布器跟上没有。
	Distributed func() (string, error)
}

type ServiceControlDeps struct {
	Upsert func(ServiceInput, string) error
	Delete func(id, expectedRevision string) error
}

type ServiceInput struct {
	ID, Name, Declaration string
	Addresses             []string
}

type DefaultExitControlDeps struct {
	Get func(nodeID string) (DefaultExitState, error)
	Set func(nodeID, declaration, expectedRevision string) (DefaultExitState, error)
}

// DefaultExitState 是控制端点给管理 UI/未来设备 API 的最小视图。它不暴露完整
// 拓扑或凭据；固定策略指向哪个节点仍由中控声明定义。
type DefaultExitState struct {
	Node     string              `json:"node"`
	Revision string              `json:"revision"`
	Current  string              `json:"current"`
	Options  []DefaultExitOption `json:"options"`
}

type DefaultExitOption struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Mode      string `json:"mode"`
	Available bool   `json:"available"`
}

type BootstrapIdentityDeps struct {
	Status func() (BootstrapIdentityView, error)
	Ensure func() (BootstrapIdentityView, error)
}

type BootstrapIdentityView struct {
	Ready                              bool
	PublicKey, Fingerprint, PublicPath string
}

// NodeEnrollmentDeps 是 webui 与中控节点接入执行器之间的窄契约。Review
// 可以重复调用来重新计算 direction 对应的隧道方案；Commit 必须重新做
// 受信预检，并拒绝 hostname、endpoint 或 SSOT revision 在复核后变化。
type NodeEnrollmentDeps struct {
	Scan   func(context.Context, EnrollmentConnection) (EnrollmentHostKey, error)
	Review func(context.Context, EnrollmentReviewInput) (EnrollmentReview, error)
	Commit func(context.Context, EnrollmentCommitInput) (string, error)
}

type ClientControlDeps struct {
	List                 func() (ClientInventory, error)
	CreateInvite         func(ClientInviteInput) (ClientInviteView, error)
	Claim                func(ClientClaimInput) (ClientClaimResult, error)
	InviteArtifact       func(inviteID string) (ClientInviteArtifact, error)
	LinuxPackage         func() (LinuxClientPackageView, error)
	DownloadLinuxPackage func() (LinuxClientPackageView, []byte, error)
}

type ClientInventory struct {
	Clients       []ClientView `json:"clients"`
	ActiveInvites int          `json:"active_invites"`
}

type ClientView struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Platform        string `json:"platform,omitempty"`
	Status          string `json:"status"`
	KeyFingerprint  string `json:"key_fingerprint,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	EnrolledAt      string `json:"claimed_at,omitempty"`
	LastSeenAt      string `json:"last_seen_at,omitempty"`
	DataPlaneStatus string `json:"data_plane_status"`
	ConfigState     string `json:"config_state"`
}

type ClientInviteInput struct {
	Name string `json:"name"`
}

type ClientInviteView struct {
	InviteID      string `json:"invite_id"`
	ClientID      string `json:"client_id"`
	ClientName    string `json:"client_name"`
	InviteURI     string `json:"invite_uri"`
	EnrollmentURL string `json:"enrollment_url"`
	ExpiresAt     string `json:"expires_at"`
}

type ClientInviteArtifact struct {
	InviteURI string `json:"invite_uri"`
	ExpiresAt string `json:"expires_at"`
}

type ClientClaimInput struct {
	Token, Platform, CSRPEM, RequestID string
}

type ClientClaimResult struct {
	Schema        int              `json:"schema"`
	ClientID      string           `json:"client_id"`
	Status        string           `json:"status"`
	EnrolledAt    string           `json:"claimed_at"`
	Replay        bool             `json:"replay"`
	Next          string           `json:"next"`
	Configuration string           `json:"configuration"`
	Bootstrap     *ClientBootstrap `json:"bootstrap,omitempty"`
}

type ClientBootstrap struct {
	NodeID            string   `json:"node_id"`
	DistributionURLs  []string `json:"distribution_urls"`
	DNS               []string `json:"dns,omitempty"`
	SecretsEnv        string   `json:"secrets_env"`
	PlatformPublicKey string   `json:"platform_public_key"`
	ReleaseAuthority  string   `json:"release_authority"`
	CACertPEM         string   `json:"ca_cert_pem"`
	NodeCertPEM       string   `json:"node_cert_pem"`
}

type LinuxClientPackageView struct {
	Filename string `json:"filename"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Size     int64  `json:"size"`
}

type EnrollmentConnection struct {
	Host, User string
	Port       int
}

type EnrollmentHostKey struct {
	Algorithm, PublicKey, Fingerprint string
}

type EnrollmentReviewInput struct {
	Connection EnrollmentConnection
	HostKey    EnrollmentHostKey
	// Country / City 是操作者在 declaration review 中确认的人读标注。
	// GeoIP 只可预填建议，不能把它冒充成远端身份或位置证明。
	Country, City string
	// DisableGeoIP lets the operator keep missing fields empty instead of
	// accepting another advisory lookup during a recomputed review.
	DisableGeoIP bool
	// RequestedDirection 是 automatic 或三个 SSOT direction 之一。
	RequestedDirection string
}

type EnrollmentCommitInput struct {
	EnrollmentReviewInput
	ExpectedNodeID, ExpectedEndpoint, ExpectedEndpointResolution, ExpectedRevision string
}

type EnrollmentReview struct {
	Connection                               EnrollmentConnection
	HostKey                                  EnrollmentHostKey
	NodeID, ObservedHostname, PublicEndpoint string
	Country, City                            string
	DisableGeoIP, GeoIPSuggested             bool
	GeoIPEvidence                            string
	EndpointEvidence, EndpointResolution     string
	System, Privilege                        string
	KernelWireGuard, WGCommand               bool
	WireGuardToolsInstalled                  bool
	RequestedDirection                       string
	ResolvedDirection                        string
	DirectionEvidence, Revision              string
	EgressEnabled                            bool
	ExpandedPolicies                         []EnrollmentPolicy
	FixedPolicies                            []EnrollmentPolicy
	Tunnels                                  []EnrollmentTunnel
}

type EnrollmentPolicy struct {
	ID, Name string
}

type EnrollmentTunnel struct {
	From, To, FromAddress, ToAddress string
	Initiator, Acceptor              string
	ListenPort                       int
}

// View 是界面要展示的全网状态。它由调用方从转述表里组装 —— webui 不自己
// 采集任何东西,只负责显示。
type View struct {
	Self       string
	Applied    string
	ObservedAt string
	// IntentSource names the inventory generation used by this view. A regular
	// node only knows the inventory in its applied report config; the control
	// node replaces it with the just-read current SSOT during enrichment.
	IntentSource string
	Nodes        []NodeView
	// TrafficHistory 是中控从相邻可信 WireGuard 计数器样本推导出的可选
	// 时间桶。nil 明确表示当前 View 没有历史数据能力；webui 不会把当前
	// 累计 counter 猜成曲线或时间桶。普通节点仍可只提供 Nodes.Tunnels
	// 中的当前本机 counter。
	TrafficHistory *TrafficHistoryView
	// TrafficHistoryStatus is available, unavailable, or not_supported. The
	// explicit state lets /traffic.json distinguish an ordinary node from a
	// control node whose retained history failed to open/query.
	TrafficHistoryStatus string
	TrafficHistoryError  string
	// Links 明确区分常驻 WG 与 SSOT 候选跳；当前 route 是单独的实读 overlay。
	// 候选边只说明可选，不冒充在线。
	Links      []LinkView
	Routes     []RouteView
	Candidates []CandidatePathView
	// Services / Policies / Ingresses 都来自中控本地经校验的 SSOT。它们是
	// 期望态，不冒充节点已经应用；运行态仍由 Nodes / Routes 表达。
	Services  []ServiceView
	Policies  []PolicyView
	Ingresses []IngressView
	Publisher *PublisherView
	Warnings  []string
}

// TrafficHistoryView 是历史流量展示的窄契约。它有意不暴露持久化实现；
// 每个 Bucket 只包含由相邻可信样本实际算出的 delta。WindowStart/End 是
// 半开区间，BucketWidth 是供人审计的采样桶宽（例如 "1h"）。
type TrafficHistoryView struct {
	WindowStart string              `json:"window_start"`
	WindowEnd   string              `json:"window_end"`
	BucketWidth string              `json:"bucket_width"`
	Source      string              `json:"source"`
	Buckets     []TrafficBucketView `json:"buckets"`
}

// TrafficBucketView 表示半开区间 [Start, End)。Samples 是该桶中被接受的
// counter transition 数；Resets/Gaps 是没有被计入字节数的拒绝 transition。
// 它们保留在桶上，缺数据和零流量因此不会被混为一谈。
type TrafficBucketView struct {
	Start   string                  `json:"start"`
	End     string                  `json:"end"`
	Samples int                     `json:"samples"`
	Resets  int                     `json:"resets,omitempty"`
	Gaps    int                     `json:"gaps,omitempty"`
	Nodes   []TrafficNodeTotalsView `json:"nodes,omitempty"`
	Links   []TrafficLinkTotalsView `json:"links,omitempty"`
}

// TrafficNodeTotalsView 是一个节点在一个桶内所有 Loom WireGuard 接口的
// delta 合计。Bytes 应等于 RXBytes+TXBytes；分字段保留方向，Bytes 让调用方
// 能原样传递已经校验的聚合值。Samples/Resets/Gaps 若非零，是可归属到该
// 节点的质量证据；桶级质量仍保留在 TrafficBucketView。
type TrafficNodeTotalsView struct {
	Node    string `json:"node"`
	RXBytes int64  `json:"rx_bytes"`
	TXBytes int64  `json:"tx_bytes"`
	Bytes   int64  `json:"bytes"`
	Samples int    `json:"samples"`
	Resets  int    `json:"resets,omitempty"`
	Gaps    int    `json:"gaps,omitempty"`
}

// TrafficLinkTotalsView 按规范化的无向 WG edge 聚合，但字节只加各端 TX
// delta：同一份 payload 不再把 sender TX 和 receiver RX 重复相加。
// ReportingEndpoints 通常为 0..2，用于把部分覆盖明确显示出来。
type TrafficLinkTotalsView struct {
	From               string `json:"from"`
	To                 string `json:"to"`
	TXBytes            int64  `json:"tx_bytes"`
	ReportingEndpoints int    `json:"reporting_endpoints"`
	Samples            int    `json:"samples"`
	Resets             int    `json:"resets,omitempty"`
	Gaps               int    `json:"gaps,omitempty"`
}

// TrafficExportView is the stable read-only payload returned by /traffic.json.
// Every node exports its own current cumulative Loom WireGuard counters. Only
// the control node attaches centrally retained delta history.
type TrafficExportView struct {
	SchemaVersion     int                         `json:"schema_version"`
	Scope             string                      `json:"scope"`
	Node              string                      `json:"node"`
	GeneratedAt       string                      `json:"generated_at"`
	CurrentObservedAt string                      `json:"current_observed_at,omitempty"`
	Current           []TrafficCurrentCounterView `json:"current"`
	HistoryStatus     string                      `json:"history_status"`
	HistoryError      string                      `json:"history_error,omitempty"`
	History           *TrafficHistoryExportView   `json:"history,omitempty"`
}

type TrafficCurrentCounterView struct {
	Interface string `json:"interface"`
	PeerNode  string `json:"peer_node,omitempty"`
	LinkID    string `json:"link_id,omitempty"`
	// Decimal strings preserve exact uint63 cumulative counters for JavaScript
	// and other JSON consumers whose number type cannot represent int64.
	RXBytes    string `json:"rx_bytes"`
	TXBytes    string `json:"tx_bytes"`
	Epoch      string `json:"counter_epoch,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
	Source     string `json:"source,omitempty"`
	Trusted    bool   `json:"trusted"`
	Verified   bool   `json:"verified"`
}

type TrafficHistoryExportView struct {
	WindowStart string                    `json:"window_start"`
	WindowEnd   string                    `json:"window_end"`
	BucketWidth string                    `json:"bucket_width"`
	Source      string                    `json:"source"`
	Buckets     []TrafficBucketExportView `json:"buckets"`
}

type TrafficBucketExportView struct {
	Start   string                        `json:"start"`
	End     string                        `json:"end"`
	Samples int                           `json:"samples"`
	Resets  int                           `json:"resets,omitempty"`
	Gaps    int                           `json:"gaps,omitempty"`
	Nodes   []TrafficNodeTotalsExportView `json:"nodes,omitempty"`
	Links   []TrafficLinkTotalsExportView `json:"links,omitempty"`
}

type TrafficNodeTotalsExportView struct {
	Node    string `json:"node"`
	RXBytes string `json:"rx_bytes"`
	TXBytes string `json:"tx_bytes"`
	Bytes   string `json:"bytes"`
	Samples int    `json:"samples"`
	Resets  int    `json:"resets,omitempty"`
	Gaps    int    `json:"gaps,omitempty"`
}

type TrafficLinkTotalsExportView struct {
	From               string `json:"from"`
	To                 string `json:"to"`
	TXBytes            string `json:"tx_bytes"`
	ReportingEndpoints int    `json:"reporting_endpoints"`
	Samples            int    `json:"samples"`
	Resets             int    `json:"resets,omitempty"`
	Gaps               int    `json:"gaps,omitempty"`
}

// NodeView 是一个节点在界面上的样子。
type NodeView struct {
	ID string
	// Declared means the node exists in the desired inventory used for this
	// view. Runtime observations can outlive an SSOT removal; those nodes remain
	// visible for diagnosis with Declared=false instead of being counted as
	// current intent.
	Declared bool
	// 以下字段是中控从 SSOT 补入的声明元数据。SSHPort 已展开默认值 22；
	// Roles 由角色块和 server.egress_capable 推导，不在 SSOT 重复存一份
	// capabilities。
	Name, Country, City, Provider, PublicEndpoint string
	SSHPort, InboundPort                          int
	InboundProtocol                               string
	// IngressKnown means this view was enriched from a current SSOT read and can
	// distinguish an absent server inbound from metadata that this node's
	// reduced report view simply does not carry.
	IngressKnown bool
	// PublicDialable is derived from the existing server direction, declared
	// public endpoint and inbound port. It is desired-state capability, not
	// evidence that the listener or its network path is healthy.
	PublicDialable      bool
	Roles               []string
	Direction           string
	EgressCapable       bool
	Drain, Decommission bool
	// Health 是 healthy / problem / unknown。空值也按 unknown 处理；
	// 未签名转述和静默节点不能因为“没看到错误”就被冒充成健康。
	Health        string
	Self          bool
	Reached       bool // 直接拉到的,还是听别人转述的
	Applied       string
	AgeSec        int
	ObservedAt    string
	Source        string
	Version       *VersionView
	Rollout       *RolloutView
	Agent         *AgentView
	Components    []ComponentView
	IdentityError string
	// TrafficVerified means an independently verified traffic attachment was
	// received for this node. VerifiedTraffic retains that signed point-in-time
	// evidence for history. It is deliberately separate from Tunnels: on the
	// local node, direct /status counters can be newer than the signed gossip
	// round and must not be overwritten by that older sample.
	TrafficTrusted    bool // direct local sample or independently verified relay
	TrafficVerified   bool // specifically verified loom-traffic-v1 relay/sample
	TrafficObservedAt string
	VerifiedTraffic   []VerifiedTrafficCounterView
	// VerifiedLinkMetrics contains independently verified, node-owned
	// single-hop measurements. It stays separate from Edges (the existing
	// report.neighbors/WireGuard contract) and from cumulative WG counters.
	VerifiedLinkMetrics []VerifiedLinkMetricView
	Tunnels             []TunnelView
	Targets             []TargetView
	// Rotating 是正在过渡窗口里的凭据。开着是正常的,开太久不是。
	Rotating []string
	Edges    []EdgeView
	Problems []string
}

// VerifiedTrafficCounterView is signed cumulative evidence retained for
// adjacent-sample history. It is not automatically the node's current value;
// the current-value contract remains TunnelView.CounterPresent.
type VerifiedTrafficCounterView struct {
	Interface, PeerNode, LinkID, PeerPublicKey string
	CounterEpoch, ObservedAt                   string
	RXBytes, TXBytes                           int64
}

// VerifiedLinkMetricView is one directed single-hop observation. Transfer
// bytes and duration are retained as raw signed values; presentation code
// derives achieved probe throughput without calling it business traffic or
// link capacity.
type VerifiedLinkMetricView struct {
	PeerNode, ObservedAt, Transport, Carrier string
	RTTMS, P50MS, P95MS, Samples, Failures   int
	TransferBytes, DurationMS                int64
}

type ComponentView struct {
	Name, Expected, Actual, Error string
	OK                            bool
}

type VersionView struct {
	Commit, Binary, Tag, Platform, Go, Error string
	Dirty                                    bool
}

type RolloutView struct {
	Snapshot, Stage, EnteredAt, LastGood, Error string
	AgeSec                                      int
	Problem                                     bool
	Stuck                                       bool
}

type AgentView struct {
	Node, UpdatedAt, Source string
	Selections              []RouteView
}

// LinkView 是拓扑底图中的边。Kind=tunnel 是 SSOT 派生 report.neighbors 的
// 常驻 WG；direct-hy2 是独立签名的 Hysteria2 单跳主动探测；
// candidate 是 RouteCandidate 的非 WG hop（未核验）；route 只作为当前选择覆盖层。
type LinkView struct {
	From, To   string
	Kind       string
	State      string
	MS         int
	Samples    int
	Failures   int
	ObservedAt string
	Source     string
	// ObservedFrom/ObservedTo preserve the direction of an active direct-link
	// probe even though the topology draws one relationship for the node pair.
	ObservedFrom, ObservedTo    string
	ProbeBytes, ProbeDurationMS int64
	ProbeSamples                int
	// Rolling quality is derived centrally from successive independently
	// verified report.neighbors summaries. RecentTXBytes is the sum of endpoint
	// WireGuard TX deltas, so each direction is counted once.
	QualityP50MS, QualityP95MS                      int
	QualityObservations, QualityFailed              int
	RecentTXBytes, RateWindowSeconds                int64
	RateSamples, RateReportingEndpoints             int
	MetricsWindow, MetricsObservedAt, MetricsSource string
}

const (
	ScopeService  = "service"
	ScopePolicy   = "policy"
	ScopeServices = "services"
)

type RouteView struct {
	Node, Declaration, Selector, Candidate, Reason string
	// ScopeKind/ScopeID 明确当前 selector 是按 service 还是 policy 选路；
	// PolicyID 是最终治理它的访问策略。Declaration 保留给旧消费者兼容。
	ScopeKind, ScopeID, PolicyID string
	Chain                        []string
	ObservedAt                   string
	Source                       string
	Stale                        bool
	Health                       *CandidateHealthView
}

type CandidateHealthView struct {
	Candidates, RecentSuccess, RecentDegraded, RecentFailed, Stale, Unknown int
	SelectedState, SelectedMetrics, BestMetrics                             string
}

// CandidatePathView 是 SSOT 业务候选路径，不是常驻隧道健康。State 为
// unverified 或 selected；只有后者来自 selector 实读。
type CandidatePathView struct {
	Node, Declaration            string
	ScopeKind, ScopeID, PolicyID string
	Chain                        []string
	State                        string
	ObservedAt                   string
	Source                       string
}

// ServiceView / PolicyView 保留 SSOT 的真实字段，既可做只读目录，也足以在
// 后续结构化编辑器中回显，而不需要从展示文案反解析配置。
type ServiceView struct {
	ID, Name, PolicyID string
	Addresses          []string
	Hosts              []HostRuleView
}

type HostRuleView struct {
	Host, Match string
}

type PolicyView struct {
	ID, Name, AddressAxis, EgressAxis, Matcher, ProbeURL string
	Objective, RankingPeriod, TuningPeriod               string
	Window, StaleAfter, Fallback                         string
	ProbeBudget, MaxHops, TopN, MinSamples               int
	SwitchThreshold                                      float64
	AvailabilityKnown, Available                         bool
	AllowedServers                                       []string
	Constraints                                          []ConstraintView
}

type ConstraintView struct {
	Kind, Expr string
}

// IngressView 是接入节点在 SSOT 中声明的本地入口。Declaration 保存原始
// 表单值；PolicyID 可包含 managed mixed/TUN 共用的有效设备默认策略。
type IngressView struct {
	Node, Platform, Kind, Listen, Mode        string
	ScopeKind, ScopeID, PolicyID, Declaration string
	Port                                      int
	Services, Default                         bool
}

type PublisherView struct {
	PID                                                       int
	IntervalSeconds                                           int64
	Commit, Binary                                            string
	StartedAt, UpdatedAt, LastSuccess, LastSnapshot, LastSSOT string
	LastError, LastErrorAt                                    string
	Healthy                                                   bool
}

type TunnelView struct {
	Interface string
	// CarrierPresent means this row came from direct interface/handshake state.
	// A relayed signed traffic counter can create a traffic-only row without
	// claiming that the remote carrier is active or failed.
	CarrierPresent bool
	// PeerNode/LinkID are the logical identity used for aggregation. The peer
	// public key is diagnostic only and may change during key rotation.
	PeerNode, LinkID, PeerPublicKey string
	State                           string // active / failed / down / 未握手
	AgeSec                          int
	// RxBytes/TxBytes are current cumulative counters, never time buckets.
	// CounterPresent distinguishes a sampled idle 0/0 counter from a tunnel row
	// whose interface is down or whose current counter attachment is absent.
	// CounterEpoch is the reset boundary; CounterObservedAt is sampling time.
	RxBytes, TxBytes                               int64
	CounterEpoch, CounterObservedAt, CounterSource string
	CounterPresent                                 bool
	TrafficTrusted, TrafficVerified                bool
	OK                                             bool
}

type TargetView struct {
	Target     string
	MS         int
	Err        string
	ObservedAt string
	// Uplink 表示这是"这台机器本该够得到"的地址 —— 它够不到才算问题。
	Uplink bool
}

type EdgeView struct {
	To         string
	MS         int
	Samples    int
	Failures   int
	Err        string
	ObservedAt string
}

// Handler 返回整个界面的 http.Handler。
func Handler(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodGet {
			fmt.Fprint(w, faviconSVG())
		}
	})
	mux.HandleFunc("/traffic.json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		if d.Snapshot == nil {
			http.NotFound(w, r)
			return
		}
		snapshot := d.Snapshot
		if d.TrafficSnapshot != nil {
			snapshot = d.TrafficSnapshot
		}
		view := snapshot()
		exported := trafficExport(view)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(exported)
	})
	readPage := func(fn func(bool) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
				return
			}
			writeHTML(w, fn(authed(d, r)))
		}
	}
	mux.HandleFunc("/clients", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		writeHTML(w, pageClients(d, clientPageState{Create: r.URL.Query().Get("new") == "1"}, authed(d, r)))
	})
	mux.HandleFunc("/clients/create", func(w http.ResponseWriter, r *http.Request) {
		// A successful response contains the short-lived bearer invitation URI.
		// Keep it out of shared/intermediary caches even on validation errors.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodPost {
			http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
			return
		}
		if !authed(d, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if d.Control == nil || d.Control.Clients == nil || d.Control.Clients.CreateInvite == nil {
			http.Error(w, "这台机器没有客户端注册能力", http.StatusNotImplemented)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			writeHTML(w, pageClients(d, clientPageState{Create: true, Error: "表单无法解析"}, true))
			return
		}
		name := strings.TrimSpace(r.Form.Get("name"))
		invite, err := d.Control.Clients.CreateInvite(ClientInviteInput{Name: name})
		if err != nil {
			writeHTML(w, pageClients(d, clientPageState{Create: true, SubmittedName: name, Error: err.Error()}, true))
			return
		}
		writeHTML(w, pageClients(d, clientPageState{Invite: &invite}, true))
	})
	mux.HandleFunc("/clients/download/linux-amd64", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		if !authed(d, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if d.Control == nil || d.Control.Clients == nil || d.Control.Clients.DownloadLinuxPackage == nil {
			http.Error(w, "Linux 客户端包尚未发布", http.StatusServiceUnavailable)
			return
		}
		view, body, err := d.Control.Clients.DownloadLinuxPackage()
		if err != nil {
			// 本机绝对路径与验签细节不暴露给下载响应。
			http.Error(w, "Linux 客户端包不可用", http.StatusServiceUnavailable)
			return
		}
		hash := sha256.Sum256(body)
		if view.Filename != "loom-client-linux-amd64.tar.gz" ||
			view.URL != "/clients/download/linux-amd64" || view.Arch != "linux/amd64" ||
			view.Size != int64(len(body)) || view.SHA256 != fmt.Sprintf("%x", hash[:]) {
			http.Error(w, "Linux 客户端包验证结果不一致", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", `attachment; filename="loom-client-linux-amd64.tar.gz"`)
		w.Header().Set("Content-Length", strconv.FormatInt(int64(len(body)), 10))
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/api/control/clients", func(w http.ResponseWriter, r *http.Request) {
		clientJSONHeaders(w)
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSONError(w, http.StatusMethodNotAllowed, "只接受 GET")
			return
		}
		if !authed(d, r) {
			writeJSONError(w, http.StatusUnauthorized, "需要中控运维会话")
			return
		}
		if d.Control == nil || d.Control.Clients == nil || d.Control.Clients.List == nil {
			writeJSONError(w, http.StatusNotImplemented, "这台机器没有客户端注册能力")
			return
		}
		inventory, err := loadClientInventory(d)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, inventory)
	})
	mux.HandleFunc("/api/control/client-invites", func(w http.ResponseWriter, r *http.Request) {
		clientJSONHeaders(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeJSONError(w, http.StatusMethodNotAllowed, "只接受 POST")
			return
		}
		if !authed(d, r) {
			writeJSONError(w, http.StatusUnauthorized, "需要中控运维会话")
			return
		}
		if d.Control == nil || d.Control.Clients == nil || d.Control.Clients.CreateInvite == nil {
			writeJSONError(w, http.StatusNotImplemented, "这台机器没有客户端注册能力")
			return
		}
		var input ClientInviteInput
		if err := decodeClientJSON(w, r, &input); err != nil {
			writeJSONError(w, clientDecodeStatus(err), err.Error())
			return
		}
		invite, err := d.Control.Clients.CreateInvite(input)
		if err != nil {
			writeJSONError(w, clientProtocolStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, invite)
	})
	mux.HandleFunc("/api/control/client-invites/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		if !authed(d, r) {
			http.Error(w, "需要中控运维会话", http.StatusUnauthorized)
			return
		}
		if d.Control == nil || d.Control.Clients == nil || d.Control.Clients.InviteArtifact == nil {
			http.NotFound(w, r)
			return
		}
		relative := strings.TrimPrefix(r.URL.Path, "/api/control/client-invites/")
		inviteID, action, ok := strings.Cut(relative, "/")
		if !ok || inviteID == "" || strings.Contains(action, "/") ||
			(action != "qr.png" && action != "download") {
			http.NotFound(w, r)
			return
		}
		artifact, err := d.Control.Clients.InviteArtifact(inviteID)
		if err != nil {
			http.Error(w, err.Error(), clientProtocolStatus(err))
			return
		}
		if action == "download" {
			w.Header().Set("Content-Type", "application/vnd.loom.invite; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="client.loom-invite"`)
			fmt.Fprintln(w, artifact.InviteURI)
			return
		}
		png, err := qrcode.Encode(artifact.InviteURI, qrcode.Medium, 320)
		if err != nil {
			http.Error(w, "二维码生成失败", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		_, _ = w.Write(png)
	})
	mux.HandleFunc("/api/client/enroll", func(w http.ResponseWriter, r *http.Request) {
		clientJSONHeaders(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeJSONError(w, http.StatusMethodNotAllowed, "只接受 POST")
			return
		}
		if d.Control == nil || d.Control.Clients == nil || d.Control.Clients.Claim == nil {
			// Do not reveal whether an invite exists when this node is not the issuer.
			writeJSONError(w, http.StatusNotFound, "client enrollment is unavailable")
			return
		}
		var wire struct {
			Token     string `json:"token"`
			Platform  string `json:"platform"`
			CSRPEM    string `json:"csr_pem"`
			RequestID string `json:"request_id"`
		}
		if err := decodeClientJSON(w, r, &wire); err != nil {
			writeJSONError(w, clientDecodeStatus(err), err.Error())
			return
		}
		result, err := d.Control.Clients.Claim(ClientClaimInput{
			Token: wire.Token, Platform: wire.Platform, CSRPEM: wire.CSRPEM, RequestID: wire.RequestID,
		})
		if err != nil {
			status := clientProtocolStatus(err)
			message := err.Error()
			if status == http.StatusInternalServerError {
				// Provisioning errors can contain local paths, SSH targets or other
				// operator-only diagnostics. The public invitation endpoint exposes
				// only a retryable boundary, never those internals.
				message = "client provisioning is temporarily unavailable"
				log.Printf("client provisioning failed: %v", err)
			}
			writeJSONError(w, status, message)
			return
		}
		status := http.StatusOK
		if result.Configuration == "pending" {
			status = http.StatusAccepted
		}
		writeJSON(w, status, result)
	})
	mux.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		writeHTML(w, pageNodes(d, authed(d, r), strings.TrimSpace(r.URL.Query().Get("added"))))
	})
	mux.HandleFunc("/nodes/add", readPage(func(ok bool) string {
		return pageNodeAdd(d, nodeAddPageState{}, ok)
	}))
	mux.HandleFunc("/nodes/add/scan", func(w http.ResponseWriter, r *http.Request) {
		if !requireEnrollmentWrite(d, w, r) {
			return
		}
		connection, _, err := parseEnrollmentForm(w, r, false)
		state := nodeAddPageState{Phase: "connect", Connection: connection}
		if err == nil {
			state.HostKey, err = d.Control.Enrollment.Scan(r.Context(), connection)
			state.Phase = "confirm"
		}
		if err != nil {
			state.Error = err.Error()
		}
		writeHTML(w, pageNodeAdd(d, state, true))
	})
	mux.HandleFunc("/nodes/add/review", func(w http.ResponseWriter, r *http.Request) {
		if !requireEnrollmentWrite(d, w, r) {
			return
		}
		connection, hostKey, err := parseEnrollmentForm(w, r, true)
		disableGeoIP := r.Form.Get("disable_geoip") == "yes"
		state := nodeAddPageState{Phase: "confirm", Connection: connection, HostKey: hostKey, DisableGeoIP: disableGeoIP}
		if err == nil && r.Form.Get("confirm_host_key") != "yes" {
			err = fmt.Errorf("confirm the SSH host fingerprint before preflight")
		}
		if err == nil {
			review, reviewErr := d.Control.Enrollment.Review(r.Context(), EnrollmentReviewInput{
				Connection: connection, HostKey: hostKey, DisableGeoIP: disableGeoIP, RequestedDirection: "automatic",
			})
			err = reviewErr
			if err == nil {
				state.Phase, state.Review = "review", &review
			}
		}
		if err != nil {
			state.Error = err.Error()
		}
		writeHTML(w, pageNodeAdd(d, state, true))
	})
	mux.HandleFunc("/nodes/add/commit", func(w http.ResponseWriter, r *http.Request) {
		if !requireEnrollmentWrite(d, w, r) {
			return
		}
		connection, hostKey, err := parseEnrollmentForm(w, r, true)
		country, countryErr := parseEnrollmentCountry(r)
		city, cityErr := parseEnrollmentCity(r)
		if err == nil {
			err = countryErr
		}
		if err == nil {
			err = cityErr
		}
		requested := strings.TrimSpace(r.Form.Get("direction"))
		input := EnrollmentReviewInput{
			Connection: connection, HostKey: hostKey,
			Country: country, City: city, DisableGeoIP: r.Form.Get("disable_geoip") == "yes",
			RequestedDirection: requested,
		}
		validReviewInput := err == nil
		state := nodeAddPageState{Phase: "review", Connection: connection, HostKey: hostKey}
		if err == nil && r.Form.Get("action") == "preview" {
			var review EnrollmentReview
			review, err = d.Control.Enrollment.Review(r.Context(), input)
			if err == nil {
				state.Review = &review
			}
		} else if err == nil && r.Form.Get("action") == "commit" {
			reviewedDirection := strings.TrimSpace(r.Form.Get("reviewed_direction"))
			commitInput := EnrollmentCommitInput{
				EnrollmentReviewInput:      input,
				ExpectedNodeID:             strings.TrimSpace(r.Form.Get("expected_node")),
				ExpectedEndpoint:           strings.TrimSpace(r.Form.Get("expected_endpoint")),
				ExpectedEndpointResolution: strings.TrimSpace(r.Form.Get("expected_endpoint_resolution")),
				ExpectedRevision:           strings.TrimSpace(r.Form.Get("revision")),
			}
			switch {
			case reviewedDirection == "":
				err = fmt.Errorf("reviewed direction is missing; recompute and review the direction plan before committing")
			case requested != reviewedDirection:
				err = fmt.Errorf("direction changed after review; recompute and review the direction plan before committing")
			case !validEnrollmentReviewToken(d, commitInput, r.Form.Get("review_token")):
				err = fmt.Errorf("review binding is invalid; recompute and review the direction plan before committing")
			default:
				var nodeID string
				nodeID, err = d.Control.Enrollment.Commit(r.Context(), commitInput)
				if err == nil {
					http.Redirect(w, r, "/nodes?added="+url.QueryEscape(nodeID), http.StatusSeeOther)
					return
				}
			}
		} else if err == nil {
			err = fmt.Errorf("unknown enrollment action")
		}
		if err != nil {
			state.Error = err.Error()
			if committed, ok := err.(interface{ Committed() bool }); ok {
				state.Committed = committed.Committed()
			}
			// A failed commit is deliberately re-reviewed from trusted state instead
			// of echoing hidden plan fields back as if they were observations.
			if validReviewInput {
				if review, reviewErr := d.Control.Enrollment.Review(r.Context(), input); reviewErr == nil {
					state.Review = &review
				}
			}
		}
		writeHTML(w, pageNodeAdd(d, state, true))
	})
	mux.HandleFunc("/nodes/bootstrap-key/generate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
			return
		}
		if !authed(d, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if d.Control == nil || d.Control.BootstrapIdentity == nil {
			http.Error(w, "这台机器没有 bootstrap identity 能力", http.StatusNotImplemented)
			return
		}
		if _, err := d.Control.BootstrapIdentity.Ensure(); err != nil {
			writeHTML(w, pageResult(d, "Generate bootstrap identity", "", err))
			return
		}
		http.Redirect(w, r, "/nodes", http.StatusSeeOther)
	})
	mux.HandleFunc("/nodes/bootstrap-key.pub", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		if !authed(d, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if d.Control == nil || d.Control.BootstrapIdentity == nil {
			http.NotFound(w, r)
			return
		}
		key, err := d.Control.BootstrapIdentity.Status()
		if err != nil || !key.Ready {
			http.Error(w, "bootstrap public key is not ready", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="loom-control-bootstrap.pub"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintln(w, key.PublicKey)
	})
	mux.HandleFunc("/nodes/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		raw := strings.TrimPrefix(r.URL.Path, "/nodes/")
		if raw == "" || strings.Contains(raw, "/") {
			http.NotFound(w, r)
			return
		}
		id, err := url.PathUnescape(raw)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		body, found := pageNodeDetail(d, id, authed(d, r))
		if !found {
			http.NotFound(w, r)
			return
		}
		writeHTML(w, body)
	})
	mux.HandleFunc("/topology", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		writeHTML(w, pageTopology(d, authed(d, r), strings.TrimSpace(r.URL.Query().Get("entry"))))
	})
	mux.HandleFunc("/api/control/default-exit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !authed(d, r) {
			writeJSONError(w, http.StatusUnauthorized, "需要中控运维会话")
			return
		}
		if d.Control == nil || d.Control.DefaultExits == nil {
			writeJSONError(w, http.StatusNotImplemented, "这台机器没有设备默认出口管理能力")
			return
		}
		switch r.Method {
		case http.MethodGet:
			nodeID := strings.TrimSpace(r.URL.Query().Get("node"))
			if nodeID == "" || len(nodeID) > 128 {
				writeJSONError(w, http.StatusBadRequest, "node 必填且不能超过 128 字节")
				return
			}
			state, err := d.Control.DefaultExits.Get(nodeID)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, state)
		case http.MethodPut:
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mediaType != "application/json" {
				writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type 必须是 application/json")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			var input struct {
				Node        string `json:"node"`
				Declaration string `json:"declaration"`
				Revision    string `json:"revision"`
			}
			if err := dec.Decode(&input); err != nil {
				writeJSONError(w, http.StatusBadRequest, "JSON 无法解析:"+err.Error())
				return
			}
			if err := dec.Decode(&struct{}{}); err != io.EOF {
				writeJSONError(w, http.StatusBadRequest, "请求体只能包含一个 JSON 对象")
				return
			}
			input.Node = strings.TrimSpace(input.Node)
			input.Declaration = strings.TrimSpace(input.Declaration)
			input.Revision = strings.TrimSpace(input.Revision)
			if input.Node == "" || len(input.Node) > 128 || len(input.Declaration) > 128 || input.Revision == "" {
				writeJSONError(w, http.StatusBadRequest, "node、revision 必填，字段不能超过 128 字节")
				return
			}
			state, err := d.Control.DefaultExits.Set(input.Node, input.Declaration, input.Revision)
			if err != nil {
				status := http.StatusBadRequest
				if strings.Contains(err.Error(), "SSOT 已被其他操作修改") {
					status = http.StatusConflict
				}
				writeJSONError(w, status, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, state)
		default:
			w.Header().Set("Allow", "GET, PUT")
			writeJSONError(w, http.StatusMethodNotAllowed, "只接受 GET 或 PUT")
		}
	})
	mux.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		message := ""
		if r.URL.Query().Get("saved") == "1" {
			message = "Service saved to SSOT. Publishing remains automatic."
		} else if r.URL.Query().Get("deleted") == "1" {
			message = "Service removed from SSOT. Publishing remains automatic."
		}
		writeHTML(w, pageServices(d, r.URL.Query().Get("service"), r.URL.Query().Get("new") == "1", message, false, nil, authed(d, r)))
	})
	serviceWrite := func(w http.ResponseWriter, r *http.Request, deleting bool) {
		if r.Method != http.MethodPost {
			http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
			return
		}
		if !authed(d, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if d.Control == nil || d.Control.Services == nil {
			http.Error(w, "这台机器没有结构化 Service 写能力", http.StatusNotImplemented)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "表单过大或无法解析", http.StatusBadRequest)
			return
		}
		id := strings.TrimSpace(r.Form.Get("id"))
		revision := r.Form.Get("revision")
		submitted := ServiceInput{
			ID: id, Name: strings.TrimSpace(r.Form.Get("name")),
			Declaration: strings.TrimSpace(r.Form.Get("declaration")),
			Addresses:   serviceAddresses(r.Form.Get("addresses")),
		}
		var err error
		if deleting {
			err = d.Control.Services.Delete(id, revision)
		} else {
			err = d.Control.Services.Upsert(submitted, revision)
		}
		if err != nil {
			writeHTML(w, pageServices(d, id, !deleting && !serviceExists(d.Snapshot(), id), err.Error(), true, &submitted, true))
			return
		}
		if deleting {
			http.Redirect(w, r, "/services?deleted=1", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/services?service="+url.QueryEscape(id)+"&saved=1", http.StatusSeeOther)
	}
	mux.HandleFunc("/services/save", func(w http.ResponseWriter, r *http.Request) { serviceWrite(w, r, false) })
	mux.HandleFunc("/services/delete", func(w http.ResponseWriter, r *http.Request) { serviceWrite(w, r, true) })
	mux.HandleFunc("/routing", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		writeHTML(w, pageRouting(d, authed(d, r), strings.TrimSpace(r.URL.Query().Get("entry"))))
	})
	mux.HandleFunc("/deployments", readPage(func(ok bool) string { return pageDeployments(d, ok) }))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeHTML(w, pageOverview(d, authed(d, r)))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeHTML(w, pageLogin(d, ""))
			return
		}
		// 口令比较用常数时间:普通的 == 会因为提前返回而泄露前缀长度。
		if d.Operator == "" {
			writeHTML(w, pageLogin(d, "这台机器没有配置运维口令,写操作全部关闭"))
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(d.Operator)) != 1 {
			writeHTML(w, pageLogin(d, "口令不对"))
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: cookieName, Value: mintToken(d), Path: "/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
			MaxAge: int(sessionTTL.Seconds()),
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("/act/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
			return
		}
		if !authed(d, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/act/")
		fn, ok := d.Actions[name]
		if !ok {
			http.Error(w, "未知动作", http.StatusNotFound)
			return
		}
		out, err := fn()
		writeHTML(w, pageResult(d, name, out, err))
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
			return
		}
		writeHTML(w, pageEvents(d, eventFilterFromRequest(r), authed(d, r)))
	})
	if d.Events != nil {
		mux.HandleFunc("/events.csv", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="loom-events.csv"`)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			cw := csv.NewWriter(w)
			_ = cw.Write([]string{"timestamp", "node", "kind", "subject", "from", "to", "level", "duration", "ongoing", "detail"})
			for _, e := range filterEvents(d.Events(10000), eventFilterFromRequest(r)) {
				_ = cw.Write([]string{e.TS, e.Node, e.Kind, e.Subject, e.From, e.To, e.Level, e.Lasted, strconv.FormatBool(e.Ongoing), e.Detail})
			}
			cw.Flush()
		})
	}
	if d.Control != nil {
		serveSSOT := func(w http.ResponseWriter, r *http.Request) {
			if !authed(d, r) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if r.Method != http.MethodPost {
				body, err := d.Control.Read()
				revision := ""
				if err == nil && d.Control.Revision != nil {
					revision, err = d.Control.Revision()
				}
				writeHTML(w, pageSSOT(d, body, revision, "", err, false))
				return
			}
			body := r.FormValue("content")
			revision := r.FormValue("revision")
			findings, err := d.Control.Validate(body)
			// 只校验不保存:让人先看清楚改动会带来什么。
			if r.FormValue("action") != "save" {
				writeHTML(w, pageSSOT(d, body, revision, findings, err, false))
				return
			}
			if err == nil && findings == "" {
				if d.Control.SaveIfRevision != nil {
					err = d.Control.SaveIfRevision(body, revision)
				} else {
					err = d.Control.Save(body)
				}
			}
			saved := err == nil && findings == ""
			if saved && d.Control.Revision != nil {
				revision, err = d.Control.Revision()
				saved = err == nil
			}
			writeHTML(w, pageSSOT(d, body, revision, findings, err, saved))
		}
		mux.HandleFunc("/ssot", serveSSOT)
		mux.HandleFunc("/settings", serveSSOT)
	} else {
		mux.HandleFunc("/settings", readPage(func(ok bool) string {
			return shell(d, "Settings", `<div class=empty>This node has no control role. SSOT writes and control keys are intentionally unavailable here.</div>`, ok)
		}))
	}
	return mux
}

const enrollmentReviewTokenDomain = "loom:webui:node-enrollment-review:v3"

// enrollmentReviewMAC signs the complete client-visible boundary between a
// reviewed plan and its commit. Length-prefixing keeps the encoding
// unambiguous even when a host key or endpoint contains punctuation.
func enrollmentReviewMAC(operator string, input EnrollmentCommitInput) []byte {
	mac := hmac.New(sha256.New, []byte(operator))
	mac.Write([]byte(enrollmentReviewTokenDomain))
	fields := []string{
		input.Connection.Host,
		input.Connection.User,
		strconv.Itoa(input.Connection.Port),
		input.HostKey.Algorithm,
		input.HostKey.PublicKey,
		input.HostKey.Fingerprint,
		input.Country,
		input.City,
		strconv.FormatBool(input.DisableGeoIP),
		input.RequestedDirection,
		input.ExpectedNodeID,
		input.ExpectedEndpoint,
		input.ExpectedEndpointResolution,
		input.ExpectedRevision,
	}
	for _, field := range fields {
		mac.Write([]byte(strconv.Itoa(len(field))))
		mac.Write([]byte{':'})
		mac.Write([]byte(field))
	}
	return mac.Sum(nil)
}

func mintEnrollmentReviewToken(d Deps, input EnrollmentCommitInput) string {
	if d.Operator == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(enrollmentReviewMAC(d.Operator, input))
}

func validEnrollmentReviewToken(d Deps, input EnrollmentCommitInput, token string) bool {
	if d.Operator == "" {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return false
	}
	want := enrollmentReviewMAC(d.Operator, input)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func requireEnrollmentWrite(d Deps, w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return false
	}
	if !authed(d, r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}
	if d.Control == nil || d.Control.Enrollment == nil {
		http.Error(w, "这台机器没有受信节点接入能力", http.StatusNotImplemented)
		return false
	}
	return true
}

func parseEnrollmentForm(w http.ResponseWriter, r *http.Request, withHostKey bool) (EnrollmentConnection, EnrollmentHostKey, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		return EnrollmentConnection{}, EnrollmentHostKey{}, fmt.Errorf("enrollment form is too large or malformed")
	}
	read := func(name string, limit int) (string, error) {
		value := strings.TrimSpace(r.Form.Get(name))
		if value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		if len(value) > limit {
			return "", fmt.Errorf("%s exceeds %d bytes", name, limit)
		}
		return value, nil
	}
	host, err := read("host", 253)
	if err != nil {
		return EnrollmentConnection{}, EnrollmentHostKey{}, err
	}
	user, err := read("user", 64)
	if err != nil {
		return EnrollmentConnection{}, EnrollmentHostKey{}, err
	}
	portText, err := read("port", 5)
	if err != nil {
		return EnrollmentConnection{}, EnrollmentHostKey{}, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return EnrollmentConnection{}, EnrollmentHostKey{}, fmt.Errorf("SSH port must be an integer from 1 to 65535")
	}
	connection := EnrollmentConnection{Host: host, User: user, Port: port}
	if !withHostKey {
		return connection, EnrollmentHostKey{}, nil
	}
	algorithm, err := read("host_key_algorithm", 32)
	if err != nil {
		return connection, EnrollmentHostKey{}, err
	}
	publicKey, err := read("host_key_public", 2048)
	if err != nil {
		return connection, EnrollmentHostKey{}, err
	}
	fingerprint, err := read("host_key_fingerprint", 256)
	if err != nil {
		return connection, EnrollmentHostKey{}, err
	}
	return connection, EnrollmentHostKey{
		Algorithm: algorithm, PublicKey: publicKey, Fingerprint: fingerprint,
	}, nil
}

func parseEnrollmentCity(r *http.Request) (string, error) {
	city := strings.TrimSpace(r.Form.Get("city"))
	if city == "" {
		return "", nil
	}
	if !utf8.ValidString(city) {
		return "", fmt.Errorf("city must be valid UTF-8")
	}
	if len(city) > 256 {
		return "", fmt.Errorf("city exceeds 256 bytes")
	}
	if strings.IndexFunc(city, func(r rune) bool { return unicode.IsControl(r) }) >= 0 {
		return "", fmt.Errorf("city contains a control character")
	}
	return city, nil
}

func parseEnrollmentCountry(r *http.Request) (string, error) {
	country := strings.ToUpper(strings.TrimSpace(r.Form.Get("country")))
	if country == "" {
		return "", nil
	}
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return "", fmt.Errorf("country must be a two-letter ISO 3166-1 alpha-2 code")
	}
	return country, nil
}

func eventFilterFromRequest(r *http.Request) eventFilter {
	q := r.URL.Query()
	trim := func(value string) string {
		value = strings.TrimSpace(value)
		if len(value) > 128 {
			value = value[:128]
		}
		return value
	}
	return eventFilter{
		Node: trim(q.Get("node")), Kind: trim(q.Get("kind")),
		Level: trim(q.Get("level")), Query: trim(q.Get("q")),
	}
}

const (
	cookieName = "loom_session"
	sessionTTL = 12 * time.Hour
)

// mintToken 签一个带过期时间的会话票。
//
// 用 HMAC 而不是随机 token + 服务端表:上报者是无状态的,重启一次所有人
// 都得重登。密钥就是运维口令本身 —— 口令换了,已发出去的票立刻全失效,
// 这正是想要的。
func mintToken(d Deps) string {
	exp := d.Now().Add(sessionTTL).Unix()
	body := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, []byte(d.Operator))
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func authed(d Deps, r *http.Request) bool {
	if d.Operator == "" {
		return false
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	body, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, []byte(d.Operator))
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(body, 10, 64)
	return err == nil && d.Now().Unix() < exp
}

func clientJSONHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

type clientDecodeError struct {
	status int
	msg    string
}

func (e *clientDecodeError) Error() string { return e.msg }

func decodeClientJSON(w http.ResponseWriter, r *http.Request, value any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return &clientDecodeError{status: http.StatusUnsupportedMediaType, msg: "Content-Type 必须是 application/json"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return fmt.Errorf("JSON 无法解析: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("请求体只能包含一个 JSON 对象")
	}
	return nil
}

func clientDecodeStatus(err error) int {
	if requestErr, ok := err.(*clientDecodeError); ok {
		return requestErr.status
	}
	return http.StatusBadRequest
}

func clientProtocolStatus(err error) int {
	withCode, ok := err.(interface{ ProtocolCode() string })
	if !ok {
		return http.StatusInternalServerError
	}
	switch withCode.ProtocolCode() {
	case "invalid_request":
		return http.StatusBadRequest
	case "invite_not_found":
		return http.StatusNotFound
	case "invite_expired":
		return http.StatusGone
	case "invite_already_used":
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: message})
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 界面里没有任何外部资源,也不该有 —— 这些机器不一定能出网,而且
	// ssh 端口转发进来时更没有。img-src 只允许静态样式里自带的导航 SVG。
	progressDigest := sha256.Sum256([]byte(progressSubmitScript))
	progressHash := base64.StdEncoding.EncodeToString(progressDigest[:])
	topologyDigest := sha256.Sum256([]byte(topologyInteractionScript))
	topologyHash := base64.StdEncoding.EncodeToString(topologyDigest[:])
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'sha256-"+progressHash+"' 'sha256-"+topologyHash+"'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	fmt.Fprint(w, body)
}
