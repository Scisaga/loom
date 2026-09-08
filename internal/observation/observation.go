package observation

import (
	"loom/internal/attest"
	"loom/internal/version"
)

// Observation 保持 §16.1 原线格式；纯读取层不依赖 Linux 采集或控制面。
type Observation struct {
	Node string `json:"node"`
	TS   string `json:"ts"`
	// Applied 是这台机器当时装着的快照 id。
	//
	// **它必须挂在观测上,不能只挂在 Status 上** —— 转述传的是观测,
	// 而"全网是不是同一版"恰恰要靠转述才能对够不到的节点回答。挂错地方的
	// 表现是:界面上够得到的那台显示版本号,其余全是"(未记录)",于是
	// 每次都报"全网不是同一个快照"。
	Applied    string              `json:"applied,omitempty"`
	Version    *version.Coordinate `json:"version,omitempty"`
	Rollout    *RolloutState       `json:"rollout,omitempty"`
	Agent      *AgentState         `json:"agent,omitempty"`
	Components []ComponentStatus   `json:"components,omitempty"`
	Edges      []Edge              `json:"edges,omitempty"`
	Targets    []Reach             `json:"targets,omitempty"`

	// Traffic is a separately signed, node-owned WireGuard counter snapshot.
	// It is deliberately outside the v5 attestation and measurement digest:
	// old readers ignore this optional field, while new readers verify the
	// loom-traffic-v1 domain before mapping any remote counter.
	Traffic *attest.TrafficAttest `json:"traffic,omitempty"`

	// LinkMetrics is an independently signed public Hysteria2 single-hop probe
	// snapshot.  Keeping it outside loom-attest-v5 and loom-traffic-v1 preserves
	// both deployed canonical contracts during rolling upgrades.
	LinkMetrics *attest.LinkMetricAttest `json:"link_metrics,omitempty"`

	// SelfCheck is a separately signed verdict derived from this node's full
	// local Status. It is outside loom-attest-v5 so old readers can ignore it
	// during a rolling upgrade without changing v5 canonical bytes. A relay's
	// outer HTTP status is never accepted as remote health evidence.
	SelfCheck *attest.SelfCheckAttest `json:"self_check,omitempty"`

	// Attest 是主签名。完成 phase B 后的新 producer 直接把 canonical v5 放在
	// 这里并省略 AttestExtended。AttestExtended 只用于滚动升级期间：当 Attest
	// 仍是旧 reader 可验证的 legacy 签名时，它携带完整 v4/v5 陈述。
	//
	// 观测可以转述:RTT、可达性是尽力而为的数字,B 转述 C 的观测,
	// 可信度就是 B 的可信度,而这够用了。**身份不行** —— "C 跑的是
	// commit X"如果只由 B 说,排障时恰恰不能假设 B 可信,因为出问题的
	// 往往就是链路上某一环。
	//
	// 签了名之后,转述的是密文不是信任:改一个字就验不过,伪造要 C 的
	// 私钥。这条正是 D71/D73 那个"版本核不了转述来的节点"的解法。
	//
	// 没有私钥的机器(比如只有 ca.crt 的中控)这里是空的,而空**不等于
	// 可信**:验不了就是验不了,调用方要当作"没核对过"。
	Attest         *attest.Signed `json:"attest,omitempty"`
	AttestExtended *attest.Signed `json:"attest_extended,omitempty"`
}

// Edge 是本节点到另一个节点的往返时间。
//
// **RTTMs 是最近若干次的中位数,不是最后一次。** 单次 TCP 建连是个很差的
// 估计:实测同一条隧道连 12 次,11 次 287ms、1 次 1316ms —— 丢一个 SYN 就
// 差出 4 倍。而上报出去的如果是最后一次,谁拿它算路径谁倒霉。
type Edge struct {
	To    string `json:"to"`
	RTTMs int    `json:"rtt_ms,omitempty"`
	// Samples / Failures 让下游知道这个数字有多少依据。
	Samples  int    `json:"samples,omitempty"`
	Failures int    `json:"failures,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Reach 是本节点**直接**访问某个目标地址的结果。
//
// 它回答的是"这台机器出去能不能到那儿",与任何链路无关 —— 正因为无关,
// 它才能被所有接入节点复用。
type Reach struct {
	Target string `json:"target"`
	// FirstByteMs 同样是中位数,不是最后一次。
	FirstByteMs int `json:"first_byte_ms,omitempty"`
	Samples     int `json:"samples,omitempty"`
	Failures    int `json:"failures,omitempty"`
	// Error 是最近一次失败的原因。**只有全部失败时才该据此判定不可达** ——
	// 一次抖动不该让一个出口被剪掉 15 分钟。
	Error string `json:"error,omitempty"`

	// Uplink 表示这是"这台机器本该够得到"的地址。
	//
	// **它决定失败算数据还是算问题。** 不带这个标记的失败是喂 Agent 剪枝
	// 的有用数据(国内机器够不到 Cloudflare 是结构性的正常状态);带这个
	// 标记的失败是这台机器的直连坏了,需要人管。
	Uplink bool `json:"uplink,omitempty"`
}

// OK 报告这个目标可达。
func (r *Reach) OK() bool { return r.Error == "" }

// §16.1：状态字段复用原 attest 类型，避免平台间签名字段漂移。
type RolloutState = attest.RolloutClaim
type AgentState = attest.AgentClaim
type AgentSelection = attest.SelectionClaim
type AgentCandidateHealth = attest.CandidateHealthClaim
type ComponentStatus = attest.ComponentClaim
