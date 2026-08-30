package report

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"loom/internal/attest"
	"loom/internal/netx"
	"loom/internal/version"
)

// Observation 是**一个节点在某一刻对外界的观测**,可以被别的节点原样转述。
//
// 这是链路状态式测量的基本单位:每台机器只量自己能量的那几段,然后互相
// 交换。对比"从接入节点把每条完整路线跑一遍":
//
//	按路线量  15 条链 × 每个接入节点各测一遍,同一个事实被重复发现 N 次
//	按段量    每台只量自己那几段,并行,"cn-a 到不了 Cloudflare"只测一次
//
// Node 字段是**观测者**,不是被观测者 —— 转述时必须原样保留,否则合并的
// 时候分不清这条数据是谁量的。
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

	// Attest 是给旧版 reader 的 v1-v3 兼容签名；AttestExtended 是新版对
	// Agent 候选健康与组件版本的完整签名。滚动升级期间必须双签：旧 reader
	// 会忽略新 JSON 字段，但无法验证 v4/v5 canonical。
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

// Age 返回这条观测有多旧。解析不了时间时返回一个很大的值 —— 宁可当它过期,
// 也不要拿一条来历不明的数据去做决定。
func (o *Observation) Age(now time.Time) time.Duration {
	t, err := time.Parse(time.RFC3339, o.TS)
	if err != nil {
		return 100 * 365 * 24 * time.Hour
	}
	age := now.Sub(t)
	// 过远的未来时间会让这条观测长期“永远最新”。它与解析失败一样，
	// 宁可当作过期，也不能让它占住 Node 索引。
	if age < -2*time.Minute {
		return 100 * 365 * 24 * time.Hour
	}
	return age
}

// history 保留每个被测对象最近若干次的结果。
//
// 中位数需要历史,而上报者本来是无状态的 —— 这是它唯一持有的状态,
// 而且只在内存里:重启之后重新攒,几分钟就回来了。
type history struct {
	mu sync.Mutex
	by map[string][]sample
	// linkBy is a separate rolling window for public Hysteria2 single-hop
	// probes.  It must not share Edge history: Edge is the persistent WG carrier
	// contract and uses a different cadence and meaning.
	linkBy   map[string][]linkProbeSample
	linkLast map[string]time.Time
}

type sample struct {
	ms  int
	err string
}

// keep 是保留多少次。1 分钟一轮,5 次约等于 5 分钟的窗口;
// 中位数因此能顶住两次离群。
const keep = 5

// Probes are independent network reads. Serial execution makes a nominal
// one-minute round grow by every timeout (N×5s + M×8s). Keep concurrency
// bounded so a larger SSOT cannot create an unbounded burst, while allowing a
// small fleet to finish within the configured cadence.
const probeConcurrency = 8

func parallelProbe(count int, fn func(int)) {
	if count <= 0 {
		return
	}
	limit := probeConcurrency
	if count < limit {
		limit = count
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn(index)
		}(i)
	}
	wg.Wait()
}

func newHistory() *history {
	return &history{
		by: map[string][]sample{}, linkBy: map[string][]linkProbeSample{},
		linkLast: map[string]time.Time{},
	}
}

func (h *history) add(key string, ms int, err error) (median, samples, failures int, lastErr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := sample{ms: ms}
	if err != nil {
		s.err = err.Error()
	}
	xs := append(h.by[key], s)
	if len(xs) > keep {
		xs = xs[len(xs)-keep:]
	}
	h.by[key] = xs

	var ok []int
	for _, x := range xs {
		if x.err == "" {
			ok = append(ok, x.ms)
		} else {
			failures++
			lastErr = x.err
		}
	}
	samples = len(xs)
	if len(ok) == 0 {
		return 0, samples, failures, lastErr
	}
	sort.Ints(ok)
	return ok[len(ok)/2], samples, failures, lastErr
}

// observe 量一遍本节点能量的东西:到每个邻居的 RTT、到每个目标的可达性。
// 返回同一轮开始时采集的完整 Status，供事件、流量历史和 Web 快照复用；
// 否则 gossip 刚做完签名自检，调用方又会机械地执行一遍完整 Collect。
func observe(cfg *Config, h *history, now time.Time) (*Observation, *Status) {
	// Take one complete local Status snapshot first. Observation identity fields
	// and the independent self-check verdict must describe the same collection,
	// rather than racing two separate rollout/Agent/component reads.
	dump, stats, wgErrors := readWGSnapshot()
	localStatus := collectWithWGStats(cfg, now, stats, wgErrors)
	o := &Observation{
		Node: localStatus.Node, TS: localStatus.TS, Applied: localStatus.Applied,
		Version: localStatus.Version, Rollout: localStatus.Rollout,
		Components: append([]ComponentStatus(nil), localStatus.Components...),
	}
	// Collect retains a parsed Agent state alongside validation errors for local
	// diagnosis. Only a state that satisfies the signed wire contract may enter
	// Observation; the errors themselves remain in the signed self-check.
	if len(validateAgentStateForConfig(localStatus.Agent, cfg, now)) == 0 {
		o.Agent = localStatus.Agent
	}
	nb := append([]Neighbor(nil), cfg.Neighbors...)
	sort.Slice(nb, func(i, j int) bool { return nb[i].Node < nb[j].Node })
	edges := make([]Edge, len(nb))
	parallelProbe(len(nb), func(i int) {
		n := nb[i]
		ms, err := tcpRTT(n.Addr, 5*time.Second)
		med, samples, fails, lastErr := h.add("edge/"+n.Node, ms, err)
		e := Edge{To: n.Node, RTTMs: med, Samples: samples, Failures: fails}
		// **只有全部失败才算不可达。** 一次抖动不该让一条边消失。
		if fails == samples {
			e.Error = lastErr
			e.RTTMs = 0
		}
		edges[i] = e
	})
	o.Edges = edges

	// 两类目标测法完全一样,只是失败的含义不同 —— 所以只多一个标记,
	// 不多一条链路上的列表(转述的线格式越简单越好)。
	uplink := map[string]bool{}
	targets := append([]string(nil), cfg.Targets...)
	for _, t := range cfg.UplinkTargets {
		uplink[t] = true
		if !contains(targets, t) {
			targets = append(targets, t)
		}
	}
	sort.Strings(targets)
	reaches := make([]Reach, len(targets))
	parallelProbe(len(targets), func(i int) {
		t := targets[i]
		ms, err := reachTarget(t, firstDNS(cfg.DNS), 8*time.Second)
		med, samples, fails, lastErr := h.add("target/"+t, ms, err)
		r := Reach{Target: t, FirstByteMs: med, Samples: samples, Failures: fails, Uplink: uplink[t]}
		if fails == samples {
			r.Error = lastErr
			r.FirstByteMs = 0
		}
		reaches[i] = r
	})
	o.Targets = reaches
	// 必须在 Edges/Targets 全部采完之后签。v3 同时绑定测量 payload；在
	// 采集前签会留下一个 relay 可改写、却看似有合法身份签名的缺口。
	// 签不了不是错误 —— 中控只有 ca.crt,没有自己的私钥。
	o.Attest, o.AttestExtended = signSelf(o, cfg.AttestationMinVersion)
	// This uses the same node TLS identity but an independent signature domain,
	// so adding counters does not mutate the deployed v5 canonical bytes.
	o.Traffic = collectTrafficAttestationFromDump(cfg, now, dump)
	// Public Hysteria2 single-hop metrics have their own signature domain.  They
	// cannot enter MeasurementsSHA256 (rolling compatibility) or WG traffic
	// counters (different semantics).
	o.LinkMetrics = collectLinkMetricAttestation(cfg, h, now)
	// Health must come from the real local collector, not from an outer relay's
	// HTTP status or from an incomplete subset of Observation fields. Include
	// the just-collected uplink measurements before deriving the final verdict.
	localStatus.Observation = o
	o.SelfCheck = collectSelfCheckAttestation(localStatus, now)
	return o, localStatus
}

// tcpRTT 用一次 TCP 建连测到邻居的往返时间。
//
// 不用 ICMP:那要 CAP_NET_RAW,而上报者只该有 CAP_NET_ADMIN(读 wg)。
// 建连时间比 ping 多一点点开销,但量的是**应用真正会走的那条路**。
func tcpRTT(addr string, timeout time.Duration) (int, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, err
	}
	ms := int(time.Since(start).Milliseconds())
	_ = c.Close()
	return ms, nil
}

// reachTarget 从本机**直接**访问目标,返回首字节时间。
//
// 不走任何代理:这里要量的就是"这台机器自己出去行不行"。节点上如果设了
// HTTP_PROXY,默认 Transport 会把请求交给它,量到的就成了那个代理的能力。
func reachTarget(url, dns string, timeout time.Duration) (int, error) {
	// **走 netx,不用系统解析器。** 这个函数量的是"这台机器够不够得到
	// 那个地址",而系统解析器坏掉时它会报"够不到" —— 长得像出网故障,
	// 实际只是解析故障,真实流量(sing-box 自带 DNS)一直好着。
	//
	// 实测:jm24 的 systemd-resolved 上游是 8.8.8.8(大陆被污染),
	// 上报者报 baidu 不可达,而换 223.5.5.5 解析后直连是 200/59ms。
	c := netx.Client(dns, timeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	start := time.Now()
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	ms := int(time.Since(start).Milliseconds())
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return ms, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// firstDNS 取第一个解析器。netx 只收一个 —— 备用解析器的价值在这里很小,
// 而"用哪个解析器测的"含糊掉之后,一个不一致的结果就无从解释了。
func firstDNS(dns []string) string {
	if len(dns) == 0 {
		return ""
	}
	return dns[0]
}

// 节点签名材料的约定位置(§13.3)。
const (
	nodeKeyPath  = "/etc/loom/tls/node.key"
	nodeCertPath = "/etc/loom/tls/node.crt"
)

// signSelf 给本节点拥有的运行态签名：身份、版本坐标、已应用快照、
// rollout 阶段、Agent 从 selector 实读的当前选择，以及本轮链路观测摘要。
//
// **签不了就返回 nil,不报错也不猜。** phase A 允许旧节点在证书补齐前继续
// 发兼容观测；phase B 的 table/HTTP/Agent 边界会把缺签名明确判为 not-ready，
// 因此这里不能用临时身份或中控密钥代签。
func signSelf(o *Observation, minVersion int) (*attest.Signed, *attest.Signed) {
	key, err := os.ReadFile(nodeKeyPath)
	if err != nil {
		return nil, nil
	}
	crt, err := os.ReadFile(nodeCertPath)
	if err != nil {
		return nil, nil
	}
	legacy, current := claimsForObservation(o, minVersion)
	legacySigned, err := attest.Sign(legacy, key, crt)
	if err != nil {
		return nil, nil
	}
	currentSigned, err := attest.Sign(current, key, crt)
	if err != nil {
		return nil, nil
	}
	// 没有新字段时 current 仍是同一份 v3 陈述，不重复携带证书和签名。
	if currentSigned.CanonicalVersion == 0 {
		return legacySigned, nil
	}
	return legacySigned, currentSigned
}

func claimsForObservation(o *Observation, minVersion int) (attest.Claim, attest.Claim) {
	c := attest.Claim{Node: o.Node, TS: o.TS, Applied: o.Applied}
	c.MeasurementsSHA256 = measurementDigest(o)
	if o.Version != nil {
		c.Commit, c.Dirty, c.Tag = o.Version.Commit, o.Version.Dirty, o.Version.Tag
		c.Binary, c.BinaryErr = o.Version.Binary, o.Version.BinaryErr
		c.Go, c.Platform = o.Version.Go, o.Version.Platform
	}
	if o.Rollout != nil {
		c.Rollout = &attest.RolloutClaim{
			Snapshot: o.Rollout.Snapshot, Stage: o.Rollout.Stage,
			EnteredAt: o.Rollout.EnteredAt, LastGood: o.Rollout.LastGood,
			Error: o.Rollout.Error,
		}
	}
	if o.Agent != nil {
		ac := &attest.AgentClaim{
			Node: o.Agent.Node, TS: o.Agent.TS,
			ComponentVersion: o.Agent.ComponentVersion,
		}
		for _, sel := range o.Agent.Selections {
			ac.Selections = append(ac.Selections, attest.SelectionClaim{
				Declaration: sel.Declaration, Selector: sel.Selector,
				Candidate: sel.Candidate, Chain: append([]string(nil), sel.Chain...),
				Reason: sel.Reason, UpdatedAt: sel.UpdatedAt,
				Health: candidateHealthClaim(sel.Health),
			})
		}
		c.Agent = ac
	}
	for _, component := range o.Components {
		c.Components = append(c.Components, attest.ComponentClaim{
			Name: component.Name, Expected: component.Expected,
			Actual: component.Actual, Error: component.Error,
		})
	}
	if minVersion >= 5 {
		c.CanonicalVersion = 5
	}
	legacy := c
	legacy.CanonicalVersion = 0
	legacy.Components = nil
	if c.Agent != nil {
		a := *c.Agent
		a.ComponentVersion = ""
		a.Selections = append([]attest.SelectionClaim(nil), c.Agent.Selections...)
		for i := range a.Selections {
			a.Selections[i].Health = nil
		}
		legacy.Agent = &a
	}
	return legacy, c
}
