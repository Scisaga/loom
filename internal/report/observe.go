package report

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
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
	Applied string  `json:"applied,omitempty"`
	Edges   []Edge  `json:"edges,omitempty"`
	Targets []Reach `json:"targets,omitempty"`
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
	return now.Sub(t)
}

// history 保留每个被测对象最近若干次的结果。
//
// 中位数需要历史,而上报者本来是无状态的 —— 这是它唯一持有的状态,
// 而且只在内存里:重启之后重新攒,几分钟就回来了。
type history struct {
	mu sync.Mutex
	by map[string][]sample
}

type sample struct {
	ms  int
	err string
}

// keep 是保留多少次。1 分钟一轮,5 次约等于 5 分钟的窗口;
// 中位数因此能顶住两次离群。
const keep = 5

func newHistory() *history { return &history{by: map[string][]sample{}} }

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
func observe(cfg *Config, h *history, now time.Time) *Observation {
	o := &Observation{Node: cfg.Node, TS: now.UTC().Format(time.RFC3339)}
	if b, err := os.ReadFile(appliedPath); err == nil {
		o.Applied = strings.TrimSpace(string(b))
	}

	nb := append([]Neighbor(nil), cfg.Neighbors...)
	sort.Slice(nb, func(i, j int) bool { return nb[i].Node < nb[j].Node })
	for _, n := range nb {
		ms, err := tcpRTT(n.Addr, 5*time.Second)
		med, samples, fails, lastErr := h.add("edge/"+n.Node, ms, err)
		e := Edge{To: n.Node, RTTMs: med, Samples: samples, Failures: fails}
		// **只有全部失败才算不可达。** 一次抖动不该让一条边消失。
		if fails == samples {
			e.Error = lastErr
			e.RTTMs = 0
		}
		o.Edges = append(o.Edges, e)
	}

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
	for _, t := range targets {
		ms, err := reachTarget(t, 8*time.Second)
		med, samples, fails, lastErr := h.add("target/"+t, ms, err)
		r := Reach{Target: t, FirstByteMs: med, Samples: samples, Failures: fails, Uplink: uplink[t]}
		if fails == samples {
			r.Error = lastErr
			r.FirstByteMs = 0
		}
		o.Targets = append(o.Targets, r)
	}
	return o
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
func reachTarget(url string, timeout time.Duration) (int, error) {
	c := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
			TLSHandshakeTimeout: timeout},
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
