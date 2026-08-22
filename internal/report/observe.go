package report

import (
	"fmt"
	"net"
	"net/http"
	"sort"
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
	Node    string  `json:"node"`
	TS      string  `json:"ts"`
	Edges   []Edge  `json:"edges,omitempty"`
	Targets []Reach `json:"targets,omitempty"`
}

// Edge 是本节点到另一个节点的往返时间。
type Edge struct {
	To    string `json:"to"`
	RTTMs int    `json:"rtt_ms,omitempty"`
	Error string `json:"error,omitempty"`
}

// Reach 是本节点**直接**访问某个目标地址的结果。
//
// 它回答的是"这台机器出去能不能到那儿",与任何链路无关 —— 正因为无关,
// 它才能被所有接入节点复用。
type Reach struct {
	Target      string `json:"target"`
	FirstByteMs int    `json:"first_byte_ms,omitempty"`
	Error       string `json:"error,omitempty"`
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

// observe 量一遍本节点能量的东西:到每个邻居的 RTT、到每个目标的可达性。
func observe(cfg *Config, now time.Time) *Observation {
	o := &Observation{Node: cfg.Node, TS: now.UTC().Format(time.RFC3339)}

	nb := append([]Neighbor(nil), cfg.Neighbors...)
	sort.Slice(nb, func(i, j int) bool { return nb[i].Node < nb[j].Node })
	for _, n := range nb {
		e := Edge{To: n.Node}
		if ms, err := tcpRTT(n.Addr, 5*time.Second); err != nil {
			e.Error = err.Error()
		} else {
			e.RTTMs = ms
		}
		o.Edges = append(o.Edges, e)
	}

	targets := append([]string(nil), cfg.Targets...)
	sort.Strings(targets)
	for _, t := range targets {
		r := Reach{Target: t}
		if ms, err := reachTarget(t, 8*time.Second); err != nil {
			r.Error = err.Error()
		} else {
			r.FirstByteMs = ms
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
