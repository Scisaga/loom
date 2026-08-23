// Package measure 是 L2 的度量采集。
//
// §16 说度量是 Loom 的核心能力,不是配套设施 —— §5 的整套调度建立在它之上。
// 没有真实质量数据就写调度引擎,权重只能靠猜,而且**无法验证阻尼参数是否
// 合适**:振荡是否发生,只有靠数据才看得出来(§20.5)。
package measure

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// ObservationPoint 决定哪些字段有值(§16.2)。
//
// **不同观测点的数据不可直接比较。** 拿 L4 的近似值和 L7 的真值一起排序会
// 得出错误结论,所以每条记录都必须带上它是从哪儿看到的。
type ObservationPoint string

const (
	// L4Tunnel 只能给出连接级指标:建连耗时、首字节返回时间、字节数。
	// 拿不到 tokens/s 与响应结构。
	L4Tunnel ObservationPoint = "l4_tunnel"
	// L7Gateway / SDK / Endpoint 才能产出应用层指标。
	L7Gateway ObservationPoint = "l7_gateway"
	SDKPoint  ObservationPoint = "sdk"
	Endpoint  ObservationPoint = "endpoint"
)

// Kind 区分被动观测与主动探测(§16.2)。
type Kind string

const (
	// Passive 来自真实流量:零额外成本、零额外暴露,且比合成探测更准确。
	Passive Kind = "passive"
	// Active 是主动探测。**计入探测预算** —— 在推理场景下它花的是真金白银。
	Active Kind = "active"
	// Derived 是从**别的节点的观测**推出来的结论,本机没有真的发请求。
	//
	// 例:cn-a 自己量到"打不到 api.ipify.org",于是所有出口在 cn-a 的候选
	// 都不必再探(§16.1.2)。这比本机去探更省、也更早,但它是**推论**,
	// 必须与亲自测到的结果分开标记 —— 否则回放历史时分不清哪些数字是真的。
	Derived Kind = "derived"
)

// Measurement 是一条度量记录(§19)。
//
// 按**完整路径**归因,不按地址或服务器单独归因:经广州到某地址的质量,
// 推不出经北京到同一地址的质量(§5.6)。
type Measurement struct {
	TS          string `json:"ts"` // RFC3339,由调用方注入
	Node        string `json:"node"`
	CandidateID string `json:"candidate_id"`
	Declaration string `json:"declaration_id"`
	// Target 是这次测的目标地址。
	//
	// **一条候选对不同目标的表现可以天差地别** —— 实测同一条候选到 baidu
	// 0.058s、到 Cloudflare 完全不通(D43)。不记目标的话,聚合出来的数字
	// 是几个互不相干的量混在一起,而且回放时无从拆分。
	Target string `json:"target,omitempty"`

	// L4 观测点能拿到的(§16.2)。
	FirstByteMs int `json:"first_byte_ms,omitempty"`

	// 探测失败本身就是数据 —— 一条连不上的候选和一条慢的候选,
	// 对调度是完全不同的信号。
	Error string `json:"error,omitempty"`

	Point ObservationPoint `json:"observation_point"`
	Kind  Kind             `json:"observation_kind"`
}

// OK 报告这次探测是否成功。
func (m *Measurement) OK() bool { return m.Error == "" }

// Append 把记录追加进 JSONL。
//
// 追加而非覆盖,是因为 §16.5 要求度量数据可回放:阻尼参数无法在线调优
// (你不能拿生产流量试"阈值 20% 与 15% 哪个更好"),只能拿历史序列离线重跑。
// 那要求原始数据长期留存,不能被聚合掉。
func Append(path string, ms []Measurement) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range ms {
		if err := enc.Encode(&ms[i]); err != nil {
			return err
		}
	}
	return nil
}

// Load 读回全部记录,供回测与排序使用。
func Load(path string) ([]Measurement, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Measurement
	dec := json.NewDecoder(f)
	for {
		var m Measurement
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Summary 是一条候选在某个窗口内的聚合结果。
type Summary struct {
	CandidateID string
	Declaration string
	Samples     int
	Failures    int
	P50         int
	P95         int
}

// Summarize 按候选聚合,只统计成功样本的分位数,失败单独计数。
//
// **失败不能被当成"很慢"混进分位数。** 一条 100% 超时的候选如果被记成
// "延迟很高",排序时它仍会排在某些候选之前;记成失败才能被过滤掉。
func Summarize(ms []Measurement) []Summary {
	type acc struct {
		decl string
		ok   []int
		fail int
	}
	byCand := map[string]*acc{}
	for i := range ms {
		m := &ms[i]
		a := byCand[m.CandidateID]
		if a == nil {
			a = &acc{decl: m.Declaration}
			byCand[m.CandidateID] = a
		}
		if m.OK() {
			a.ok = append(a.ok, m.FirstByteMs)
		} else {
			a.fail++
		}
	}

	out := make([]Summary, 0, len(byCand))
	for id, a := range byCand {
		s := Summary{CandidateID: id, Declaration: a.decl,
			Samples: len(a.ok) + a.fail, Failures: a.fail}
		if len(a.ok) > 0 {
			sort.Ints(a.ok)
			s.P50 = percentile(a.ok, 50)
			s.P95 = percentile(a.ok, 95)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Declaration != out[j].Declaration {
			return out[i].Declaration < out[j].Declaration
		}
		// 有成功样本的排前面;都有则按 p50。
		iu, ju := out[i].Samples > out[i].Failures, out[j].Samples > out[j].Failures
		if iu != ju {
			return iu
		}
		if out[i].P50 != out[j].P50 {
			return out[i].P50 < out[j].P50
		}
		return out[i].CandidateID < out[j].CandidateID
	})
	return out
}

// percentile 取排序后切片的第 p 分位,**索引向上取整**。
//
// 向上取整是有意的:三个样本谈不上 p95,取最大值比取中间那个诚实 ——
// 向下取整会让 p95 在小样本下等于 p50,看起来像"很稳定",而实际上只是
// 样本不够。宁可偏保守。
func percentile(sorted []int, p int) int {
	if len(sorted) == 0 {
		return 0
	}
	num := (len(sorted) - 1) * p
	i := num / 100
	if num%100 != 0 {
		i++ // 向上取整
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// FormatSummary 渲染成人可读的表。
func FormatSummary(ss []Summary) string {
	var b strings.Builder
	decl := ""
	for _, s := range ss {
		if s.Declaration != decl {
			decl = s.Declaration
			fmt.Fprintf(&b, "\n%s\n", decl)
		}
		status := fmt.Sprintf("p50 %4dms  p95 %4dms", s.P50, s.P95)
		if s.Failures == s.Samples {
			status = "全部失败"
		} else if s.Failures > 0 {
			status += fmt.Sprintf("  (%d/%d 失败)", s.Failures, s.Samples)
		}
		fmt.Fprintf(&b, "  %-42s %s\n", s.CandidateID, status)
	}
	return b.String()
}
