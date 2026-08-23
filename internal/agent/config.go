// Package agent 是跑在接入节点上的调参回路:按 tuning_period 探测每条候选、
// 按 objective 排序、带阻尼地切 selector(§5.5)。
//
// 它是 SSOT 里那组调参字段的**唯一消费者**。在它出现之前,
// switch_threshold / window / min_samples / stale_after 四个字段没有任何
// 代码读取,objective 与 tuning_period 也只被校验器检查拼写 —— SSOT 描述了
// 一个不存在的控制环。
//
// **节点上不放 SSOT。** Agent 读的是渲染出来的 agent/config.json,它由
// SSOT 纯函数导出(§12),内容只够跑这个回路:探测哪些候选、打哪个目标、
// 多久一轮、什么时候允许切。
package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"loom/internal/model"
)

// Config 是 Agent 在节点上读到的全部输入。
type Config struct {
	Node string `json:"node"`

	// API 是 sing-box 的控制端点(§7.3.1)。selector 的当前选择由它设置。
	API       string `json:"api"`
	APISecret string `json:"api_secret"`

	// Probe 是探测入口(§7.3.3):一个回环端口,用户名区分候选。
	Probe       string `json:"probe"`
	ProbeSecret string `json:"probe_secret"`

	Declarations []Decl `json:"declarations"`

	// Peers 是本节点能顺着隧道直接够到的上报接口(§16.1)。
	//
	// 覆盖面取决于拓扑:接入节点只和一部分服务器有隧道,而 AllowedIPs 是
	// /32,拉不到隧道那头以外的地址。好在**握手年龄是对称的** —— 一条隧道
	// 的健康状况在两端看到的是同一件事,所以只要每条隧道至少有一端在能拉到
	// 的节点上,隧道健康就是全覆盖的。配置自检不对称,拉不到的节点只能靠
	// 它自己的 journal。
	Peers []Peer `json:"peers,omitempty"`

	// SelfReport 是本机上报者的地址。问它一家就够 —— 它已经把邻居转述的
	// 观测都收进来了,不必 Agent 自己再跑一遍转述。
	SelfReport string `json:"self_report,omitempty"`

	// PeerPeriod 是拉取上报的间隔。
	PeerPeriod string `json:"peer_period,omitempty"`
}

// Peer 是一个能拉到的节点。
type Peer struct {
	Node string `json:"node"`
	Addr string `json:"addr"`
}

// Decl 是一条访问声明在 Agent 视角下的样子。
type Decl struct {
	ID string `json:"id"`
	// Selector 是这条声明在 sing-box 里的 selector tag。
	Selector string `json:"selector"`

	Objective model.Objective `json:"objective"`

	// Targets 是要探测的目标。**每条候选对每个目标各测一遍。**
	//
	// 服务的目标就是它自己的地址(§4.5)—— 不再需要"代表性目标"这种东西,
	// 因为真实目标本身就是被测对象。钉死出口的声明仍然用一个代表性目标,
	// 因为那时候目标确实是未知的。
	//
	// 多目标不需要特殊的合并逻辑:失败会进失败率,而排序键本来就是
	// (失败率分档, 目标指标)。某个目标全网都挂时,所有候选同等受罚,
	// 相对次序不变 —— 这正是想要的。
	Targets []string `json:"targets"`

	// 以下四个字段定义调参回路的节奏与阻尼(§5.5)。
	TuningPeriod    string  `json:"tuning_period"`
	SwitchThreshold float64 `json:"switch_threshold"`
	Window          string  `json:"window"`
	MinSamples      int     `json:"min_samples"`
	StaleAfter      string  `json:"stale_after"`

	Candidates []Cand `json:"candidates"`
}

// Cand 是一条候选:tag 用于上报与切换,ProbeUser 用于把探测流量打到它上面。
type Cand struct {
	Tag string `json:"tag"`
	// ProbeUser 是探测入口的用户名。**不是候选 tag** —— tag 含冒号,
	// SOCKS5 客户端会在第一个冒号处切分 user:pass(§7.3.3)。
	ProbeUser string `json:"probe_user"`
}

// Supported 报告 Agent 能否为这个 objective 排序。
//
// **不能的必须显式报出,不许静默降级。** ttft 需要 L7 观测点、throughput
// 需要批量传输探测、cost 需要价格源(§16.2、§5.2);拿 L4 首字节时间冒充
// 这三个中的任何一个,产出的排序看着完全正常,却在优化另一件事。
func Supported(o model.Objective) (bool, string) {
	switch o {
	case model.Latency, model.Stability:
		return true, ""
	case model.TTFT:
		return false, "ttft 只能由 L7 观测点产出(§16.2),Agent 现在只有 L4 首字节时间"
	case model.Throughput:
		return false, "throughput 需要批量传输探测,Agent 现在只测首字节"
	case model.Cost:
		return false, "cost 需要价格数据源(§5.2),Agent 拿不到"
	}
	return false, fmt.Sprintf("未知 objective:%q", o)
}

// Load 解析节点上的 agent/config.json,并把明显不可执行的输入挡在启动阶段。
func Load(b []byte) (*Config, error) {
	var c Config
	dec := json.NewDecoder(newTrimReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("解析 agent 配置:%w", err)
	}
	if c.Node == "" {
		return nil, fmt.Errorf("agent 配置缺少 node")
	}
	for i := range c.Declarations {
		d := &c.Declarations[i]
		if ok, why := Supported(d.Objective); !ok {
			return nil, fmt.Errorf("声明 %s 的 objective=%s 无法执行:%s", d.ID, d.Objective, why)
		}
		if _, err := d.Period(); err != nil {
			return nil, fmt.Errorf("声明 %s 的 tuning_period:%w", d.ID, err)
		}
		if _, err := d.Win(); err != nil {
			return nil, fmt.Errorf("声明 %s 的 window:%w", d.ID, err)
		}
		if _, err := d.Stale(); err != nil {
			return nil, fmt.Errorf("声明 %s 的 stale_after:%w", d.ID, err)
		}
		if len(d.Candidates) == 0 {
			return nil, fmt.Errorf("%s 没有候选 —— 无从探测,也无从选择", d.ID)
		}
		if len(d.Targets) == 0 {
			return nil, fmt.Errorf("%s 没有探测目标 —— 排序无从谈起", d.ID)
		}
	}
	if c.PeerPeriod != "" {
		if _, err := dur(c.PeerPeriod, "peer_period"); err != nil {
			return nil, err
		}
	}
	// 秘密占位符没被替换就跑起来,表现是"认证一直失败",排障要绕很久。
	// 宁可启动就说清楚(与 sing-box 拿到非法密码即拒绝启动同理)。
	for _, p := range []struct{ name, v string }{
		{"api_secret", c.APISecret}, {"probe_secret", c.ProbeSecret},
	} {
		if len(p.v) > 2 && p.v[0] == '$' && p.v[1] == '{' {
			return nil, fmt.Errorf("%s 仍是未替换的占位符 %s —— 先跑 loom hydrate", p.name, p.v)
		}
	}
	return &c, nil
}

func (d *Decl) Period() (time.Duration, error) { return dur(d.TuningPeriod, "tuning_period") }
func (d *Decl) Win() (time.Duration, error)    { return dur(d.Window, "window") }
func (d *Decl) Stale() (time.Duration, error)  { return dur(d.StaleAfter, "stale_after") }

func dur(s, name string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("%s 为空", name)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if v <= 0 {
		return 0, fmt.Errorf("%s=%s 必须为正", name, s)
	}
	return v, nil
}
