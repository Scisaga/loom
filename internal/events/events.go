// Package events 记录**状态变化**,不记录状态。
//
// 上报者每分钟采一次全网,但"每分钟一条 cn-a 正常"没有任何价值 —— 那只是
// 另一份没人看的日志。有价值的是**变化**:什么时候坏的、什么时候好的、
// 坏了多久。
//
// 这三个问题现在答不出来:转述表每个观测者只留最新一份,旧的被覆盖。
// 之前四台机器的 wg 单元坏了多久,查不到,因为从来没记过。
package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Event 是一次状态变化。
type Event struct {
	TS string `json:"ts"` // RFC3339,由调用方注入

	// Node 是这件事发生在谁身上。
	Node string `json:"node"`
	// Kind 是变化的类别:tunnel / drift / snapshot / reach / route。
	Kind string `json:"kind"`
	// Subject 是具体对象:接口名、文件路径、服务 id……
	Subject string `json:"subject,omitempty"`

	// From / To 是变化的两端。**两个都要有** —— 只记 To 的话,
	// "从坏变好"和"一直是好的"在日志里长得一样。
	From string `json:"from"`
	To   string `json:"to"`

	Detail string `json:"detail,omitempty"`
}

// Key 是这条事件跟踪的那个状态的身份。同一个 Key 的连续两次观测不同,
// 才产生事件。
func (e *Event) Key() string { return e.Node + "|" + e.Kind + "|" + e.Subject }

// Level 是一条事件的性质。
//
// **不是所有变化都是问题。** 快照号变了、选路切换了,都是系统正常工作的
// 表现 —— 把它们混进"待处理"里,真的问题就被淹没了。实测踩过:面板上
// 列了 7 条"还在持续的问题",7 条全是快照号和选路结果,而这正是我建这个
// 面板要防的那种"狼来了"。
type Level string

const (
	// LevelInfo 是正常运转的记录:发布了新快照、Agent 换了条路。
	LevelInfo Level = "info"
	// LevelProblem 需要人看一眼。
	LevelProblem Level = "problem"
	// LevelOK 是从问题状态恢复。
	LevelOK Level = "ok"
	// LevelPending 是过渡态 —— 现在正常,但它不该一直是这样(如凭据轮换
	// 的两代并存窗口)。开太久就是忘了收尾。
	LevelPending Level = "pending"
)

// Level 由**类别**决定,不靠猜 To 的字符串。
//
// 靠猜的版本把任何不在白名单里的值都当成问题,于是每个快照号都成了故障。
func (e *Event) Level() Level {
	switch e.Kind {
	case "snapshot", "route":
		return LevelInfo
	case "target":
		// **target 是数据,不是告警。** 它回答"这台机器够不够得到那个目标",
		// 而 Agent 拿它剪枝 —— 国内机器够不到 Cloudflare 正是要的答案,
		// 不是故障。需要人管的那种够不到走 uplink(见 model.Node.ProbeTargets)。
		return LevelInfo
	case "rotation":
		return LevelPending
	}
	if problemState(e.Kind, e.To) {
		return LevelProblem
	}
	if problemState(e.Kind, e.From) {
		return LevelOK
	}
	return LevelInfo
}

// Bad 报告这条事件是不是把系统带进了需要人看的状态。
func (e *Event) Bad() bool { return e.Level() == LevelProblem }

// Recovered 报告这是不是一次恢复。
func (e *Event) Recovered() bool { return e.Level() == LevelOK }

// problemState 说某个类别的某个取值算不算有问题。
func problemState(kind, state string) bool {
	switch kind {
	case "tunnel":
		return state != "active"
	case "drift":
		return state != "clean"
	case "uplink":
		// "这台机器本该够得到却够不到" —— 直连坏了,需要人管。
		return state != "ok"
	case "reach":
		return state != "reachable"
	case "edge":
		return state != "ok"
	}
	return false
}

// Append 追加事件。
func Append(path string, evs []Event) error {
	if len(evs) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range evs {
		if err := enc.Encode(&evs[i]); err != nil {
			return err
		}
	}
	return nil
}

// Load 读全部事件,最新的在前。
func Load(path string) ([]Event, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // 坏行跳过,不让一行毁掉整个历史
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS > out[j].TS })
	return out, nil
}

// Compact 丢弃超过 retention 的事件。追加日志不压实会无限长大。
func Compact(path string, now time.Time, retention time.Duration) error {
	evs, err := Load(path)
	if err != nil || len(evs) == 0 {
		return err
	}
	cut := now.Add(-retention).Format(time.RFC3339)
	kept := evs[:0]
	for i := range evs {
		if evs[i].TS >= cut {
			kept = append(kept, evs[i])
		}
	}
	if len(kept) == len(evs) {
		return nil
	}
	// 写回时恢复时间顺序 —— 文件本身是追加日志,倒序存会让人困惑。
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].TS < kept[j].TS })
	tmp := path + ".compact"
	_ = os.Remove(tmp)
	if err := Append(tmp, kept); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Duration 算某个状态持续了多久:从这条事件到同 Key 的下一条。
//
// **"没有下一条"不等于"还在持续"。** 上报者重启时是静默播种的(否则每次
// 重启都像全网同时变化),所以日志的最后一条可能早就不是当前状态了。
// 实测踩过:一条 2.4 小时前的快照事件被显示成"还在持续",而那台机器
// 早就换了两个版本。
//
// 所以 ongoing 要**和当前状态核对**:调用方给出 cur(该 Key 现在是什么),
// 只有对得上才算还在持续。cur 为空表示不知道,那时退回旧行为。
func Duration(evs []Event, i int, now time.Time, cur string) (time.Duration, bool) {
	// evs 是倒序的(最新在前),所以"下一条"在索引更小的方向。
	t, err := time.Parse(time.RFC3339, evs[i].TS)
	if err != nil {
		return 0, false
	}
	for j := i - 1; j >= 0; j-- {
		if evs[j].Key() != evs[i].Key() {
			continue
		}
		next, err := time.Parse(time.RFC3339, evs[j].TS)
		if err != nil {
			return 0, false
		}
		return next.Sub(t), false
	}
	if cur != "" && cur != evs[i].To {
		// 日志里没有后续,但当前状态已经不是它了 —— 中间的变化发生在
		// 上报者重启的播种期,没被记下来。不能当成"还在持续"。
		return now.Sub(t), false
	}
	return now.Sub(t), true
}

// Human 把时长写成人能读的。
func Human(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1f 小时", d.Hours())
	}
	return fmt.Sprintf("%.1f 天", d.Hours()/24)
}

// openAppend 给测试用。
func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}
