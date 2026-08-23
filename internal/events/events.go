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

// Bad 报告这个状态是不是"有问题"。用来在界面上区分"出事了"和"恢复了"。
func (e *Event) Bad() bool { return !okState(e.To) }

// Recovered 报告这是不是一次恢复。
func (e *Event) Recovered() bool { return okState(e.To) && !okState(e.From) }

func okState(s string) bool {
	switch s {
	case "ok", "active", "clean", "reachable", "":
		return true
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
// 没有下一条表示还在持续中,返回到 now 为止的时长和 ongoing=true。
// **"还在持续"和"持续了 X 之后恢复了"必须分得开** —— 前者需要人现在就管。
func Duration(evs []Event, i int, now time.Time) (time.Duration, bool) {
	// evs 是倒序的(最新在前),所以"下一条"在索引更小的方向。
	cur, err := time.Parse(time.RFC3339, evs[i].TS)
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
		return next.Sub(cur), false
	}
	return now.Sub(cur), true
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
