package report

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/events"
)

// StatePath 是"现在有什么问题"的落脚点,与事件历史放在一起。
//
// **它和 events.jsonl 是两件不同的事,不要合并。**
//
//	events.jsonl   历史,只追加,只记变化 → 回答"多久了"
//	state.json     现状,每轮覆盖         → 回答"现在有什么问题"
//
// 原来面板两个问题都问事件历史,于是第一个答错了:事件按定义只有变化,
// 而 detector 重启时是**静默播种**的(否则每次重启都像全网同时变化一次)。
// 结果是**上报者启动那一刻就已经坏掉的任何东西,在它恢复之前面板永远看不见**。
//
// 实测:ber01 ↔ hz01 断了 9 小时,edge 事件做完之后仍然上不了面板 ——
// 因为播种时它就是坏的,没有"变化"。这跟当初"四台机器 wg-quick 全 failed、
// 存在多久没人知道"是同一个形状的盲区,只是换了一层。
const StatePath = "/var/lib/loom/state.json"

// Tracked 是一个受跟踪状态的当前值,以及**已知从什么时候起是这个值**。
type Tracked struct {
	State string `json:"state"`
	// Since 是这个值的已知起点。
	Since string `json:"since"`
	// Exact 为真表示 Since 来自一次真实的状态变化;为假表示它只是下界 ——
	// 上报者开始跟踪它的时候就已经是这个值了,更早的事无从得知。
	Exact  bool   `json:"exact,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// TrackedState 是 detector 这一轮看到的全部受跟踪状态。
//
// **它跨重启存活,而且必须跨重启存活。** 时长是这个面板唯一真正新增的
// 信息("链路断了"看节点表也知道,"断了两天了"才让人动手),而上报者重启
// 是常事 —— 今天就为了发版重启了两次。每次重启把所有时长清零的话,
// 面板在最该说话的时候恰好失忆。
type TrackedState struct {
	TS     string             `json:"ts"`
	States map[string]Tracked `json:"states"`
}

// Unresolved 是面板上的一行。
type Unresolved struct {
	Node, Kind, Subject string
	State, Detail       string
	Level               string
	Lasted              string
	// AtLeast 为真时,Lasted 只是下界:这个问题在上报者开始记之前就存在。
	AtLeast bool
}

// UnresolvedNow 算出**现在**有哪些未解决的问题,各持续了多久。
//
// 问题清单来自当前状态,时长来自状态自己记的起点(必要时再查事件历史)——
// 两个问题各问各的来源。这是这个函数存在的全部理由。
func UnresolvedNow(st *TrackedState, evs []events.Event, now time.Time) []Unresolved {
	if st == nil {
		return nil
	}
	keys := make([]string, 0, len(st.States))
	for k := range st.States {
		keys = append(keys, k)
	}
	// 排序之后再遍历:map 顺序不定,否则面板每次刷新行序都在跳。
	sort.Strings(keys)

	var out []Unresolved
	for _, k := range keys {
		t := st.States[k]
		node, kind, subject := splitKey(k)
		probe := events.Event{Kind: kind, To: t.State}
		lvl := probe.Level()
		if lvl != events.LevelProblem && lvl != events.LevelPending {
			continue
		}
		u := Unresolved{
			Node: node, Kind: kind, Subject: subject,
			State: t.State, Detail: t.Detail, Level: string(lvl),
		}
		since, ok := parseTS(t.Since)
		exact := t.Exact
		// 事件历史可能比状态记得更早、更准 —— 状态是被覆盖的,事件是追加的。
		// 两者取更早的那个,并且只有真实变化才算精确。
		if at, found := enteredAt(evs, k, t.State); found && (!ok || at.Before(since)) {
			since, ok, exact = at, true, true
		}
		switch {
		case !ok:
			u.Lasted, u.AtLeast = "时长未知", true
		default:
			u.Lasted, u.AtLeast = events.Human(now.Sub(since)), !exact
		}
		out = append(out, u)
	}
	return out
}

// enteredAt 找这个 Key 最近一次进入 state 是什么时候。
//
// evs 是倒序的(最新在前),所以第一条匹配的就是最近一次。
func enteredAt(evs []events.Event, key, state string) (time.Time, bool) {
	for i := range evs {
		if evs[i].Key() != key || evs[i].To != state {
			continue
		}
		if t, ok := parseTS(evs[i].TS); ok {
			return t, true
		}
		return time.Time{}, false
	}
	return time.Time{}, false
}

func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// WriteTrackedState 覆盖式写当前状态。
//
// 先写临时文件再改名:`loom status` 可能正好在读,而半截 JSON 会让它报一个
// 跟真实原因无关的解析错误。
func WriteTrackedState(path string, st *TrackedState) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadTrackedState 读当前状态。文件不存在返回 (nil, nil) ——
// 这台机器不是中控,或者上报者还没跑过一轮,都不是错误。
//
// 坏文件也返回 (nil, nil) 而不是错误:它是每轮覆盖的缓存,不是事实来源。
// 为一份读不懂的缓存让整个面板罢工,是在最需要它的时候把它关掉。
func LoadTrackedState(path string) (*TrackedState, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st TrackedState
	if json.Unmarshal(b, &st) != nil || st.States == nil {
		return nil, nil
	}
	return &st, nil
}
