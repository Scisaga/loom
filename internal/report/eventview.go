package report

import (
	"time"

	"loom/internal/events"
	"loom/internal/webui"
)

// EventsPath 是中控记事件的地方。
const EventsPath = "/var/lib/loom/events.jsonl"

// recentEvents 读最近的事件给界面用。
//
// 每条都带上"这个状态持续了多久" —— 只说"09:00 隧道断了"没什么用,
// **"断了 20 分钟后恢复"和"断了 20 分钟还没好"是完全不同的两件事**,
// 而后者需要人现在就管。
func recentEvents(path string, now time.Time, limit int, cur func(string) string) []webui.EventView {
	evs, err := events.Load(path)
	if err != nil {
		return []webui.EventView{{Detail: "读事件日志失败:" + err.Error(), Bad: true}}
	}
	var out []webui.EventView
	for i := range evs {
		if len(out) >= limit {
			break
		}
		e := &evs[i]
		d, ongoing := events.Duration(evs, i, now, cur(e.Key()))
		out = append(out, webui.EventView{
			TS: e.TS, Node: e.Node, Kind: e.Kind, Subject: e.Subject,
			From: e.From, To: e.To, Detail: e.Detail,
			Bad: e.Bad(), Recovered: e.Recovered(), Level: string(e.Level()),
			Lasted: events.Human(d), Ongoing: ongoing,
		})
	}
	return out
}

// unresolvedNow 给界面用的"现在有什么问题"。
//
// 它**不是**从事件历史里筛出来的。事件按定义只有变化,而上报者重启是静默
// 播种的 —— 播种那一刻已经坏掉的东西不会产生任何事件,于是旧版面板对它
// 完全瞎。清单从当前状态来,时长才查事件历史(见 tracked.go)。
func unresolvedNow(path string, now time.Time, st *TrackedState) []webui.UnresolvedView {
	evs, err := events.Load(path)
	if err != nil {
		return []webui.UnresolvedView{{
			Kind: "事件历史", Detail: "读不到,时长只能给下界:" + err.Error(),
			Level: string(events.LevelProblem), Lasted: "时长未知", AtLeast: true,
		}}
	}
	var out []webui.UnresolvedView
	for _, u := range UnresolvedNow(st, evs, now) {
		out = append(out, webui.UnresolvedView{
			Node: u.Node, Kind: u.Kind, Subject: u.Subject,
			State: u.State, Detail: u.Detail,
			Level: u.Level, Lasted: u.Lasted, AtLeast: u.AtLeast,
		})
	}
	return out
}
