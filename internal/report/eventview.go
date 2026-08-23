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
func recentEvents(path string, now time.Time, limit int) []webui.EventView {
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
		d, ongoing := events.Duration(evs, i, now)
		out = append(out, webui.EventView{
			TS: e.TS, Node: e.Node, Kind: e.Kind, Subject: e.Subject,
			From: e.From, To: e.To, Detail: e.Detail,
			Bad: e.Bad(), Recovered: e.Recovered(),
			Lasted: events.Human(d), Ongoing: ongoing,
		})
	}
	return out
}
