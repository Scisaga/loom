package report

import (
	"fmt"
	"sort"
	"time"

	"loom/internal/events"
	"loom/internal/webui"
)

// detector 把每轮的全网快照变成**状态变化**。
//
// 它只在中控上跑。每个节点都有同样的视图(靠转述),所以理论上谁都能记 ——
// 但记 N 份同样的事件只会让人不知道该看哪一份。中控是人会去看的地方。
//
// 代价写在这儿:**中控停了就不记事件**。转述仍然在传,只是没人写下来。
type detector struct {
	path      string
	retention time.Duration
	// prev 是上一轮每个受跟踪状态的值。**没有它就只能记录"现在是什么",
	// 而那正是已经有的东西。**
	prev map[string]string
	// seeded 为假时,第一轮只播种不产生事件 —— 否则每次重启都会看起来
	// 像全网同时变化了一次。
	seeded bool
}

func newDetector(path string, retention time.Duration) *detector {
	return &detector{path: path, retention: retention, prev: map[string]string{}}
}

// observe 比较这一轮和上一轮,把差异写进事件日志。
func (d *detector) observe(v webui.View, now time.Time) ([]events.Event, error) {
	cur := map[string]events.Event{}
	add := func(node, kind, subject, state, detail string) {
		e := events.Event{
			TS:   now.UTC().Format(time.RFC3339),
			Node: node, Kind: kind, Subject: subject, To: state, Detail: detail,
		}
		cur[e.Key()] = e
	}

	for _, n := range v.Nodes {
		// 听不听得到。转述断了、机器没了,都表现为这个。
		reach := "reachable"
		if !n.Reached && n.AgeSec > 300 {
			reach = "silent"
		}
		add(n.ID, "reach", "", reach, "")

		add(n.ID, "snapshot", "", nonEmpty(n.Applied, "未记录"), "")

		for _, t := range n.Tunnels {
			state := "active"
			switch {
			case t.State == "down":
				state = "down"
			case t.State == "未握手":
				state = "never"
			case t.State != "" && t.State != "active":
				// 单元不是 active:隧道现在可能还通,但重启就不回来了。
				state = t.State
			case !t.OK:
				state = "stale"
			}
			add(n.ID, "tunnel", t.Interface, state, fmt.Sprintf("握手 %d 秒前", t.AgeSec))
		}

		// 漂移:把"有几处"当状态,而不是逐个文件 —— 逐个文件会让一次
		// 批量变更刷出一屏事件。
		drift := "clean"
		if len(n.Problems) > 0 {
			drift = fmt.Sprintf("%d 处", len(n.Problems))
		}
		add(n.ID, "drift", "", drift, joinFirst(n.Problems, 3))

		// 轮换窗口:开着是过渡态,开太久就是忘了收尾。
		for _, c := range n.Rotating {
			add(n.ID, "rotation", c, "两代并存", "过渡窗口开着 —— 全网取到之后要把 accept_previous 改回 false")
		}

		for _, r := range n.Targets {
			state := "ok"
			if r.Err != "" {
				state = "unreachable"
			}
			add(n.ID, "target", r.Target, state, r.Err)
		}
	}

	// 第一轮只播种。重启不该看起来像全网同时变化了一次。
	if !d.seeded {
		for k, e := range cur {
			d.prev[k] = e.To
		}
		d.seeded = true
		return nil, nil
	}

	var out []events.Event
	keys := make([]string, 0, len(cur))
	for k := range cur {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := cur[k]
		old, had := d.prev[k]
		if had && old == e.To {
			continue
		}
		e.From = old
		if !had {
			e.From = "(新)"
		}
		out = append(out, e)
		d.prev[k] = e.To
	}
	// 消失的东西也是变化:一个节点不再出现在视图里。
	for k, old := range d.prev {
		if _, still := cur[k]; still {
			continue
		}
		node, kind, subject := splitKey(k)
		out = append(out, events.Event{
			TS: now.UTC().Format(time.RFC3339), Node: node, Kind: kind,
			Subject: subject, From: old, To: "消失", Detail: "不再出现在全网视图里",
		})
		delete(d.prev, k)
	}

	if err := events.Append(d.path, out); err != nil {
		return out, err
	}
	return out, events.Compact(d.path, now, d.retention)
}

func nonEmpty(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

func joinFirst(xs []string, n int) string {
	if len(xs) == 0 {
		return ""
	}
	if len(xs) > n {
		return fmt.Sprintf("%s(等 %d 处)", xs[0], len(xs))
	}
	out := xs[0]
	for _, x := range xs[1:] {
		out += ";" + x
	}
	return out
}

func splitKey(k string) (node, kind, subject string) {
	parts := [3]string{}
	i, start := 0, 0
	for j := 0; j < len(k) && i < 2; j++ {
		if k[j] == '|' {
			parts[i] = k[start:j]
			i++
			start = j + 1
		}
	}
	parts[2] = k[start:]
	return parts[0], parts[1], parts[2]
}
