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
	// statePath 是当前状态的落脚点。空则不写。
	statePath string
	// details 是每个受跟踪状态的补充说明,跟着 prev 一起走。
	details map[string]string
	// since 是每个状态的已知起点,exact 说这个起点是不是来自一次真实变化。
	//
	// **它们跨重启存活**(启动时从 statePath 读回来):时长是面板唯一真正
	// 新增的信息,而上报者重启是常事。每次重启把时长清零的话,面板在最该
	// 说话的时候恰好失忆 —— 实测过一次"至少 28 秒",而那条链路已经断了
	// 10 小时。
	since map[string]time.Time
	exact map[string]bool
	// restored* 是上一次状态文件里的内容,只在播种那一轮用一次。
	restoredState map[string]string
	restoredSince map[string]time.Time
	restoredExact map[string]bool
}

// current 返回某个受跟踪状态的当前值。事件日志的最后一条不一定是现状
// (重启时静默播种),所以判断"还在持续"要跟它核对。
func (d *detector) current(key string) string { return d.prev[key] }

func newDetector(path string, retention time.Duration) *detector {
	return &detector{
		path: path, retention: retention,
		prev: map[string]string{}, details: map[string]string{},
		since: map[string]time.Time{}, exact: map[string]bool{},
		restoredState: map[string]string{},
		restoredSince: map[string]time.Time{},
		restoredExact: map[string]bool{},
	}
}

// restore 从上一次的状态文件把"已知起点"接回来。
//
// **只接值没变的那些。** 上报者停着的时候状态可能变过,而变化发生在什么
// 时候无从得知 —— 那种情况按新起点算,并且标成下界,不假装知道。
func (d *detector) restore(prev *TrackedState) {
	if prev == nil {
		return
	}
	for k, t := range prev.States {
		at, ok := parseTS(t.Since)
		if !ok {
			continue
		}
		d.restoredState[k] = t.State
		d.restoredSince[k] = at
		d.restoredExact[k] = t.Exact
	}
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

		// 节点之间的链路。
		//
		// **这是转述唯一带过来的链路事实。** 隧道握手年龄只有直接问那台
		// 机器才拿得到(见 view.go:`st == nil` 那个分支),而中控直接问得到
		// 的只有它自己 —— 所以两台都不是中控的机器之间断了,除了这里
		// 没有任何地方会发现。
		//
		// 实测的代价:ber01 ↔ hz01 断了 7 小时,事件历史里一条记录都没有,
		// 未解决面板上也没有。数据一直在转述里、`loom status` 也一直显示
		// 着 ❌,就是从来没有人把它变成一条事件 —— 于是"断了多久"这个
		// 做事件历史的全部理由,恰恰在这类故障上答不出来。
		//
		// **只记通与不通,不记 RTT。** RTT 每轮都在变,记进状态就是每轮
		// 一条事件;而慢和断该有不同的反应(同 D59 那条超时的形状)。
		for _, e := range n.Edges {
			state := "ok"
			if e.Err != "" {
				state = "unreachable"
			}
			add(n.ID, "edge", e.To, state, e.Err)
		}
	}

	// 第一轮只播种。重启不该看起来像全网同时变化了一次。
	//
	// **代价记在这里:播种时已经坏掉的东西不会产生事件。** 面板因此不能
	// 只从事件历史推导"有什么问题" —— 它读 statePath 那份当前状态,
	// 用 seededAt 给出时长的下界(tracked.go)。
	if !d.seeded {
		for k, e := range cur {
			d.prev[k] = e.To
			d.details[k] = e.Detail
			// 上一次记的还是这个值,就把起点接回来;不是,就从现在算起。
			if old, ok := d.restoredState[k]; ok && old == e.To {
				d.since[k] = d.restoredSince[k]
				d.exact[k] = d.restoredExact[k]
			} else {
				d.since[k] = now
				d.exact[k] = false
			}
		}
		d.seeded = true
		return nil, d.persist(now)
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
		// 这一次变化是被亲眼看到的,所以起点是精确的。
		d.since[k] = now
		d.exact[k] = true
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
		delete(d.since, k)
		delete(d.exact, k)
	}

	for k, e := range cur {
		d.details[k] = e.Detail
	}
	for k := range d.details {
		if _, still := cur[k]; !still {
			delete(d.details, k)
		}
	}
	if err := events.Append(d.path, out); err != nil {
		return out, err
	}
	if err := d.persist(now); err != nil {
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

// persist 把这一轮的当前状态写下来,供面板回答"现在有什么问题"。
//
// 写失败不该让记事件失败 —— 但也不能不说,否则面板会安静地停在旧状态上。
func (d *detector) persist(now time.Time) error {
	if d.statePath == "" {
		return nil
	}
	return WriteTrackedState(d.statePath, d.trackedState(now))
}

// trackedState 把内存里的当前状态拍一张快照。
//
// 落盘和界面都走它 —— **两条路必须是同一份状态**,否则 `loom status` 和
// 网页面板会各说各话,而那正是面板开始说谎的方式。
func (d *detector) trackedState(now time.Time) *TrackedState {
	st := &TrackedState{
		TS:     now.UTC().Format(time.RFC3339),
		States: make(map[string]Tracked, len(d.prev)),
	}
	for k, v := range d.prev {
		t := Tracked{State: v, Detail: d.details[k], Exact: d.exact[k]}
		if at, ok := d.since[k]; ok {
			t.Since = at.UTC().Format(time.RFC3339)
		}
		st.States[k] = t
	}
	return st
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
