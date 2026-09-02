package report

import (
	"path/filepath"
	"testing"
	"time"

	"loom/internal/events"
	"loom/internal/webui"
)

func newTestDetector(t *testing.T) *detector {
	t.Helper()
	return newDetector(filepath.Join(t.TempDir(), "events.jsonl"), 30*24*time.Hour)
}

func viewWithEdges(edges ...webui.EdgeView) webui.View {
	return webui.View{Nodes: []webui.NodeView{{ID: "demo-a", Edges: edges}}}
}

// 两台都不是中控的机器之间断了,必须变成事件。
//
// **这是转述唯一带过来的链路事实。** 隧道握手年龄只有直接问那台机器才
// 拿得到(view.go 里 `st == nil` 那个分支),而中控直接问得到的只有它自己。
// 所以在这条之前,demo-a ↔ demo-c 断了 7 小时,事件历史里一条记录都没有,
// 未解决面板上也没有 —— 数据一直在转述里、`loom status` 也一直显示着 ❌,
// 就是没人把它变成事件,于是"断了多久"答不出来。
func TestEdgeFailureBecomesEvent(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)

	// 第一轮只播种 —— 重启不该看起来像全网同时变化了一次。
	if evs, err := d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", MS: 219}), now); err != nil {
		t.Fatal(err)
	} else if len(evs) != 0 {
		t.Fatalf("第一轮不该产生事件,产生了 %d 条", len(evs))
	}

	evs, err := d.observe(viewWithEdges(
		webui.EdgeView{To: "demo-c", Err: "i/o timeout"}), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("链路断了应该产生 1 条事件,产生了 %d 条:%v", len(evs), evs)
	}
	e := evs[0]
	if e.Kind != "edge" || e.Node != "demo-a" || e.Subject != "demo-c" {
		t.Errorf("事件身份不对:%+v", e)
	}
	if e.From != "ok" || e.To != "unreachable" {
		t.Errorf("两端都要有,否则「从坏变好」和「一直是好的」长得一样:%+v", e)
	}
	if !e.Bad() {
		t.Errorf("链路不通该是 problem 级,否则上不了未解决面板:%s", e.Level())
	}
}

// 恢复也要记 —— 只记坏不记好的话,"断了多久"永远算不出结束时间。
func TestEdgeRecoveryBecomesEvent(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)

	d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", Err: "i/o timeout"}), now)
	evs, err := d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", MS: 219}), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || !evs[0].Recovered() {
		t.Fatalf("恢复没被记成一次恢复:%v", evs)
	}
}

// **RTT 变化不产生事件。**
//
// RTT 每轮都在变。把它记进状态就是每轮一条事件 —— 那不是历史,是噪音,
// 而且会把真正的通断变化淹掉(同 events 包"只记变化"的理由)。
// 慢和断该有不同的反应。
func TestEdgeRTTChangeIsNotAnEvent(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)

	d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", MS: 219}), now)
	for i, ms := range []int{220, 350, 180, 900} {
		evs, err := d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", MS: ms}),
			now.Add(time.Duration(i+1)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != 0 {
			t.Fatalf("RTT 从 219 变成 %d 就产生了事件:%v", ms, evs)
		}
	}
}

// 一条链路两端都会报,于是产生两条事件 —— 这是刻意的,不是重复。
//
// 单向故障真实存在:实测过 demo-a → demo-c 的包到得了、demo-c → demo-a 的回程
// 被丢。合并成一条就看不出这种不对称了。
func TestEdgeIsRecordedPerObserver(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	both := func(aErr, bErr string) webui.View {
		return webui.View{Nodes: []webui.NodeView{
			{ID: "demo-a", Edges: []webui.EdgeView{{To: "demo-c", Err: aErr}}},
			{ID: "demo-c", Edges: []webui.EdgeView{{To: "demo-a", Err: bErr}}},
		}}
	}
	d.observe(both("", ""), now)

	// 只有一端报坏:那是一次单向故障,必须看得出来。
	evs, err := d.observe(both("i/o timeout", ""), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Node != "demo-a" {
		t.Fatalf("单向故障应该只产生观测方那一条:%v", evs)
	}

	evs, err = d.observe(both("i/o timeout", "i/o timeout"), now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Node != "demo-c" {
		t.Fatalf("另一端随后也断,应该再产生它自己那一条:%v", evs)
	}
}

// edge 必须被 events 包认成"有问题的状态",否则它进不了未解决面板 ——
// 那是 D55 那个"级别靠猜"的 bug 的同一个位置。
func TestEdgeLevelIsClassifiedByKind(t *testing.T) {
	bad := events.Event{Kind: "edge", Subject: "demo-c", From: "ok", To: "unreachable"}
	if !bad.Bad() {
		t.Errorf("unreachable 不是 problem:%s", bad.Level())
	}
	ok := events.Event{Kind: "edge", Subject: "demo-c", From: "unreachable", To: "ok"}
	if !ok.Recovered() {
		t.Errorf("恢复不是 ok 级:%s", ok.Level())
	}
}

func TestTrafficOnlyCounterDoesNotBecomeUnresolvedTunnel(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 28, 20, 0, 0, 0, time.UTC)
	v := webui.View{Nodes: []webui.NodeView{{
		ID: "demo-e",
		Tunnels: []webui.TunnelView{
			{Interface: "wg-demo-b", State: "active", OK: true},
			{
				Interface: "wg-signed-only", State: "counter-only",
				CounterPresent: true, TrafficTrusted: true, TrafficVerified: true,
			},
		},
	}}}

	if evs, err := d.observe(v, now); err != nil {
		t.Fatal(err)
	} else if len(evs) != 0 {
		t.Fatalf("seed round produced events: %v", evs)
	}
	if got := UnresolvedNow(d.trackedState(now), nil, now); len(got) != 0 {
		t.Fatalf("traffic-only evidence became a carrier problem: %v", got)
	}
	if _, ok := d.trackedState(now).States["demo-e/tunnel/wg-signed-only"]; ok {
		t.Fatal("traffic-only evidence entered the persistent tunnel state tracker")
	}
}

func TestRolloutAndIdentityFailuresBecomeEvents(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	base := webui.View{Nodes: []webui.NodeView{{ID: "demo-b",
		Rollout: &webui.RolloutView{Snapshot: "snap", Stage: "verified"}}}}
	if _, err := d.observe(base, now); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.Nodes = []webui.NodeView{{ID: "demo-b", IdentityError: "outer node mismatch",
		Rollout: &webui.RolloutView{Snapshot: "snap", Stage: "activating", Stuck: true, Problem: true}}}
	evs, err := d.observe(bad, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	levels := map[string]bool{}
	for i := range evs {
		if evs[i].Bad() {
			levels[evs[i].Kind] = true
		}
	}
	if !levels["identity"] || !levels["rollout"] {
		t.Fatalf("签名与 rollout 故障都应成为 problem 事件:%+v", evs)
	}
}

func TestDecommissionedRolloutEventIsInformational(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	verified := webui.View{Nodes: []webui.NodeView{{ID: "old01",
		Rollout: &webui.RolloutView{Snapshot: "before", Stage: "verified"}}}}
	if _, err := d.observe(verified, now); err != nil {
		t.Fatal(err)
	}
	decommissioned := webui.View{Nodes: []webui.NodeView{{ID: "old01",
		Rollout: &webui.RolloutView{Snapshot: "signed-stop", Stage: "decommissioned"}}}}
	evs, err := d.observe(decommissioned, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range evs {
		if evs[i].Kind == "rollout" {
			if evs[i].Bad() {
				t.Fatalf("下线事件应是 info，不是 problem:%+v", evs[i])
			}
			if evs[i].To == "decommissioned" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("没有记录 verified→decommissioned 事件:%+v", evs)
	}
}

// **播种时就已经坏掉的东西,必须上得了面板。**
//
// 这是这一轮要修的那个盲区。detector 第一轮静默播种(否则每次重启都像
// 全网同时变化一次),所以那时**已经**坏掉的东西不产生任何事件。旧版面板
// 从事件历史筛"未解决",于是对它完全瞎 —— 实测:demo-a ↔ demo-c 断了 9 小时,
// edge 事件做完之后仍然上不了面板。
//
// 修法是问对来源:清单来自当前状态,时长才来自事件历史。
func TestSeededBadStateStillReachesPanel(t *testing.T) {
	d := newTestDetector(t)
	seed := time.Date(2026, 8, 24, 1, 0, 0, 0, time.UTC)
	now := seed.Add(9 * time.Hour)

	// 播种那一轮它就是坏的 —— 没有任何事件产生。
	evs, err := d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", Err: "i/o timeout"}), seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Fatalf("播种轮不该产生事件,产生了 %d 条", len(evs))
	}

	got := UnresolvedNow(d.trackedState(now), nil, now)
	if len(got) != 1 {
		t.Fatalf("播种时就坏的问题没上面板:%v", got)
	}
	u := got[0]
	if u.Node != "demo-a" || u.Kind != "edge" || u.Subject != "demo-c" {
		t.Errorf("身份不对:%+v", u)
	}
	// 起点不知道,只能给下界 —— 而**必须标成下界**,假装精确才是说谎。
	if !u.AtLeast {
		t.Error("查不到起点却没标成下界")
	}
	// 从开始跟踪那一刻算起 —— 更早的事无从得知,所以是下界。
	if u.Lasted != "9.0 小时" {
		t.Errorf("下界该从开始跟踪那一刻算,得到 %q", u.Lasted)
	}
}

// 有事件可查时用准确时长,不退回下界。
func TestUnresolvedUsesExactDurationWhenKnown(t *testing.T) {
	d := newTestDetector(t)
	seed := time.Date(2026, 8, 24, 1, 0, 0, 0, time.UTC)
	broke := seed.Add(8 * time.Hour)
	now := seed.Add(10 * time.Hour)

	d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", MS: 219}), seed)
	evs, err := d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", Err: "i/o timeout"}), broke)
	if err != nil || len(evs) != 1 {
		t.Fatalf("没产生断开事件:%v %v", evs, err)
	}

	got := UnresolvedNow(d.trackedState(now), evs, now)
	if len(got) != 1 {
		t.Fatalf("期望 1 条,得到 %v", got)
	}
	if got[0].AtLeast {
		t.Error("明明查得到起点,却标成了下界")
	}
	if got[0].Lasted != "2.0 小时" {
		t.Errorf("时长该从事件算起,得到 %q", got[0].Lasted)
	}
}

// 已经恢复的不该留在面板上 —— 面板问的是"现在",不是"曾经"。
func TestRecoveredLeavesPanel(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 24, 1, 0, 0, 0, time.UTC)

	d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", Err: "boom"}), now)
	if got := UnresolvedNow(d.trackedState(now), nil, now); len(got) != 1 {
		t.Fatalf("坏的时候没上面板:%v", got)
	}
	evs, _ := d.observe(viewWithEdges(webui.EdgeView{To: "demo-c", MS: 219}), now.Add(time.Hour))
	if got := UnresolvedNow(d.trackedState(now.Add(time.Hour)), evs, now.Add(time.Hour)); len(got) != 0 {
		t.Errorf("恢复之后还赖在面板上:%v", got)
	}
}

// 面板行序必须稳定 —— 状态存在 map 里,不排序的话每次刷新行序都在跳。
func TestUnresolvedOrderIsStable(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 24, 1, 0, 0, 0, time.UTC)
	v := webui.View{Nodes: []webui.NodeView{
		{ID: "demo-e", Edges: []webui.EdgeView{{To: "demo-c", Err: "x"}, {To: "demo-b", Err: "x"}}},
		{ID: "demo-a", Edges: []webui.EdgeView{{To: "demo-c", Err: "x"}}},
	}}
	d.observe(v, now)

	first := UnresolvedNow(d.trackedState(now), nil, now)
	for i := 0; i < 20; i++ {
		got := UnresolvedNow(d.trackedState(now), nil, now)
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("第 %d 次行序变了:%v ≠ %v", i, got, first)
			}
		}
	}
}

// **重启不能把时长清零。**
//
// 时长是这个面板唯一真正新增的信息("链路断了"看节点表也知道,"断了两天了"
// 才让人动手),而上报者重启是常事 —— 今天为了发版就重启了两次。
//
// 实测过这个 bug:改完面板之后,一条断了 10 小时的链路显示成"至少 28 秒",
// 因为上报者刚重启过。技术上没说错,实际效果是让人以为它刚坏。
func TestDurationSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	broke := time.Date(2026, 8, 24, 1, 0, 0, 0, time.UTC)

	// 第一段:上报者跑着,亲眼看到链路断了。
	d1 := newDetector(filepath.Join(dir, "events.jsonl"), 30*24*time.Hour)
	d1.statePath = statePath
	d1.observe(viewWithEdges(webui.EdgeView{To: "demo-c", MS: 219}), broke.Add(-time.Hour))
	if _, err := d1.observe(viewWithEdges(webui.EdgeView{To: "demo-c", Err: "boom"}), broke); err != nil {
		t.Fatal(err)
	}

	// 第二段:重启。新 detector 从状态文件接回起点。
	d2 := newDetector(filepath.Join(dir, "events.jsonl"), 30*24*time.Hour)
	d2.statePath = statePath
	prev, err := LoadTrackedState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil {
		t.Fatal("状态文件没写出来,重启后无从接续")
	}
	d2.restore(prev)

	restart := broke.Add(10 * time.Hour)
	if _, err := d2.observe(viewWithEdges(webui.EdgeView{To: "demo-c", Err: "boom"}), restart); err != nil {
		t.Fatal(err)
	}

	got := UnresolvedNow(d2.trackedState(restart), nil, restart)
	if len(got) != 1 {
		t.Fatalf("重启之后问题不见了:%v", got)
	}
	if got[0].Lasted != "10.0 小时" {
		t.Errorf("重启把时长清零了:%q(期望 10.0 小时)", got[0].Lasted)
	}
	if got[0].AtLeast {
		t.Error("起点是亲眼看到的,不该标成下界")
	}
}

// 上报者停着的时候状态变了 —— 变化发生在什么时候无从得知,
// **那就按新起点算并标成下界,不假装知道。**
func TestChangedWhileDownIsNotBackdated(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	start := time.Date(2026, 8, 24, 1, 0, 0, 0, time.UTC)

	d1 := newDetector(filepath.Join(dir, "events.jsonl"), 30*24*time.Hour)
	d1.statePath = statePath
	d1.observe(viewWithEdges(webui.EdgeView{To: "demo-c", MS: 219}), start) // 好的

	d2 := newDetector(filepath.Join(dir, "events.jsonl"), 30*24*time.Hour)
	d2.statePath = statePath
	prev, _ := LoadTrackedState(statePath)
	d2.restore(prev)

	// 停机期间断了,重启后第一次看到就是坏的。
	restart := start.Add(10 * time.Hour)
	d2.observe(viewWithEdges(webui.EdgeView{To: "demo-c", Err: "boom"}), restart)

	got := UnresolvedNow(d2.trackedState(restart), nil, restart)
	if len(got) != 1 {
		t.Fatalf("期望 1 条:%v", got)
	}
	if !got[0].AtLeast {
		t.Error("停机期间变的,起点不可知,必须标成下界")
	}
	if got[0].Lasted != "0 秒" {
		t.Errorf("不该把停机那 10 小时算进去 —— 它可能一直是好的:%q", got[0].Lasted)
	}
}

// **同一个测量,两种含义 —— 分级必须跟着含义走。**
//
// 声明里的 probe_url 由上报者测,结果喂 Agent 剪枝:"demo-b 够不到 Cloudflare"
// 正是要的答案,它把 15 条候选砍到 6 条。把它当成待处理问题的后果实测过 ——
// 在面板上挂了 14 小时,而与此同时国内机器**没有任何一个够得到的目标**,
// 所以它的直连真断了反而看不出来。两件事恰好反着。
func TestTargetIsDataAndUplinkIsAlarm(t *testing.T) {
	d := newTestDetector(t)
	now := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)
	view := func(targetErr, uplinkErr string) webui.View {
		return webui.View{Nodes: []webui.NodeView{{ID: "demo-b", Targets: []webui.TargetView{
			{Target: "https://api.ipify.org", Err: targetErr},
			{Target: "https://www.baidu.com", Err: uplinkErr, Uplink: true},
		}}}}
	}

	// 结构性够不到的那个:是数据,不是告警。
	d.observe(view("", ""), now)
	evs, err := d.observe(view("i/o timeout", ""), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("期望 1 条事件:%v", evs)
	}
	if evs[0].Kind != "target" {
		t.Errorf("没打上 target 类:%+v", evs[0])
	}
	if evs[0].Bad() {
		t.Error("声明目标够不到被当成了故障 —— 那是喂剪枝的数据")
	}
	if got := UnresolvedNow(d.trackedState(now.Add(time.Minute)), nil, now.Add(time.Minute)); len(got) != 0 {
		t.Errorf("它不该上未解决面板:%v", got)
	}

	// 本该够得到却够不到:这才是要人管的。
	evs, err = d.observe(view("i/o timeout", "connection refused"), now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Kind != "uplink" {
		t.Fatalf("期望一条 uplink 事件:%v", evs)
	}
	if !evs[0].Bad() {
		t.Error("直连坏了却不是 problem 级 —— 上不了面板")
	}
	at := now.Add(2 * time.Minute)
	got := UnresolvedNow(d.trackedState(at), evs, at)
	if len(got) != 1 || got[0].Kind != "uplink" {
		t.Fatalf("直连故障没上面板:%v", got)
	}
}
