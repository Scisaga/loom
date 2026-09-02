package events

import (
	"path/filepath"
	"testing"
	"time"
)

func at(min int) string {
	return time.Date(2026, 8, 23, 9, min, 0, 0, time.UTC).Format(time.RFC3339)
}

// 只记变化,不记状态。一次 69 秒的断连应当是**两条**记录,
// 不是 70 条"还在断"。
func TestDurationPairsTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	if err := Append(path, []Event{
		{TS: at(0), Node: "n", Kind: "tunnel", Subject: "wg-a", From: "active", To: "down"},
		{TS: at(20), Node: "n", Kind: "tunnel", Subject: "wg-a", From: "down", To: "active"},
	}); err != nil {
		t.Fatal(err)
	}
	evs, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("期望 2 条,得到 %d", len(evs))
	}
	// Load 倒序,最新在前。
	if evs[0].To != "active" {
		t.Errorf("最新一条应当是恢复,得到 %+v", evs[0])
	}
	now := time.Date(2026, 8, 23, 9, 35, 0, 0, time.UTC)

	// 那次断连持续了 20 分钟,已经结束。
	d, ongoing := Duration(evs, 1, now, "active")
	if ongoing || d != 20*time.Minute {
		t.Errorf("断连时长 %v ongoing=%v,期望 20m 且已结束", d, ongoing)
	}
	// 当前状态还在持续。
	d, ongoing = Duration(evs, 0, now, "active")
	if !ongoing || d != 15*time.Minute {
		t.Errorf("当前状态 %v ongoing=%v,期望 15m 且持续中", d, ongoing)
	}
}

// 不同 Key 的事件不能互相配对 —— 否则 wg-a 的恢复会被当成 wg-b 的。
func TestDurationDoesNotCrossKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	_ = Append(path, []Event{
		{TS: at(0), Node: "n", Kind: "tunnel", Subject: "wg-a", To: "down"},
		{TS: at(5), Node: "n", Kind: "tunnel", Subject: "wg-b", To: "active"},
	})
	evs, _ := Load(path)
	now := time.Date(2026, 8, 23, 9, 30, 0, 0, time.UTC)
	// wg-a 那条(倒序里在后面)没有后续,应当是持续中。
	for i := range evs {
		if evs[i].Subject != "wg-a" {
			continue
		}
		if _, ongoing := Duration(evs, i, now, "down"); !ongoing {
			t.Error("wg-a 被 wg-b 的事件错误地配对了")
		}
	}
}

// "从坏变好"和"一直是好的"必须分得开 —— 所以 From 和 To 都要记。
func TestBadAndRecovered(t *testing.T) {
	cases := []struct {
		kind, from, to string
		bad, rec       bool
	}{
		{"tunnel", "active", "down", true, false},
		{"tunnel", "down", "active", false, true},
		{"drift", "clean", "2 处", true, false},
		{"uplink", "ok", "unreachable", true, false},
		{"uplink", "unreachable", "ok", false, true},
		{"edge", "ok", "unreachable", true, false},
		{"edge", "unreachable", "ok", false, true},
		{"tunnel", "active", "active", false, false}, // 不该出现,但也不该被当成事故
	}
	for _, c := range cases {
		e := Event{Kind: c.kind, From: c.from, To: c.to}
		if e.Bad() != c.bad || e.Recovered() != c.rec {
			t.Errorf("%s %s → %s:bad=%v rec=%v,期望 %v/%v",
				c.kind, c.from, c.to, e.Bad(), e.Recovered(), c.bad, c.rec)
		}
	}
}

// **target 是数据,不是告警。**
//
// 它回答"这台机器够不够得到那个目标",而 Agent 拿它剪枝 —— "demo-b 够不到
// Cloudflare"正是要的答案(15 条候选砍到 6 条),不是故障。
//
// 当成故障的后果实测过:在未解决面板上挂了 14 小时,而与此同时国内机器
// **没有任何一个够得到的目标**,所以它的直连真断了反而看不出来。两件事
// 恰好反着。需要人管的那种够不到走 uplink(model.Node.ProbeTargets)。
func TestTargetIsDataNotAlarm(t *testing.T) {
	for _, e := range []Event{
		{Kind: "target", Subject: "https://api.ipify.org", From: "ok", To: "unreachable"},
		{Kind: "target", Subject: "https://api.ipify.org", From: "unreachable", To: "ok"},
	} {
		if e.Bad() {
			t.Errorf("%s %s → %s 被当成了故障", e.Kind, e.From, e.To)
		}
		if e.Level() != LevelInfo {
			t.Errorf("%s 的级别是 %s,期望 info", e.Kind, e.Level())
		}
	}
}

// **发布新快照、Agent 换路都不是问题。** 把它们当成问题的后果实测过:
// "还在持续的问题"面板列了 7 条,7 条全是快照号和选路结果 —— 而这正是
// 这个面板要防的那种"狼来了"。
func TestNormalOperationIsNotAProblem(t *testing.T) {
	for _, e := range []Event{
		{Kind: "snapshot", From: "abc123", To: "def456"},
		{Kind: "route", Subject: "cn-web", From: "edge-b", To: "direct"},
	} {
		if e.Bad() {
			t.Errorf("%s 被当成问题:%+v", e.Kind, e)
		}
		if e.Level() != LevelInfo {
			t.Errorf("%s 的 level 是 %s,期望 info", e.Kind, e.Level())
		}
	}
	// 轮换窗口是过渡态:不是故障,但也不该一直开着。
	r := Event{Kind: "rotation", Subject: "cred-x", To: "两代并存"}
	if r.Level() != LevelPending {
		t.Errorf("轮换窗口的 level 是 %s,期望 pending", r.Level())
	}
}

// 上报者重启时静默播种,所以日志的最后一条不一定是现状。
// 实测踩过:一条 2.4 小时前的快照事件被显示成"还在持续",而那台机器
// 早就换了两个版本。
func TestOngoingChecksAgainstCurrentState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	_ = Append(path, []Event{{TS: at(0), Node: "n", Kind: "tunnel", Subject: "wg-a", To: "down"}})
	evs, _ := Load(path)
	now := time.Date(2026, 8, 23, 9, 30, 0, 0, time.UTC)

	if _, ongoing := Duration(evs, 0, now, "down"); !ongoing {
		t.Error("当前状态就是它,却说不在持续")
	}
	if _, ongoing := Duration(evs, 0, now, "active"); ongoing {
		t.Error("当前状态已经变了,却还说在持续 —— 播种期的变化没被记下来")
	}
	if _, ongoing := Duration(evs, 0, now, ""); !ongoing {
		t.Error("不知道当前状态时应当退回旧行为")
	}
}

// 追加日志不压实会无限长大。
func TestCompactDropsOld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	old := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	_ = Append(path, []Event{
		{TS: old, Node: "n", Kind: "tunnel", To: "down"},
		{TS: at(0), Node: "n", Kind: "tunnel", To: "active"},
	})
	now := time.Date(2026, 8, 23, 9, 35, 0, 0, time.UTC)
	if err := Compact(path, now, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	evs, _ := Load(path)
	if len(evs) != 1 || evs[0].TS != at(0) {
		t.Errorf("压实之后剩 %d 条:%+v", len(evs), evs)
	}
}

// 一行坏数据不该毁掉整个历史。
func TestBadLineIsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	_ = Append(path, []Event{{TS: at(0), Node: "n", To: "down"}})
	f, _ := openAppend(path)
	_, _ = f.WriteString("这不是 JSON\n")
	_ = f.Close()
	_ = Append(path, []Event{{TS: at(1), Node: "n", To: "active"}})
	evs, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Errorf("坏行让历史少了:剩 %d 条", len(evs))
	}
}
