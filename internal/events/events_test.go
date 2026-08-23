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
	d, ongoing := Duration(evs, 1, now)
	if ongoing || d != 20*time.Minute {
		t.Errorf("断连时长 %v ongoing=%v,期望 20m 且已结束", d, ongoing)
	}
	// 当前状态还在持续。
	d, ongoing = Duration(evs, 0, now)
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
		if _, ongoing := Duration(evs, i, now); !ongoing {
			t.Error("wg-a 被 wg-b 的事件错误地配对了")
		}
	}
}

// "从坏变好"和"一直是好的"必须分得开 —— 所以 From 和 To 都要记。
func TestBadAndRecovered(t *testing.T) {
	cases := []struct {
		from, to string
		bad, rec bool
	}{
		{"active", "down", true, false},
		{"down", "active", false, true},
		{"clean", "2 处", true, false},
		{"ok", "unreachable", true, false},
		{"unreachable", "ok", false, true},
		{"active", "active", false, false}, // 不该出现,但也不该被当成事故
	}
	for _, c := range cases {
		e := Event{From: c.from, To: c.to}
		if e.Bad() != c.bad || e.Recovered() != c.rec {
			t.Errorf("%s → %s:bad=%v rec=%v,期望 %v/%v", c.from, c.to, e.Bad(), e.Recovered(), c.bad, c.rec)
		}
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
