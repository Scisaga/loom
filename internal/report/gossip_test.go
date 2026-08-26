package report

import (
	"strings"
	"testing"
	"time"

	"loom/internal/attest"
)

func TestTableRejectsFuturePoisonBeforeIndexing(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	tbl := newTable()
	valid := &Observation{Node: "n1", TS: now.Add(-time.Minute).Format(time.RFC3339), Applied: "good"}
	if err := tbl.put(valid, now, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	poison := &Observation{Node: "n1", TS: now.Add(time.Hour).Format(time.RFC3339), Applied: "poison"}
	if err := tbl.put(poison, now, 10*time.Minute); err == nil || !strings.Contains(err.Error(), "未来") {
		t.Fatalf("未来观测没有在入表前被拒绝:%v", err)
	}
	got := tbl.snapshot("", now, 10*time.Minute)
	if len(got) != 1 || got[0].Applied != "good" {
		t.Fatalf("未来 poison 遮住了合法观测:%+v", got)
	}
}

func TestTablePrefersSignedObservationForSameNode(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	tbl := newTable()
	// 签名正确性由 attest 专门测试；这里注入成功 verifier，只钉表的替换规则。
	tbl.verify = func(*Observation, time.Time, time.Duration) error { return nil }
	unsigned := &Observation{Node: "n1", TS: now.Add(-time.Minute).Format(time.RFC3339), Applied: "unsigned"}
	if err := tbl.put(unsigned, now, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	signed := &Observation{Node: "n1", TS: now.Add(-2 * time.Minute).Format(time.RFC3339), Applied: "signed", Attest: &attest.Signed{}}
	if err := tbl.put(signed, now, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	newerUnsigned := &Observation{Node: "n1", TS: now.Format(time.RFC3339), Applied: "downgrade"}
	if err := tbl.put(newerUnsigned, now, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	got := tbl.snapshot("", now, 10*time.Minute)
	if len(got) != 1 || got[0].Applied != "signed" || got[0].Attest == nil {
		t.Fatalf("unsigned 覆盖了 signed，或 signed 未取代 unsigned:%+v", got)
	}
}

func TestExpiredSignedDoesNotPermanentlyHideFreshLegacy(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	tbl := newTable()
	tbl.verify = func(*Observation, time.Time, time.Duration) error { return nil }
	// 模拟表中上一轮留下、此刻刚过期的 signed；put 自己会拒收过期输入，
	// 所以直接播种旧表正是要覆盖的生命周期场景。
	tbl.by["n1"] = &Observation{Node: "n1", TS: now.Add(-11 * time.Minute).Format(time.RFC3339), Attest: &attest.Signed{}}
	fresh := &Observation{Node: "n1", TS: now.Format(time.RFC3339), Applied: "legacy"}
	if err := tbl.put(fresh, now, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	got := tbl.snapshot("", now, 10*time.Minute)
	if len(got) != 1 || got[0].Applied != "legacy" || got[0].Attest != nil {
		t.Fatalf("过期 signed 永久占住索引:%+v", got)
	}
}

func TestRelayedSelfObservationCannotOverrideOwnMeasurement(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	tbl := newTable()
	own := &Observation{Node: "jm24", TS: now.Format(time.RFC3339), Applied: "own"}
	if err := tbl.put(own, now, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	poison := &Observation{Node: "jm24", TS: now.Add(time.Minute).Format(time.RFC3339), Applied: "relay-poison"}
	if err := tbl.putRelayed(poison, "jm24", now, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	got, _ := tbl.view("jm24", now, 10*time.Minute)
	if got == nil || got.Applied != "own" {
		t.Fatalf("邻居转述覆盖了本机 observe:%+v", got)
	}
}

func TestTableRejectsMalformedAndExpiredTimestamps(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	tbl := newTable()
	if err := tbl.put(&Observation{Node: "bad", TS: "not-a-time"}, now, 10*time.Minute); err == nil {
		t.Error("格式损坏的时间没有告警")
	}
	if err := tbl.put(&Observation{Node: "old", TS: now.Add(-11 * time.Minute).Format(time.RFC3339)}, now, 10*time.Minute); err != nil {
		t.Fatalf("正常过期观测应静默淘汰，得到:%v", err)
	}
	if got := tbl.snapshot("", now, 10*time.Minute); len(got) != 0 {
		t.Fatalf("非法观测留在索引:%+v", got)
	}
}
