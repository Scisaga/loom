package publish

import (
	"os"
	"strings"
	"testing"
)

// **只记变化,不记状态**(同 events 包)。
//
// 发布器每 30 秒收敛一轮,同一个快照会被反复确认。逐轮记一行的话,一天就是
// 2880 行"还是那个快照" —— 那不是历史,是噪音,而且会把真正的版本变化淹掉。
func TestPublishedRecordsOnlyChanges(t *testing.T) {
	dir := t.TempDir()

	for i := 0; i < 5; i++ {
		wrote, err := AppendPublished(dir, Published{At: "2026-08-24T00:00:00Z", Snapshot: "aaa", SSOTSum: "s1"})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && !wrote {
			t.Fatal("第一条没写进去")
		}
		if i > 0 && wrote {
			t.Fatalf("第 %d 次是同一个快照,却又记了一行", i+1)
		}
	}

	if _, err := AppendPublished(dir, Published{At: "2026-08-24T00:01:00Z", Snapshot: "bbb", SSOTSum: "s2"}); err != nil {
		t.Fatal(err)
	}
	recs, err := ReadPublished(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("确认 5 次 + 换一版,应该是 2 条,实际 %d 条", len(recs))
	}
	if recs[0].Snapshot != "aaa" || recs[1].Snapshot != "bbb" {
		t.Errorf("顺序不对:%v", recs)
	}
}

// 退回旧版之后又发新版,历史里必须两条都在 —— 只按"见过的 id"去重的话,
// 回滚这件事本身就从历史里消失了。
func TestPublishedKeepsReturnToOldSnapshot(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"aaa", "bbb", "aaa"} {
		if _, err := AppendPublished(dir, Published{At: "2026-08-24T00:00:00Z", Snapshot: id}); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := ReadPublished(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("回滚回 aaa 应该留下第 3 条,实际 %d 条", len(recs))
	}
}

// 还没发过任何东西是个合法状态,不是错误。
func TestPublishedEmptyIsNotAnError(t *testing.T) {
	recs, err := ReadPublished(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Errorf("空目录读出了 %d 条", len(recs))
	}
}

// 坏行跳过,不让整份历史读失败。
//
// 这是一份追加式日志,写到一半断电会留下半行。为了一行坏数据丢掉整段历史,
// 恰恰是在最需要它的时候把它弄没 —— 而"最需要它的时候"就是刚断过电。
func TestPublishedSkipsBadLines(t *testing.T) {
	dir := t.TempDir()
	if _, err := AppendPublished(dir, Published{At: "t", Snapshot: "aaa"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(HistoryPath(dir), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	// 半行(断电)、空行、以及一行合法记录
	if _, err := f.WriteString("{\"snapshot\":\"bb\n\n{\"at\":\"t\",\"snapshot\":\"ccc\"}\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	recs, err := ReadPublished(dir)
	if err != nil {
		t.Fatalf("一行坏数据让整段历史读不出来了:%v", err)
	}
	if len(recs) != 2 || recs[1].Snapshot != "ccc" {
		t.Errorf("应该跳过坏行留下 aaa 与 ccc,实际 %v", recs)
	}
}

// 发布历史和源头存档放在同一个目录,但互不干扰:
// 存档按 *.yaml 数版本,历史是单独一个文件。
func TestHistoryDoesNotDisturbArchive(t *testing.T) {
	dir := t.TempDir()
	if _, err := ArchiveSSOT(dir, []byte(goodSSOT)); err != nil {
		t.Fatal(err)
	}
	if _, err := AppendPublished(dir, Published{At: "t", Snapshot: "aaa"}); err != nil {
		t.Fatal(err)
	}
	if n := countFiles(t, dir); n != 1 {
		t.Errorf("发布历史被算进源头存档了:数出 %d 份", n)
	}
	if !strings.HasSuffix(HistoryPath(dir), ".jsonl") {
		t.Errorf("历史文件名不该是 .yaml,否则会被当成一版源头:%s", HistoryPath(dir))
	}
}
