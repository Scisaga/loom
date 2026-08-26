package rollout

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// 没做过 rollout 不是错误,是这台机器的正常初始状态。
func TestReadAbsentIsNotAnError(t *testing.T) {
	r, err := Read(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || r != nil {
		t.Fatalf("文件不存在应返回 (nil, nil),得到 (%v, %v)", r, err)
	}
}

func TestWriteReadRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "rollout.json")
	in := Begin(nil, "7594f5743a6f", "f9f7894ff7dc", at("2026-08-25T09:00:00Z"))
	if err := in.Write(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Error("临时文件没被 rename 掉")
	}
	out, err := Read(p)
	if err != nil || out == nil || out.Snapshot != "7594f5743a6f" || out.Stage != Staging {
		t.Fatalf("读回来的不对:%+v(err=%v)", out, err)
	}
}

// 这是本文件的**主要理由**:失败时 LastGood 必须不动,它是回退目标。
// 动了的话,回退会指向那份刚刚失败的快照。
func TestFailureKeepsLastGood(t *testing.T) {
	r := Begin(nil, "aaa", "", at("2026-08-25T09:00:00Z"))
	r.Enter(Activating, at("2026-08-25T09:00:10Z"))
	r.Enter(Verifying, at("2026-08-25T09:00:20Z"))
	r.Enter(Verified, at("2026-08-25T09:00:30Z"))
	if r.LastGood != "aaa" {
		t.Fatalf("Verified 之后 LastGood 应是 aaa,得到 %q", r.LastGood)
	}

	next := Begin(r, "bbb", "", at("2026-08-25T10:00:00Z"))
	if next.LastGood != "aaa" {
		t.Fatalf("新一轮必须继承回退目标,得到 %q", next.LastGood)
	}
	next.Enter(Activating, at("2026-08-25T10:00:10Z"))
	next.Fail(errors.New("装到一半炸了"), at("2026-08-25T10:00:20Z"))
	if next.LastGood != "aaa" {
		t.Fatalf("失败后 LastGood 必须仍是 aaa,得到 %q", next.LastGood)
	}
	if next.Error == "" {
		t.Error("失败要记原因")
	}
}

// **装上了不算,跑起来了才算。** 只有 Verified 推进 LastGood ——
// 否则回退目标会指向一份装得上但跑不了的快照。
func TestOnlyVerifiedAdvancesLastGood(t *testing.T) {
	r := Begin(nil, "aaa", "", at("2026-08-25T09:00:00Z"))
	for _, s := range []Stage{Activating, Verifying} {
		r.Enter(s, at("2026-08-25T09:00:10Z"))
		if r.LastGood != "" {
			t.Fatalf("到 %s 就推进 LastGood 是错的,得到 %q", s, r.LastGood)
		}
	}
	r.Enter(Verified, at("2026-08-25T09:00:20Z"))
	if r.LastGood != "aaa" {
		t.Fatalf("Verified 才该推进,得到 %q", r.LastGood)
	}
}

func TestStepsRecordDuration(t *testing.T) {
	r := Begin(nil, "aaa", "", at("2026-08-25T09:00:00Z"))
	r.Enter(Activating, at("2026-08-25T09:00:07Z"))
	if len(r.Steps) != 1 || r.Steps[0].Stage != Staging || r.Steps[0].MS != 7000 {
		t.Fatalf("应记下 staging 用了 7000ms,得到 %+v", r.Steps)
	}
}

func TestInFlightAndTerminal(t *testing.T) {
	for _, c := range []struct {
		s    Stage
		want bool
	}{
		{Staging, true}, {Activating, true}, {Verifying, true},
		{Verified, false}, {Decommissioned, false}, {Failed, false},
	} {
		if got := (&Record{Stage: c.s}).InFlight(); got != c.want {
			t.Errorf("%s 的 InFlight 应为 %v", c.s, c.want)
		}
	}
}

func TestDecommissionedIsSuccessfulTerminalWithoutAdvancingLastGood(t *testing.T) {
	prev := &Record{Snapshot: "old", Stage: Verified, LastGood: "old"}
	r := Begin(prev, "signed-decommission", "", at("2026-08-25T09:00:00Z"))
	r.Enter(Decommissioned, at("2026-08-25T09:00:01Z"))
	if r.InFlight() || r.Stage != Decommissioned {
		t.Fatalf("decommission 应是终态:%+v", r)
	}
	if r.LastGood != "old" {
		t.Fatalf("下线不应把无 applied 的快照推进为 LastGood:%q", r.LastGood)
	}
}

// 卡住的判据是**进入当前阶段有多久**,不是整次 rollout 多久 ——
// 一次正常的二进制升级本来就要走好几步。
func TestStuckMeasuresCurrentStageNotTotal(t *testing.T) {
	r := &Record{
		Stage:     Activating,
		StartedAt: "2026-08-25T09:00:00Z", // 整体已经一小时
		EnteredAt: "2026-08-25T09:59:00Z", // 但这一步才一分钟
	}
	now := at("2026-08-25T10:00:00Z")
	if r.Stuck(now, 5*time.Minute) {
		t.Error("这一步才 1 分钟,不该算卡住")
	}
	r.EnteredAt = "2026-08-25T09:50:00Z" // 这一步十分钟
	if !r.Stuck(now, 5*time.Minute) {
		t.Error("这一步 10 分钟,超过 5 分钟上限,该算卡住")
	}
	// 终态永远不算卡住。
	r.Stage = Failed
	if r.Stuck(now, time.Second) {
		t.Error("终态不该算卡住")
	}
}

// 空路径 = 明确关掉记录。dry-run 靠它做到"没有副作用" ——
// 否则演练会留下一条停在 activating 的记录,而面板会把它报成卡住。
func TestEmptyPathDisablesRecording(t *testing.T) {
	r, err := Read("")
	if err != nil || r != nil {
		t.Fatalf("空路径应安静地返回 (nil, nil),得到 (%v, %v)", r, err)
	}
	rec := Begin(nil, "aaa", "", at("2026-08-25T09:00:00Z"))
	if err := rec.Write(""); err != nil {
		t.Fatalf("空路径写入应是 no-op,得到 %v", err)
	}
}

// 亚秒级的步长必须记准。秒级时间戳下,两个 482ms 的步会被记成一模一样
// 的数 —— 因为都是从同一个被截断的秒起算的。实测在真机上撞到过。
func TestSubSecondStepsAreMeasuredCorrectly(t *testing.T) {
	base := at("2026-08-25T10:51:15Z")
	r := Begin(nil, "aaa", "", base.Add(800*time.Millisecond))
	r.Enter(Activating, base.Add(920*time.Millisecond)) // 真实 120ms
	r.Enter(Verifying, base.Add(1400*time.Millisecond)) // 真实 480ms

	if len(r.Steps) != 2 {
		t.Fatalf("应有 2 步,得到 %d", len(r.Steps))
	}
	if r.Steps[0].MS != 120 {
		t.Errorf("staging 真实 120ms,记成了 %dms", r.Steps[0].MS)
	}
	if r.Steps[1].MS != 480 {
		t.Errorf("activating 真实 480ms,记成了 %dms", r.Steps[1].MS)
	}
}

// 旧记录是秒级的,新代码必须照样读得懂 —— 解析侧用 RFC3339 layout,
// 它同时认得带小数秒和不带的。
func TestSecondGranularityRecordsStillParse(t *testing.T) {
	r := &Record{Stage: Activating, EnteredAt: "2026-08-25T10:51:15Z"}
	if !r.Stuck(at("2026-08-25T11:30:00Z"), 5*time.Minute) {
		t.Error("秒级旧记录应该照样能算出卡了多久")
	}
}
