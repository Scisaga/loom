package main

import (
	"strings"
	"testing"
	"time"

	"loom/internal/report"
	"loom/internal/rollout"
)

func rs(stage rollout.Stage, entered string) *report.RolloutState {
	return &report.RolloutState{Snapshot: "7594f5743a6f", Stage: string(stage), EnteredAt: entered}
}

func now() time.Time {
	t, _ := time.Parse(time.RFC3339, "2026-08-25T10:00:00Z")
	return t
}

// 终态不该出现在面板上 —— 装完了就是装完了,天天报"已完成"是噪音。
func TestVerifiedIsSilent(t *testing.T) {
	lines, bad := rolloutFindings(map[string]*report.RolloutState{
		"demo-d": rs(rollout.Verified, "2026-08-25T09:00:00Z"),
	}, now())
	if len(lines) != 0 || bad != 0 {
		t.Fatalf("Verified 不该输出任何东西,得到 bad=%d:\n%s", bad, strings.Join(lines, "\n"))
	}
}

func TestDecommissionedIsShownWithoutAlarm(t *testing.T) {
	lines, bad := rolloutFindings(map[string]*report.RolloutState{
		"old01": rs(rollout.Decommissioned, "2026-08-24T09:00:00Z"),
	}, now())
	got := strings.Join(lines, "\n")
	if bad != 0 || !strings.Contains(got, "已按签名快照") || !strings.Contains(got, "old01") {
		t.Fatalf("有意下线应明确展示但不报警,bad=%d:\n%s", bad, got)
	}
}

// 正在装是正常的,说一声但**不报警** —— 否则每次发布都会响一片。
func TestInFlightIsShownButNotAnAlarm(t *testing.T) {
	lines, bad := rolloutFindings(map[string]*report.RolloutState{
		"demo-e": rs(rollout.Activating, "2026-08-25T09:58:00Z"), // 才两分钟
	}, now())
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "正在") || !strings.Contains(got, "demo-e") {
		t.Fatalf("正在装的要说出来:\n%s", got)
	}
	if bad != 0 {
		t.Fatalf("正在装不是故障,bad 应为 0,得到 %d", bad)
	}
}

// 这是本文件的**主要理由**:卡了很久必须报出来。
// 只看 Applied 的话,这台机器看起来只是"还没轮到它"。
func TestStuckIsAnAlarm(t *testing.T) {
	lines, bad := rolloutFindings(map[string]*report.RolloutState{
		"demo-c": rs(rollout.Activating, "2026-08-25T08:00:00Z"), // 两小时
	}, now())
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "卡在") || !strings.Contains(got, "demo-c") {
		t.Fatalf("卡住必须报出来:\n%s", got)
	}
	if bad != 1 {
		t.Fatalf("卡住是故障,bad 应为 1,得到 %d", bad)
	}
}

// 失败要带上回退目标 —— 救火时第一个要问的就是"能退到哪"。
func TestFailedShowsRollbackTarget(t *testing.T) {
	r := rs(rollout.Failed, "2026-08-25T09:00:00Z")
	r.Error = "安装失败(已回滚):exit status 1"
	r.LastGood = "6f85b31d089a"
	lines, bad := rolloutFindings(map[string]*report.RolloutState{"demo-a": r}, now())
	got := strings.Join(lines, "\n")
	for _, want := range []string{"失败", "exit status 1", "6f85b31d089a"} {
		if !strings.Contains(got, want) {
			t.Errorf("失败信息少了 %q:\n%s", want, got)
		}
	}
	if bad != 1 {
		t.Errorf("失败应计入 bad,得到 %d", bad)
	}
}

// 时间戳读不出来时**不能装作刚进来** —— 那会把一台卡死的机器
// 显示成"正在装 0 秒",而这正是面板说谎的形状。
func TestUnparseableTimestampIsReportedNotGuessed(t *testing.T) {
	lines, bad := rolloutFindings(map[string]*report.RolloutState{
		"demo-b": rs(rollout.Staging, "不是时间"),
	}, now())
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "算不出") {
		t.Fatalf("算不出时长要说出来,而不是当成 0:\n%s", got)
	}
	if bad != 1 {
		t.Fatalf("状态读不出来是故障,得到 bad=%d", bad)
	}
}

// 阈值边界:恰好等于上限不算卡住,超过才算。
func TestStuckThresholdBoundary(t *testing.T) {
	exact := now().Add(-stuckLimit).UTC().Format(time.RFC3339)
	if _, bad := rolloutFindings(map[string]*report.RolloutState{
		"demo-d": rs(rollout.Verifying, exact),
	}, now()); bad != 0 {
		t.Errorf("恰好等于上限不该算卡住,得到 bad=%d", bad)
	}
	over := now().Add(-stuckLimit - time.Second).UTC().Format(time.RFC3339)
	if _, bad := rolloutFindings(map[string]*report.RolloutState{
		"demo-d": rs(rollout.Verifying, over),
	}, now()); bad != 1 {
		t.Errorf("超过上限该算卡住,得到 bad=%d", bad)
	}
}

// 一次正常的二进制升级不能被报成卡住。
//
// 下载落在 activating 里；慢链路下载较大制品可能持续数分钟。
// 阈值调到分钟以内的话,每次升级都会误报 —— 而误报的面板等于没有面板。
func TestNormalBinaryUpgradeIsNotReportedAsStuck(t *testing.T) {
	// 构造进入 activating 已经 3 分钟、仍在下载的慢链路场景。
	entered := now().Add(-3 * time.Minute).UTC().Format(time.RFC3339Nano)
	lines, bad := rolloutFindings(map[string]*report.RolloutState{
		"demo-e": rs(rollout.Activating, entered),
	}, now())
	if bad != 0 {
		t.Fatalf("正常的二进制升级不该报警:\n%s", strings.Join(lines, "\n"))
	}
	if !strings.Contains(strings.Join(lines, "\n"), "正在") {
		t.Errorf("但要说它在进行中:\n%s", strings.Join(lines, "\n"))
	}
}
