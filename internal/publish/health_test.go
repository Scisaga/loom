package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// 这是本文件的**主要理由**:2026-08-24 发布器连续 2 小时 17 分发不出东西,
// 而 systemd 全程 active。这个形状必须被判成 bad。
func TestFailingSinceLastSuccessIsBad(t *testing.T) {
	h := &Health{
		PID: os.Getpid(), UpdatedAt: "2026-08-24T22:19:30Z", IntervalSeconds: 30,
		LastSuccess: "2026-08-24T19:43:24Z", LastSnapshot: "6f85b31d089a",
		LastError:   "解析 SSOT:field retired_ports not found in type model.Tunnel",
		LastErrorAt: "2026-08-24T22:08:43Z",
	}
	lines, bad := h.Findings(at("2026-08-24T22:20:00Z"))
	if !bad {
		t.Fatal("上次成功之后一直失败,必须判成 bad")
	}
	got := strings.Join(lines, "\n")
	if !strings.Contains(got, "retired_ports") {
		t.Errorf("要印出失败原因:\n%s", got)
	}
	if !strings.Contains(got, "active 不代表功能活着") {
		t.Errorf("要点明进程活着与功能活着的区别:\n%s", got)
	}
}

// **反过来同样重要:SSOT 一周不改就一周不发,那是正常的。**
// 拿"距上次成功多久"当告警会天天误报,而误报的面板等于没有面板。
func TestLongQuietPeriodIsNotAnAlarm(t *testing.T) {
	h := &Health{
		PID: os.Getpid(), UpdatedAt: "2026-08-25T09:59:30Z", IntervalSeconds: 30,
		LastSuccess: "2026-08-18T10:00:00Z", LastSnapshot: "abc123def456",
	}
	lines, bad := h.Findings(at("2026-08-25T10:00:00Z")) // 七天没动静
	if bad {
		t.Fatalf("七天没改 SSOT 不是故障:\n%s", strings.Join(lines, "\n"))
	}
	if !strings.Contains(strings.Join(lines, "\n"), "7 天") &&
		!strings.Contains(strings.Join(lines, "\n"), "168 小时") {
		t.Logf("时长显示:%s", strings.Join(lines, "\n"))
	}
}

// 失败之后又成功了:不该报警,但历史要留着。
func TestRecoveredErrorIsShownButNotAnAlarm(t *testing.T) {
	h := &Health{
		PID: os.Getpid(), UpdatedAt: "2026-08-24T22:29:30Z", IntervalSeconds: 30,
		LastSuccess: "2026-08-24T22:25:40Z", LastSnapshot: "7594f5743a6f",
		LastError:   "解析 SSOT:field retired_ports not found",
		LastErrorAt: "2026-08-24T22:08:43Z",
	}
	lines, bad := h.Findings(at("2026-08-24T22:30:00Z"))
	if bad {
		t.Fatal("已经恢复了,不该继续报警")
	}
	if !strings.Contains(strings.Join(lines, "\n"), "之后已恢复") {
		t.Errorf("恢复了也要留着历史:\n%s", strings.Join(lines, "\n"))
	}
}

func TestNeverPublishedIsBad(t *testing.T) {
	_, bad := (&Health{PID: os.Getpid(), UpdatedAt: "2026-08-25T09:59:30Z"}).Findings(at("2026-08-25T10:00:00Z"))
	if !bad {
		t.Fatal("一次都没成功过必须判成 bad")
	}
}

func TestStaleHeartbeatIsBadEvenAfterSuccessfulPublish(t *testing.T) {
	h := &Health{
		PID: os.Getpid(), UpdatedAt: "2026-08-25T09:55:00Z", IntervalSeconds: 30,
		LastSuccess: "2026-08-25T09:50:00Z", LastSnapshot: "abc123def456",
	}
	lines, bad := h.Findings(at("2026-08-25T10:00:00Z"))
	if !bad {
		t.Fatal("心跳过期必须判成 bad,否则进程死后状态会永久假绿")
	}
	if !strings.Contains(strings.Join(lines, "\n"), "心跳已过期") {
		t.Fatalf("应明确指出是心跳过期:\n%s", strings.Join(lines, "\n"))
	}
}

func TestDeadPublisherPIDIsBadImmediately(t *testing.T) {
	h := &Health{
		PID: 1 << 30, UpdatedAt: "2026-08-25T09:59:59Z", IntervalSeconds: 30,
		LastSuccess: "2026-08-25T09:50:00Z", LastSnapshot: "abc123def456",
	}
	lines, bad := h.Findings(at("2026-08-25T10:00:00Z"))
	if !bad || !strings.Contains(strings.Join(lines, "\n"), "已不存在") {
		t.Fatalf("PID 已消失应立即报错:\n%s", strings.Join(lines, "\n"))
	}
}

func TestFailureLaterInSameSecondIsNotHidden(t *testing.T) {
	h := &Health{
		PID: os.Getpid(), UpdatedAt: "2026-08-25T10:00:00.300Z", IntervalSeconds: 30,
		LastSuccess: "2026-08-25T10:00:00.100Z", LastSnapshot: "abc123def456",
		LastError: "verify failed", LastErrorAt: "2026-08-25T10:00:00.200Z",
	}
	lines, bad := h.Findings(at("2026-08-25T10:00:01Z"))
	if !bad || !strings.Contains(strings.Join(lines, "\n"), "一直发不出去") {
		t.Fatalf("同一秒内较晚的失败不能被秒级比较吞掉:\n%s", strings.Join(lines, "\n"))
	}
}

// 读不到文件是"发布器没在这台机器上跑",不是错误。
func TestReadHealthAbsentIsNotAnError(t *testing.T) {
	h, err := ReadHealth(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || h != nil {
		t.Fatalf("文件不存在应返回 (nil, nil),得到 (%v, %v)", h, err)
	}
}

// 原子写:读的人要么看到完整的旧版本,要么看到完整的新版本。
func TestWriteIsAtomicAndRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "publisher.json")
	in := &Health{PID: 42, StartedAt: "2026-08-25T00:00:00Z", LastSnapshot: "abc"}
	if err := in.Write(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Error("临时文件没有被 rename 掉")
	}
	out, err := ReadHealth(p)
	if err != nil || out == nil || out.PID != 42 || out.LastSnapshot != "abc" {
		t.Fatalf("读回来的不对:%+v(err=%v)", out, err)
	}
}
