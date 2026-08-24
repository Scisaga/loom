package agent

import (
	"testing"
	"time"

	"loom/internal/report"
)

func TestExitOfPicksTheLastHop(t *testing.T) {
	cases := map[string]string{
		"cand:best-egress:direct":              "SELF",
		"cand:best-egress:cn-a":                "cn-a",
		"cand:best-egress:cn-a>edge-a":         "edge-a",
		"cand:sg-fixed:cn-b>cn-a>edge-a":       "edge-a",
		"cand:llm:cn-a>edge-a@api.example.com": "edge-a",
	}
	for tag, want := range cases {
		if got := exitOf(tag, "SELF"); got != want {
			t.Errorf("%s 的出口算成 %q,期望 %q", tag, got, want)
		}
	}
}

// 三个状态必须分清:已知能到、已知不能到、**不知道**。
// 把"不知道"当成"不能到",一台刚加进来还没被观测过的服务器会永远不被尝试。
func TestUnknownIsNotTreatedAsUnreachable(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	o := newObserved()
	o.put(&report.Observation{
		Node: "cn-a", TS: now.Add(-time.Minute).Format(time.RFC3339),
		Targets: []report.Reach{{Target: "https://t/", Error: "connection refused"}},
	})
	o.put(&report.Observation{
		Node: "edge-a", TS: now.Add(-time.Minute).Format(time.RFC3339),
		Targets: []report.Reach{{Target: "https://t/", FirstByteMs: 300}},
	})
	dead := o.unreachable("https://t/", now, 15*time.Minute)
	if _, bad := dead["cn-a"]; !bad {
		t.Error("cn-a 明确打不到,却没被剪")
	}
	if _, bad := dead["edge-a"]; bad {
		t.Error("edge-a 能到,却被剪了")
	}
	if _, bad := dead["从没听说过的机器"]; bad {
		t.Error("没有观测的节点被当成打不到 —— 新加的服务器会永远不被尝试")
	}
	// 另一个目标不受影响:可达性是 (节点, 目标) 的属性,不是节点的属性。
	if len(o.unreachable("https://别的目标/", now, 15*time.Minute)) != 0 {
		t.Error("一个目标的失败被算到了另一个目标头上")
	}
}

// 过期的观测必须丢掉,不能拿来剪枝 —— 一份 15 分钟前的"打不到"比没有更危险。
func TestStaleObservationsAreIgnored(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	o := newObserved()
	o.put(&report.Observation{
		Node: "cn-a", TS: now.Add(-time.Hour).Format(time.RFC3339),
		Targets: []report.Reach{{Target: "https://t/", Error: "refused"}},
	})
	if len(o.unreachable("https://t/", now, 15*time.Minute)) != 0 {
		t.Error("一小时前的观测还被用来剪枝")
	}
}

// 转述会让同一份观测从多条路径回来。只保留最新的一份,否则表会无限长大。
func TestKeepsOnlyNewestPerObserver(t *testing.T) {
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	o := newObserved()
	o.put(&report.Observation{Node: "cn-a", TS: base.Format(time.RFC3339),
		Targets: []report.Reach{{Target: "https://t/", Error: "旧"}}})
	o.put(&report.Observation{Node: "cn-a", TS: base.Add(time.Minute).Format(time.RFC3339),
		Targets: []report.Reach{{Target: "https://t/", FirstByteMs: 100}}})
	// 旧的再来一次也不该覆盖新的
	o.put(&report.Observation{Node: "cn-a", TS: base.Format(time.RFC3339),
		Targets: []report.Reach{{Target: "https://t/", Error: "旧"}}})
	if o.len() != 1 {
		t.Fatalf("同一个观测者存了 %d 份", o.len())
	}
	if len(o.unreachable("https://t/", base.Add(2*time.Minute), 15*time.Minute)) != 0 {
		t.Error("旧的失败观测覆盖了新的成功观测")
	}
}
