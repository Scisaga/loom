package agent

import (
	"strings"
	"testing"
	"time"

	"loom/internal/measure"
	"loom/internal/model"
)

func decl(o model.Objective, minS int, thr float64, tags ...string) *Decl {
	d := &Decl{ID: "d", Selector: "decl:d", Objective: o, MinSamples: minS, SwitchThreshold: thr}
	for _, t := range tags {
		d.Candidates = append(d.Candidates, Cand{Tag: t, ProbeUser: "u-" + t})
	}
	return d
}

func sum(tag string, samples, failures, p50, p95 int) measure.Summary {
	return measure.Summary{CandidateID: tag, Declaration: "d",
		Samples: samples, Failures: failures, P50: p50, P95: p95}
}

func withKBps(s measure.Summary, kbps int) measure.Summary { s.KBps = kbps; return s }

// 这是 Agent 存在的首要理由:sing-box 每次重启,selector 都回到 default,
// 而实测 default(直连)对 best-egress 的目标完全不通。停在一条已经证明
// 打不通的路上,不该被 min_samples 或 switch_threshold 拦住 —— 阻尼是为了
// 防止在两个能用的候选之间横跳,不是为了守着一具尸体。
func TestSwitchesAwayFromDeadCandidateImmediately(t *testing.T) {
	d := decl(model.Latency, 20, 0.2, "direct", "edge-a")
	got := Decide(d, "direct", []measure.Summary{
		sum("direct", 3, 3, 0, 0), // 3 次全失败
		sum("edge-a", 3, 0, 800, 900),
	})
	if !got.Switch || got.Choice != "edge-a" {
		t.Fatalf("当前候选全部失败却没切:%+v", got)
	}
	if !strings.Contains(got.Reason, "全部失败") {
		t.Errorf("理由没说清是因为失败:%q", got.Reason)
	}
}

// 反面:两个都能用时,样本不够就不许切 —— 否则头几次探测的噪声会决定路由。
func TestColdStartDoesNotSwitchBetweenHealthyCandidates(t *testing.T) {
	d := decl(model.Latency, 20, 0.2, "cn-a", "edge-a")
	got := Decide(d, "cn-a", []measure.Summary{
		sum("cn-a", 2, 0, 900, 950),
		sum("edge-a", 2, 0, 100, 120), // 快得多,但只有 2 个样本
	})
	if got.Switch {
		t.Fatalf("样本不足 min_samples 却切了:%+v", got)
	}
	if !strings.Contains(got.Reason, "min_samples") {
		t.Errorf("理由没说清是样本不够:%q", got.Reason)
	}
}

// §5.5 的阻尼:小幅领先不足以切。没有它,两条延迟接近的链路会一直互相顶掉。
func TestDampingBlocksMarginalImprovement(t *testing.T) {
	d := decl(model.Latency, 3, 0.2, "a", "b")
	got := Decide(d, "a", []measure.Summary{
		sum("a", 5, 0, 100, 120),
		sum("b", 5, 0, 90, 110), // 好 10%,阈值 20%
	})
	if got.Switch {
		t.Fatalf("仅好 10%% 却切了:%+v", got)
	}
	if !strings.Contains(got.Reason, "未过阈值") {
		t.Errorf("理由没说清是被阈值挡住:%q", got.Reason)
	}
	// 好 40% 就该切了。
	got = Decide(d, "a", []measure.Summary{
		sum("a", 5, 0, 100, 120),
		sum("b", 5, 0, 60, 70),
	})
	if !got.Switch || got.Choice != "b" {
		t.Fatalf("好 40%% 却没切:%+v", got)
	}
}

// 失败率必须压过目标指标:一条一半请求出错但很快的链路,不该赢过一条
// 全部成功但慢一点的。把失败折算成"很慢"就会得出相反结论。
func TestFailureRateOutranksSpeed(t *testing.T) {
	d := decl(model.Latency, 3, 0.0, "flaky", "solid")
	got := Decide(d, "solid", []measure.Summary{
		sum("flaky", 10, 5, 50, 60),   // 快一倍,但一半失败
		sum("solid", 10, 0, 100, 120), // 慢,但从不失败
	})
	if got.Switch {
		t.Fatalf("切到了半数失败的候选:%+v", got)
	}
}

// §5.5 小于旧 10% 分档的差异也必须优先于速度；现任样本不足不能绕过这一规则。
func TestFailureRateAlwaysPrecedesObjective(t *testing.T) {
	for _, objective := range []model.Objective{model.Latency, model.Stability, model.Throughput} {
		for _, tc := range []struct {
			name                                                                   string
			currentSamples, currentFailures, challengerSamples, challengerFailures int
		}{
			{"same old tier", 100, 0, 100, 9},
			{"nonzero same old tier", 100, 11, 100, 19},
			{"current below min samples", 2, 0, 10, 5},
			{"current below min and same old tier", 2, 0, 100, 1},
		} {
			t.Run(string(objective)+"/"+tc.name, func(t *testing.T) {
				d := decl(objective, 3, 0.2, "solid", "flaky")
				sums := []measure.Summary{
					withKBps(sum("solid", tc.currentSamples, tc.currentFailures, 900, 950), 100),
					withKBps(sum("flaky", tc.challengerSamples, tc.challengerFailures, 50, 60), 2000),
				}
				if got := Decide(d, "solid", sums); got.Switch || got.Choice != "solid" {
					t.Fatalf("higher failure rate won on speed: %+v", got)
				}
				if got := Decide(d, "", sums); !got.Switch || got.Choice != "solid" {
					t.Fatalf("initial ranking chose higher failure rate: %+v", got)
				}
				if tc.currentSamples >= d.MinSamples {
					if got := Decide(d, "flaky", sums); !got.Switch || got.Choice != "solid" {
						t.Fatalf("lower failure rate lost to latency threshold: %+v", got)
					}
				}
			})
		}
	}
}

func TestEqualFailureRatiosKeepObjectiveDamping(t *testing.T) {
	d := decl(model.Latency, 3, 0.2, "a", "b")
	for _, tc := range []struct {
		p50        int
		wantSwitch bool
	}{{90, false}, {60, true}} {
		got := Decide(d, "a", []measure.Summary{sum("a", 10, 1, 100, 120), sum("b", 20, 2, tc.p50, 110)})
		if got.Switch != tc.wantSwitch {
			t.Fatalf("equal failure ratios bypassed damping: %+v", got)
		}
	}
}

// stability 看 p95 而不是 p50 —— p50 好看、p95 很差的链路正是它要避开的。
func TestStabilityRanksByTail(t *testing.T) {
	d := decl(model.Stability, 3, 0.2, "spiky", "even")
	got := Decide(d, "spiky", []measure.Summary{
		sum("spiky", 10, 0, 50, 2000), // p50 更好,p95 灾难
		sum("even", 10, 0, 90, 120),
	})
	if !got.Switch || got.Choice != "even" {
		t.Fatalf("stability 没有按尾部选:%+v", got)
	}
}

// 当前选择不在候选集里(配置变了),必须切回来,否则流量停在一个
// 已经没人维护的出站上。
func TestSwitchesWhenCurrentNotInCandidateSet(t *testing.T) {
	d := decl(model.Latency, 20, 0.2, "a", "b")
	got := Decide(d, "removed", []measure.Summary{sum("a", 1, 0, 300, 300)})
	if !got.Switch || got.Choice != "a" {
		t.Fatalf("当前选择已不存在却没切:%+v", got)
	}
}

// 全都不通时保持不动:乱切没有意义,而且会掩盖"整条声明都挂了"这件事。
func TestNoSwitchWhenNothingWorks(t *testing.T) {
	d := decl(model.Latency, 1, 0.2, "a", "b")
	got := Decide(d, "a", []measure.Summary{sum("a", 3, 3, 0, 0), sum("b", 3, 3, 0, 0)})
	if got.Switch {
		t.Fatalf("全部失败时切了:%+v", got)
	}
}

// 不切也必须有理由 —— 否则日志里"没动"和"没跑"分不出来。
func TestEveryDecisionHasAReason(t *testing.T) {
	d := decl(model.Latency, 3, 0.2, "a", "b")
	for _, sums := range [][]measure.Summary{
		nil,
		{sum("a", 3, 3, 0, 0)},
		{sum("a", 5, 0, 100, 100), sum("b", 5, 0, 99, 99)},
		{sum("a", 5, 0, 100, 100), sum("b", 5, 0, 10, 10)},
	} {
		if got := Decide(d, "a", sums); got.Reason == "" {
			t.Errorf("这组输入没有给出理由:%+v", sums)
		}
	}
}

// 不能执行的 objective 必须显式拒绝,不能拿 L4 首字节时间冒充。
func TestUnsupportedObjectivesAreRefused(t *testing.T) {
	for _, o := range []model.Objective{model.TTFT, model.Cost} {
		if ok, why := Supported(o); ok || why == "" {
			t.Errorf("%s 被当成可执行的,或没给理由", o)
		}
	}
	for _, o := range []model.Objective{model.Latency, model.Stability, model.Throughput} {
		if ok, _ := Supported(o); !ok {
			t.Errorf("%s 应该可执行", o)
		}
	}
}

func TestInWindowDropsOldAndStale(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	const node, scope = "n", "scope"
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	ms := []measure.Measurement{
		{TS: at(90 * time.Minute), Node: node, DecisionScope: scope, Declaration: "d", CandidateID: "old", FirstByteMs: 1},
		{TS: at(5 * time.Minute), Node: node, DecisionScope: scope, Declaration: "d", CandidateID: "fresh", FirstByteMs: 2},
		{TS: now.Add(time.Hour).Format(time.RFC3339), Node: node, DecisionScope: scope, Declaration: "d", CandidateID: "future", FirstByteMs: 99},
		{TS: at(5 * time.Minute), Node: node, DecisionScope: scope, Declaration: "other", CandidateID: "fresh", FirstByteMs: 3},
		// 窗口内有样本,但这条候选最新的一笔已经超过 stale_after
		{TS: at(50 * time.Minute), Node: node, DecisionScope: scope, Declaration: "d", CandidateID: "stale", FirstByteMs: 4},
	}
	got := inWindow(ms, node, "d", scope, now, time.Hour, 30*time.Minute)
	if len(got) != 1 || got[0].CandidateID != "fresh" {
		t.Fatalf("窗口过滤结果不对:%+v", got)
	}
}

// 首字节和吞吐会给出**相反**的排序。实测:edge-a 首字节排第 4(956ms),
// 按拉完 2MB 的真实耗时排第 2 —— 因为它的吞吐是排它前面那条的 3 倍。
// 每多一跳吞吐掉到四分之一,而首字节完全看不出这件事。
func TestThroughputRanksBySpeedNotLatency(t *testing.T) {
	d := decl(model.Throughput, 3, 0.2, "fast-connect", "fast-transfer")
	got := Decide(d, "fast-connect", []measure.Summary{
		withKBps(sum("fast-connect", 10, 0, 400, 500), 250),    // 连得快,传得慢(两跳)
		withKBps(sum("fast-transfer", 10, 0, 900, 1000), 2000), // 连得慢,传得快(一跳)
	})
	if !got.Switch || got.Choice != "fast-transfer" {
		t.Fatalf("按吞吐排序却选了连得快的那条:%+v", got)
	}
	if !strings.Contains(got.Reason, "KB/s") {
		t.Errorf("理由里没有吞吐数字:%q", got.Reason)
	}
	// 同一批数据按 latency 排,应当选另一条 —— 两个 objective 本来就该分道扬镳。
	dl := decl(model.Latency, 3, 0.2, "fast-connect", "fast-transfer")
	if g := Decide(dl, "fast-connect", []measure.Summary{
		withKBps(sum("fast-connect", 10, 0, 400, 500), 250),
		withKBps(sum("fast-transfer", 10, 0, 900, 1000), 2000),
	}); g.Switch {
		t.Errorf("按延迟排序不该切到传得快但连得慢的那条:%+v", g)
	}
}

// 没有吞吐数据的候选不能因为"没数据"而赢下一个按吞吐排序的声明。
// 探测目标只返回几百字节时就是这种情况。
func TestNoThroughputDataDoesNotWin(t *testing.T) {
	d := decl(model.Throughput, 3, 0.2, "measured", "unmeasured")
	got := Decide(d, "measured", []measure.Summary{
		withKBps(sum("measured", 10, 0, 500, 600), 300),
		sum("unmeasured", 10, 0, 100, 120), // 连得快,但没吞吐数据
	})
	if got.Switch {
		t.Fatalf("切到了没有吞吐数据的候选:%+v", got)
	}
}

// 按吞吐排序却一条都测不出吞吐:这不是"大家一样好",是测不出来。
// 让它们并列最差的话,排序会退化成按候选名字排 —— 看起来在工作,实际在乱选。
func TestThroughputWithNoDataRefusesToRank(t *testing.T) {
	d := decl(model.Throughput, 3, 0.2, "a", "b")
	got := Decide(d, "a", []measure.Summary{
		sum("a", 10, 0, 500, 600), // 都成功,但都没有吞吐数据
		sum("b", 10, 0, 100, 120),
	})
	if got.Switch {
		t.Fatalf("没有吞吐数据却切了:%+v", got)
	}
	if !strings.Contains(got.Reason, "32KB") {
		t.Errorf("理由没说清是目标返回内容太少:%q", got.Reason)
	}
}
