package measure

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPercentileRoundsUp:小样本下 p95 必须偏向最大值。
//
// 向下取整会让 p95 在三个样本时等于 p50,看起来像"很稳定" —— 而那只是
// 样本不够。排序时把它当成稳定就会选错。
func TestPercentileRoundsUp(t *testing.T) {
	three := []int{100, 200, 900}
	if got := percentile(three, 50); got != 200 {
		t.Errorf("p50 = %d,期望 200", got)
	}
	if got := percentile(three, 95); got != 900 {
		t.Errorf("p95 = %d,期望 900(三个样本谈不上 p95,取最大值才诚实)", got)
	}
	if got := percentile([]int{42}, 95); got != 42 {
		t.Errorf("单样本 p95 = %d,期望 42", got)
	}
	if got := percentile(nil, 50); got != 0 {
		t.Errorf("空样本应返回 0,得到 %d", got)
	}
}

// TestFailuresDoNotPolluteQuantiles:失败不能被当成"很慢"混进分位数。
//
// 一条 100% 超时的候选若被记成"延迟很高",排序时仍会排在某些候选之前;
// 记成失败才能被过滤掉。
func TestFailuresDoNotPolluteQuantiles(t *testing.T) {
	ms := []Measurement{
		{CandidateID: "a", Declaration: "d", FirstByteMs: 100},
		{CandidateID: "a", Declaration: "d", FirstByteMs: 120},
		{CandidateID: "a", Declaration: "d", Error: "timeout"},
		{CandidateID: "b", Declaration: "d", Error: "timeout"},
		{CandidateID: "b", Declaration: "d", Error: "timeout"},
	}
	got := Summarize(ms)
	if len(got) != 2 {
		t.Fatalf("期望 2 条汇总,得到 %d", len(got))
	}
	// 有成功样本的必须排在全失败的前面。
	if got[0].CandidateID != "a" {
		t.Errorf("排序错了:全失败的候选不该排在有成功样本的前面,得到 %q", got[0].CandidateID)
	}
	if got[0].Samples != 3 || got[0].Failures != 1 {
		t.Errorf("a: 样本 %d 失败 %d,期望 3/1", got[0].Samples, got[0].Failures)
	}
	if got[0].P50 != 120 {
		t.Errorf("a 的 p50 = %d —— 失败样本混进分位数了", got[0].P50)
	}
	if got[1].Samples != got[1].Failures {
		t.Errorf("b 应当是全失败")
	}
	if got[1].P50 != 0 {
		t.Errorf("全失败的候选不该有分位数,得到 %d", got[1].P50)
	}
}

// TestObservationPointIsRecorded:不同观测点的数据不可直接比较(§16.2),
// 所以每条记录都必须带上它是从哪儿看到的。
func TestObservationPointIsRecorded(t *testing.T) {
	m := Measurement{Point: L4Tunnel, Kind: Active}
	if m.Point == "" || m.Kind == "" {
		t.Error("观测点与探测方式都必须记录")
	}
	if m.FirstByteMs != 0 {
		t.Error("零值不该被当成有效测量")
	}
}

func TestLegacyMeasurementJSONRemainsReadableWithoutInventingScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "measurements.jsonl")
	legacy := []byte(`{"ts":"2026-09-07T12:00:00Z","node":"n","candidate_id":"a","declaration_id":"d","first_byte_ms":12,"observation_point":"l4_tunnel","observation_kind":"active"}` + "\n")
	if err := os.WriteFile(path, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("legacy JSONL no longer loads:%v", err)
	}
	if len(got) != 1 || got[0].CandidateID != "a" || got[0].DecisionScope != "" {
		t.Fatalf("legacy sample was changed or assigned a false scope:%+v", got)
	}
}
