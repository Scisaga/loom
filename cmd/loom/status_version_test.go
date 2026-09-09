package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/report"
	"loom/internal/version"
)

func TestLocalStatusUsesReportServiceObservation(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	want := &report.Status{Node: "demo-d", Observation: &report.Observation{
		Node: "demo-d", TS: now.Format(time.RFC3339), Attest: &attest.Signed{},
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	got, err := localStatusFrom(strings.TrimPrefix(srv.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.Observation == nil || got.Observation.Node != "demo-d" || got.Observation.Attest == nil {
		t.Fatalf("本机路径丢失 report 后台签名观测:%+v", got)
	}
}

func TestAttestationReadinessUsesSSOTDenominator(t *testing.T) {
	ready, missing := attestationReadiness(
		[]string{"demo-a", "demo-b", "demo-c", "demo-d", "demo-e"},
		map[string]bool{"demo-a": true, "demo-d": true, "demo-e": true, "ghost": true},
	)
	if ready != 3 || !reflect.DeepEqual(missing, []string{"demo-b", "demo-c"}) {
		t.Fatalf("readiness=%d missing=%v", ready, missing)
	}
}

func coord(commit string) *version.Coordinate {
	return &version.Coordinate{Commit: commit, Platform: "linux/amd64", Go: "go1.27"}
}

func joined(lines []string) string { return strings.Join(lines, "\n") }

// 这是本文件存在的**主要理由**:第一版把"拓扑上够得到"当成"已经答上来了",
// 于是一次超时会被指认成"跑的是旧二进制",而那台机器上面刚被报过"拉不到"。
// 同一件事报两遍,还报成两回事。
func TestFetchFailureIsNotMistakenForOldBinary(t *testing.T) {
	vcs := map[string]*version.Coordinate{
		"demo-d": coord("aaaa111122223333"),
		"demo-e": coord("aaaa111122223333"),
		"demo-a": coord("aaaa111122223333"),
	}
	// demo-c 拉取超时:它既不在 vcs 里,也不在 answered 里。
	answered := map[string]bool{"demo-d": true, "demo-e": true, "demo-a": true}
	lines, bad := versionFindings(vcs, answered, []string{"demo-b"}, 5)

	if strings.Contains(joined(lines), "旧二进制") {
		t.Fatalf("拉不到的节点被误诊成旧二进制:\n%s", joined(lines))
	}
	if strings.Contains(joined(lines), "demo-c") {
		t.Fatalf("拉不到的节点不该在版本表里再出现一次:\n%s", joined(lines))
	}
	if bad != 0 {
		t.Fatalf("超时已经在别处计过 bad,这里不该再加:bad=%d", bad)
	}
}

// 答上来了却没带版本坐标 —— 只有这种才是真的旧二进制,必须报。
func TestAnsweredWithoutVersionIsOldBinary(t *testing.T) {
	vcs := map[string]*version.Coordinate{"demo-d": coord("aaaa111122223333")}
	answered := map[string]bool{"demo-d": true, "demo-e": true}
	lines, bad := versionFindings(vcs, answered, nil, 5)

	got := joined(lines)
	if !strings.Contains(got, "旧二进制") || !strings.Contains(got, "demo-e") {
		t.Fatalf("答上来但没版本的节点应报成旧二进制:\n%s", got)
	}
	if bad != 1 {
		t.Fatalf("旧二进制是故障,应计入 bad,得到 %d", bad)
	}
}

// 分母取 SSOT 节点数。彻底失联的机器如果不进分母就会整个消失,
// 而消失的样子和一切正常一模一样。
func TestDenominatorComesFromSSOTNotFromWhoAnswered(t *testing.T) {
	vcs := map[string]*version.Coordinate{"demo-d": coord("aaaa111122223333")}
	lines, _ := versionFindings(vcs, map[string]bool{"demo-d": true}, nil, 5)
	if !strings.Contains(joined(lines), "1/5 台核对过") {
		t.Fatalf("分母应是 SSOT 的 5,得到:\n%s", joined(lines))
	}
}

// 够不到是拓扑事实,要印出来,但**不能计入 bad** —— 否则每次都响。
func TestUnreachableIsReportedButNotAnAlarm(t *testing.T) {
	vcs := map[string]*version.Coordinate{
		"demo-d": coord("aaaa111122223333"),
		"demo-e": coord("aaaa111122223333"),
	}
	answered := map[string]bool{"demo-d": true, "demo-e": true}
	lines, bad := versionFindings(vcs, answered, []string{"demo-b", "demo-c"}, 5)

	got := joined(lines)
	if !strings.Contains(got, "demo-b") || !strings.Contains(got, "demo-c") {
		t.Fatalf("够不到的节点必须印出来,否则空白会被当成一致:\n%s", got)
	}
	if strings.Contains(got, "⚠️ 够不到") {
		t.Fatalf("够不到是拓扑不是故障,不该带告警标记:\n%s", got)
	}
	if bad != 0 {
		t.Fatalf("够不到不该计入 bad,得到 %d", bad)
	}
}

func TestCommitSplitIsAnAlarm(t *testing.T) {
	vcs := map[string]*version.Coordinate{
		"demo-d": coord("aaaa111122223333"),
		"demo-e": coord("bbbb444455556666"),
	}
	lines, bad := versionFindings(vcs, map[string]bool{"demo-d": true, "demo-e": true}, nil, 2)
	if !strings.Contains(joined(lines), "不是同一个 commit") || bad != 1 {
		t.Fatalf("commit 分裂应报警并计 bad,bad=%d:\n%s", bad, joined(lines))
	}
}

func TestDirtyBuildIsAnAlarm(t *testing.T) {
	c := coord("aaaa111122223333")
	c.Dirty = true
	vcs := map[string]*version.Coordinate{"demo-d": c}
	lines, bad := versionFindings(vcs, map[string]bool{"demo-d": true}, nil, 1)
	if !strings.Contains(joined(lines), "脏工作区") || bad != 1 {
		t.Fatalf("脏构建应报警并计 bad,bad=%d:\n%s", bad, joined(lines))
	}
}

// 一台都没核对到时不该印一张空表 —— 空表比不印更容易被当成"没问题"。
func TestNoCoordinatesPrintsNothing(t *testing.T) {
	lines, bad := versionFindings(nil, nil, []string{"demo-b"}, 5)
	if len(lines) != 0 || bad != 0 {
		t.Fatalf("没有任何版本坐标时不该输出,得到 bad=%d:\n%s", bad, joined(lines))
	}
}

// D81 之后,"够不到"不再等于"核不了":带签名的转述节点要被并进版本表。
// 这里只验分流逻辑 —— 签名本身的正确性由 internal/attest 的测试守着。
func TestFoldAttestedSplitsVerifiableFromNot(t *testing.T) {
	// 没有 CA 时必须原样返回,不能假装核过了。
	vcs := map[string]*version.Coordinate{}
	snaps := map[string]string{}
	answered := map[string]bool{}
	obs := map[string]report.Observation{"demo-b": {Node: "demo-b", Applied: "伪造快照"}}
	still, bad := foldAttested(obs, snaps, vcs, map[string]*report.RolloutState{}, answered,
		[]string{"demo-b", "demo-c"}, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC), 0)
	if len(still) != 2 {
		t.Fatalf("核不了的应原样返回 2 个,得到 %v", still)
	}
	if len(vcs) != 0 {
		t.Errorf("没核过的不该进版本表,得到 %v", vcs)
	}
	if len(snaps) != 0 {
		t.Errorf("未签名 Applied 不该进快照表,得到 %v", snaps)
	}
	if bad != 0 {
		t.Fatalf("没有签名只是尚未核对，不应报坏:bad=%d", bad)
	}
}

func TestFoldAttestedPhaseBRemovesUnsignedObservationFromMatrixInput(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	obs := map[string]report.Observation{"demo-d": {
		Node: "demo-d", TS: now.Format(time.RFC3339),
		Targets: []report.Reach{{Target: "https://example.test", FirstByteMs: 1}},
	}}
	loadedCA := false
	_, bad := foldAttestedWithCALoader(obs, map[string]string{},
		map[string]*version.Coordinate{}, map[string]*report.RolloutState{},
		map[string]bool{"demo-d": true}, nil, now, 5, func() ([]byte, error) {
			loadedCA = true
			return nil, nil
		})
	if loadedCA {
		t.Fatal("完全没有主签名时不应读取 CA")
	}
	if bad != 1 {
		t.Fatalf("phase-B unsigned observation 应明确计坏，得到 %d", bad)
	}
	if _, ok := obs["demo-d"]; ok {
		t.Fatal("phase-B unsigned observation 仍留在 printMatrix 的输入中")
	}
}

func TestFoldAttestedPhaseBRemovesFailedSignatureFromMatrixInput(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	obs := map[string]report.Observation{"demo-d": {
		Node: "demo-d", TS: now.Format(time.RFC3339), Attest: &attest.Signed{},
		Targets: []report.Reach{{Target: "https://example.test", FirstByteMs: 1}},
	}}
	_, bad := foldAttestedWithCALoader(obs, map[string]string{},
		map[string]*version.Coordinate{}, map[string]*report.RolloutState{},
		map[string]bool{"demo-d": true}, nil, now, 5,
		func() ([]byte, error) { return []byte("不是 CA"), nil })
	if bad != 1 {
		t.Fatalf("phase-B 验签失败应明确计坏，得到 %d", bad)
	}
	if _, ok := obs["demo-d"]; ok {
		t.Fatal("phase-B 验签失败 observation 仍留在 printMatrix 的输入中")
	}
}

func TestFoldAttestedPhaseBRemovesUnsignedDirectIdentityState(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	obs := map[string]report.Observation{"demo-d": {
		Node: "demo-d", TS: now.Format(time.RFC3339),
	}}
	snaps := map[string]string{"demo-d": "外层伪造快照"}
	vcs := map[string]*version.Coordinate{"demo-d": {Commit: "外层伪造 commit"}}
	rolls := map[string]*report.RolloutState{"demo-d": {Stage: "verified"}}
	answered := map[string]bool{"demo-d": true}

	_, bad := foldAttestedWithCALoader(obs, snaps, vcs, rolls, answered, nil, now, 5,
		func() ([]byte, error) { return nil, nil })
	if bad != 1 {
		t.Fatalf("phase-B unsigned direct status 应明确计坏，得到 %d", bad)
	}
	if _, ok := snaps["demo-d"]; ok {
		t.Fatal("未经签名的 Applied 仍进入快照汇总")
	}
	if _, ok := vcs["demo-d"]; ok {
		t.Fatal("未经签名的 Version 仍进入版本汇总")
	}
	if _, ok := rolls["demo-d"]; ok {
		t.Fatal("未经签名的 Rollout 仍进入 rollout 汇总")
	}
	if answered["demo-d"] {
		t.Fatal("未经签名的 direct status 仍被标成已核对")
	}
}

func TestFoldAttestedPhaseBRejectsDirectStatusWithoutObservation(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	snaps := map[string]string{"demo-d": "外层伪造快照"}
	answered := map[string]bool{"demo-d": true}

	_, bad := foldAttestedWithCALoader(map[string]report.Observation{}, snaps,
		map[string]*version.Coordinate{}, map[string]*report.RolloutState{}, answered,
		nil, now, 5, func() ([]byte, error) { return nil, nil })
	if bad != 1 {
		t.Fatalf("phase-B 缺少 observation 的 direct status 应明确计坏，得到 %d", bad)
	}
	if _, ok := snaps["demo-d"]; ok || answered["demo-d"] {
		t.Fatal("缺少 observation 的 direct status 身份状态没有被清除")
	}
}
