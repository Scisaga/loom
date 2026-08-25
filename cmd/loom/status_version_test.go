package main

import (
	"strings"
	"testing"

	"loom/internal/version"
)

func coord(commit string) *version.Coordinate {
	return &version.Coordinate{Commit: commit, Platform: "linux/amd64", Go: "go1.27"}
}

func joined(lines []string) string { return strings.Join(lines, "\n") }

// 这是本文件存在的**主要理由**:第一版把"拓扑上够得到"当成"已经答上来了",
// 于是一次超时会被指认成"跑的是旧二进制",而那台机器上面刚被报过"拉不到"。
// 同一件事报两遍,还报成两回事。
func TestFetchFailureIsNotMistakenForOldBinary(t *testing.T) {
	vcs := map[string]*version.Coordinate{
		"jm24":  coord("aaaa111122223333"),
		"sg02":  coord("aaaa111122223333"),
		"ber01": coord("aaaa111122223333"),
	}
	// hz01 拉取超时:它既不在 vcs 里,也不在 answered 里。
	answered := map[string]bool{"jm24": true, "sg02": true, "ber01": true}
	lines, bad := versionFindings(vcs, answered, []string{"gz02"}, 5)

	if strings.Contains(joined(lines), "旧二进制") {
		t.Fatalf("拉不到的节点被误诊成旧二进制:\n%s", joined(lines))
	}
	if strings.Contains(joined(lines), "hz01") {
		t.Fatalf("拉不到的节点不该在版本表里再出现一次:\n%s", joined(lines))
	}
	if bad != 0 {
		t.Fatalf("超时已经在别处计过 bad,这里不该再加:bad=%d", bad)
	}
}

// 答上来了却没带版本坐标 —— 只有这种才是真的旧二进制,必须报。
func TestAnsweredWithoutVersionIsOldBinary(t *testing.T) {
	vcs := map[string]*version.Coordinate{"jm24": coord("aaaa111122223333")}
	answered := map[string]bool{"jm24": true, "sg02": true}
	lines, bad := versionFindings(vcs, answered, nil, 5)

	got := joined(lines)
	if !strings.Contains(got, "旧二进制") || !strings.Contains(got, "sg02") {
		t.Fatalf("答上来但没版本的节点应报成旧二进制:\n%s", got)
	}
	if bad != 1 {
		t.Fatalf("旧二进制是故障,应计入 bad,得到 %d", bad)
	}
}

// 分母取 SSOT 节点数。彻底失联的机器如果不进分母就会整个消失,
// 而消失的样子和一切正常一模一样。
func TestDenominatorComesFromSSOTNotFromWhoAnswered(t *testing.T) {
	vcs := map[string]*version.Coordinate{"jm24": coord("aaaa111122223333")}
	lines, _ := versionFindings(vcs, map[string]bool{"jm24": true}, nil, 5)
	if !strings.Contains(joined(lines), "1/5 台核对过") {
		t.Fatalf("分母应是 SSOT 的 5,得到:\n%s", joined(lines))
	}
}

// 够不到是拓扑事实,要印出来,但**不能计入 bad** —— 否则每次都响。
func TestUnreachableIsReportedButNotAnAlarm(t *testing.T) {
	vcs := map[string]*version.Coordinate{
		"jm24": coord("aaaa111122223333"),
		"sg02": coord("aaaa111122223333"),
	}
	answered := map[string]bool{"jm24": true, "sg02": true}
	lines, bad := versionFindings(vcs, answered, []string{"gz02", "hz01"}, 5)

	got := joined(lines)
	if !strings.Contains(got, "gz02") || !strings.Contains(got, "hz01") {
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
		"jm24": coord("aaaa111122223333"),
		"sg02": coord("bbbb444455556666"),
	}
	lines, bad := versionFindings(vcs, map[string]bool{"jm24": true, "sg02": true}, nil, 2)
	if !strings.Contains(joined(lines), "不是同一个 commit") || bad != 1 {
		t.Fatalf("commit 分裂应报警并计 bad,bad=%d:\n%s", bad, joined(lines))
	}
}

func TestDirtyBuildIsAnAlarm(t *testing.T) {
	c := coord("aaaa111122223333")
	c.Dirty = true
	vcs := map[string]*version.Coordinate{"jm24": c}
	lines, bad := versionFindings(vcs, map[string]bool{"jm24": true}, nil, 1)
	if !strings.Contains(joined(lines), "脏工作区") || bad != 1 {
		t.Fatalf("脏构建应报警并计 bad,bad=%d:\n%s", bad, joined(lines))
	}
}

// 一台都没核对到时不该印一张空表 —— 空表比不印更容易被当成"没问题"。
func TestNoCoordinatesPrintsNothing(t *testing.T) {
	lines, bad := versionFindings(nil, nil, []string{"gz02"}, 5)
	if len(lines) != 0 || bad != 0 {
		t.Fatalf("没有任何版本坐标时不该输出,得到 bad=%d:\n%s", bad, joined(lines))
	}
}
