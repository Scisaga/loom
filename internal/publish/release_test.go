package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRel(t *testing.T, dir, content, reason string) Release {
	t.Helper()
	src := filepath.Join(t.TempDir(), "loom")
	if err := os.WriteFile(src, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteRelease(dir, src, Release{Reason: reason, ReleasedAt: "2026-08-25T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	r, _, err := ReadRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	return *r
}

// 没放行过任何二进制不是错误 —— 那是"只发配置"这个合法状态。
func TestReadReleaseAbsentIsNotAnError(t *testing.T) {
	r, bin, err := ReadRelease(t.TempDir())
	if err != nil || r != nil || bin != "" {
		t.Fatalf("没有 release 应返回 (nil, \"\", nil),得到 (%v, %q, %v)", r, bin, err)
	}
	if r, _, err := ReadRelease(""); err != nil || r != nil {
		t.Fatalf("空目录名应同样安静,得到 (%v, %v)", r, err)
	}
}

func TestWriteThenReadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "二进制内容", "第一次放行")
	if r.Reason != "第一次放行" || r.Size != len("二进制内容") {
		t.Fatalf("记录不对:%+v", r)
	}
	_, bin, err := ReadRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(bin)
	if err != nil || string(b) != "二进制内容" {
		t.Fatalf("副本内容不对:%q(err=%v)", b, err)
	}
	// 副本必须可执行,否则发布器读得到但节点装上去跑不了。
	st, _ := os.Stat(bin)
	if st.Mode().Perm()&0o111 == 0 {
		t.Errorf("副本应可执行,得到 %v", st.Mode().Perm())
	}
}

// 这是本文件的**主要理由**:记录在、副本不在时**必须报错**。
// 默默回落到"本机当前二进制"正好是 release 要防的那件事。
func TestMissingCopyIsAnErrorNotAFallback(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "内容", "放行")
	if err := os.Remove(ReleaseBinPath(dir, r.SHA256)); err != nil {
		t.Fatal(err)
	}
	rel, bin, err := ReadRelease(dir)
	if err == nil {
		t.Fatalf("副本不见了必须报错,却返回了 (%v, %q)", rel, bin)
	}
	if !strings.Contains(err.Error(), "loom release") {
		t.Errorf("错误里要说怎么修,得到:%v", err)
	}
}

// 副本被换成别的东西 —— 大小对不上就该发现。
func TestSizeMismatchIsCaught(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "原本的内容", "放行")
	if err := os.WriteFile(ReleaseBinPath(dir, r.SHA256), []byte("短"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadRelease(dir); err == nil {
		t.Fatal("副本大小对不上应报错")
	}
}

// 停发之后配置照发,而**本地副本要留着** —— 它们是回滚缓存,
// 删了回滚就得回网络取。
func TestClearKeepsTheLocalCache(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "内容", "放行")
	if err := ClearRelease(dir); err != nil {
		t.Fatal(err)
	}
	rel, _, err := ReadRelease(dir)
	if err != nil || rel != nil {
		t.Fatalf("停发后应回到\"没放行过\",得到 (%v, %v)", rel, err)
	}
	if _, err := os.Stat(ReleaseBinPath(dir, r.SHA256)); err != nil {
		t.Errorf("本地副本不该被删:%v", err)
	}
	// 再停一次不该报错 —— 幂等。
	if err := ClearRelease(dir); err != nil {
		t.Errorf("重复 clear 应幂等,得到 %v", err)
	}
}

// 同样的内容放行两次:副本按内容寻址,不该重复写,记录该更新。
func TestReleasingSameContentTwiceIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	a := writeRel(t, dir, "一样的内容", "第一次")
	b := writeRel(t, dir, "一样的内容", "第二次,理由改了")
	if a.SHA256 != b.SHA256 {
		t.Fatalf("同样内容应得到同样的 sha:%s vs %s", a.SHA256, b.SHA256)
	}
	if b.Reason != "第二次,理由改了" {
		t.Errorf("理由应被更新,得到 %q", b.Reason)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, releaseBins))
	if len(ents) != 1 {
		t.Errorf("内容寻址下应只有一个副本,得到 %d 个", len(ents))
	}
}
