package publish

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func releaseTestBinary(t *testing.T) []byte {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeRel(t *testing.T, dir, reason string) Release {
	t.Helper()
	body := releaseTestBinary(t)
	src := filepath.Join(t.TempDir(), "loom")
	if err := os.WriteFile(src, body, 0o755); err != nil {
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
	body := releaseTestBinary(t)
	r := writeRel(t, dir, "第一次放行")
	if r.Reason != "第一次放行" || r.Size != len(body) {
		t.Fatalf("记录不对:%+v", r)
	}
	_, bin, err := ReadRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(bin)
	if err != nil || !bytes.Equal(b, body) {
		t.Fatalf("副本内容不对:size=%d(err=%v)", len(b), err)
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
	r := writeRel(t, dir, "放行")
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
	r := writeRel(t, dir, "放行")
	if err := os.WriteFile(ReleaseBinPath(dir, r.SHA256), []byte("短"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadRelease(dir); err == nil {
		t.Fatal("副本大小对不上应报错")
	}
}

// 同样大小也不代表同样内容。旧实现只 stat size,同尺寸篡改会被当成已批准。
func TestSameSizeHashMismatchIsCaught(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "放行")
	corrupt := strings.Repeat("x", r.Size)
	if err := os.WriteFile(ReleaseBinPath(dir, r.SHA256), []byte(corrupt), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadRelease(dir); err == nil || !strings.Contains(err.Error(), "哈希对不上") {
		t.Fatalf("同尺寸内容被替换必须报哈希错,得到:%v", err)
	}
}

func TestWriteReleaseRepairsCorruptExistingBlobAtomically(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "第一次")
	dst := ReleaseBinPath(dir, r.SHA256)
	if err := os.WriteFile(dst, []byte(strings.Repeat("z", r.Size)), 0o755); err != nil {
		t.Fatal(err)
	}
	// 再次明确放行同一候选应修复缓存,而不是因为同名文件已存在就跳过。
	r = writeRel(t, dir, "修复缓存")
	if _, _, err := ReadRelease(dir); err != nil {
		t.Fatalf("修复后应能通过全内容校验:%v", err)
	}
	b, _ := os.ReadFile(dst)
	if !bytes.Equal(b, releaseTestBinary(t)) {
		t.Fatalf("缓存没有被修复:size=%d", len(b))
	}
}

func TestCandidateMutationCannotBeApproved(t *testing.T) {
	src := filepath.Join(t.TempDir(), "loom")
	if err := os.WriteFile(src, []byte("candidate"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := ReadBinaryCandidate(src)
	if err != nil {
		t.Fatal(err)
	}
	c.Body[0] ^= 0xff
	if err := WriteReleaseCandidate(t.TempDir(), c, Release{Reason: "x"}); err == nil {
		t.Fatal("检查后的候选字节发生变化必须拒绝")
	}
}

// 停发之后配置照发,而**本地副本要留着** —— 它们是回滚缓存,
// 删了回滚就得回网络取。
func TestClearKeepsTheLocalCache(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "放行")
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

func TestClearReleaseDurablyRemovesAuthorizationRecord(t *testing.T) {
	dir := t.TempDir()
	writeRel(t, dir, "durable clear")
	if err := ClearRelease(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, releaseFile)); !os.IsNotExist(err) {
		t.Fatalf("clear 后 release 授权仍存在:%v", err)
	}
	if err := ClearRelease(dir); err != nil {
		t.Fatalf("durable clear 必须保持幂等:%v", err)
	}
}

// 同样的内容放行两次:副本按内容寻址,不该重复写,记录该更新。
func TestReleasingSameContentTwiceIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	a := writeRel(t, dir, "第一次")
	b := writeRel(t, dir, "第二次,理由改了")
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

func TestReleaseMetadataIsDerivedFromAndBoundToBinaryBuildInfo(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "coordinate test")
	c := newBinaryCandidate(releaseTestBinary(t))
	vc, err := InspectBinary(c)
	if err != nil {
		t.Fatal(err)
	}
	if r.Commit != vc.Commit || r.Dirty != vc.Dirty {
		t.Fatalf("省略的坐标应从实际 buildinfo 补齐:release=%+v build=%+v", r, vc)
	}

	r.Commit = "definitely-not-the-binary-commit"
	writeReleaseRecordForTest(t, dir, r)
	if _, _, err := ReadRelease(dir); err == nil || !strings.Contains(err.Error(), "构建坐标不符") {
		t.Fatalf("伪造 commit 必须被实际 buildinfo 拒绝:%v", err)
	}
}

func TestLegacyReleaseWithoutCoordinatesUsesActualBuildInfo(t *testing.T) {
	dir := t.TempDir()
	r := writeRel(t, dir, "legacy coordinate")
	r.Commit, r.Dirty = "", false // 明确的旧记录兼容形态。
	writeReleaseRecordForTest(t, dir, r)

	got, _, err := ReadRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := InspectBinary(newBinaryCandidate(releaseTestBinary(t)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Commit != vc.Commit || got.Dirty != vc.Dirty {
		t.Fatalf("旧记录不能继续展示空/错误坐标:got=%+v build=%+v", got, vc)
	}
}

func TestReleaseRequiresReasonAndRFC3339Timestamp(t *testing.T) {
	c := newBinaryCandidate(releaseTestBinary(t))
	for _, tc := range []struct {
		name string
		r    Release
	}{
		{"blank-reason", Release{Reason: "  ", ReleasedAt: "2026-08-26T20:00:00Z"}},
		{"missing-time", Release{Reason: "why"}},
		{"bad-time", Release{Reason: "why", ReleasedAt: "yesterday"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := WriteReleaseCandidate(t.TempDir(), c, tc.r); err == nil {
				t.Fatal("必填/格式错误的 release 元数据不应入库")
			}
		})
	}

	dir := t.TempDir()
	r := writeRel(t, dir, "valid first")
	r.Reason = ""
	writeReleaseRecordForTest(t, dir, r)
	if _, _, err := ReadRelease(dir); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("读取既有记录也必须 fail-closed:%v", err)
	}
}

func writeReleaseRecordForTest(t *testing.T, dir string, r Release) {
	t.Helper()
	b, err := json.MarshalIndent(&r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, releaseFile), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
