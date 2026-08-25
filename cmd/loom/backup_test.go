package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 备份的两条规矩方向相反,而分错边的代价也不对称:
//
//   - **必需项缺了要硬失败。** 一个"成功"但内容不全的备份,只有在需要它的
//     那天才会被发现。
//   - **可选项缺了不能拦。** 源头存档要发布器成功发过一次才建,拿它当必需项
//     的话,一台刚起来的中控连备份都做不了 —— 而"做危险变更之前先备份"
//     恰恰是最需要它能跑的时候。
//
// 第二条是加了源头存档之后当场踩到的:默认清单一改,备份就整个不干活了。
func TestBackupOptionalMissingDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	must := filepath.Join(dir, "must.env")
	if err := os.WriteFile(must, []byte("K=V\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var included, missing, skipped, oddities []string
	srcs := []backupSrc{
		{path: must},
		{path: filepath.Join(dir, "还不存在"), optional: true},
	}
	for _, src := range srcs {
		n, err := addPath(tw, src.path, &included, &oddities)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			if src.optional {
				skipped = append(skipped, src.path)
			} else {
				missing = append(missing, src.path)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	if len(missing) != 0 {
		t.Errorf("可选项被当成必需项了:%v", missing)
	}
	if len(skipped) != 1 {
		t.Fatalf("缺失的可选项没被记下来,会被静默省略:%v", skipped)
	}
	if len(included) != 1 || !strings.HasSuffix(included[0], "must.env") {
		t.Errorf("必需项没进包:%v", included)
	}
}

// 必需项缺失仍然要被认出来 —— 上面那条放松不能顺手把这条也放松了。
func TestBackupRequiredMissingIsCaught(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var included, missing, oddities []string
	for _, src := range []backupSrc{{path: filepath.Join(dir, "缺的")}} {
		n, err := addPath(tw, src.path, &included, &oddities)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 && !src.optional {
			missing = append(missing, src.path)
		}
	}
	tw.Close()
	if len(missing) != 1 {
		t.Error("必需项不存在,却没被认出来")
	}
}

// 存在的可选项照常打包 —— "可选"说的是它可能还没出生,不是它不重要。
func TestBackupOptionalPresentIsIncluded(t *testing.T) {
	dir := t.TempDir()
	hist := filepath.Join(dir, "ssot-history")
	if err := os.MkdirAll(hist, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hist, "abc.yaml"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var included, oddities []string
	n, err := addPath(tw, hist, &included, &oddities)
	if err != nil {
		t.Fatal(err)
	}
	tw.Close()
	if n != 1 {
		t.Fatalf("可选项存在却没被打包:n=%d", n)
	}
	sort.Strings(included)
	if len(included) != 1 || !strings.HasSuffix(included[0], "abc.yaml") {
		t.Errorf("打进去的不对:%v", included)
	}
}

// 默认清单漏一项的后果只有在需要备份的那天才会发现,而那天没法补救。
// 所以每一项都钉住,不靠"看一眼觉得齐了"。
func TestDefaultBackupSrcsCoverTheIrreplaceable(t *testing.T) {
	got := map[string]bool{}
	optional := map[string]bool{}
	for _, s := range defaultBackupSrcs() {
		got[s.path] = true
		optional[s.path] = s.optional
	}

	// 签名私钥丢了,全网再也收不到任何新配置 —— 换钥要逐台手工改
	// control.json。D38 与附录 C #15 都写着它靠 loom backup 保存。
	// **deploy/pki 不顶替它**:那是 CA 与节点证书,是另一样东西。
	for _, must := range []string{"deploy/keys", "deploy/secrets.env", "deploy/pki"} {
		if !got[must] {
			t.Errorf("默认备份清单缺少 %s —— 丢了就不可再生", must)
		}
		if optional[must] {
			t.Errorf("%s 不能是可选的:静默跳过会制造出\"你以为备份了\"", must)
		}
	}

	// 源头存档要发布器成功发布过一次才会建,所以它可以合法地还不存在。
	if !got["deploy/ssot-history"] || !optional["deploy/ssot-history"] {
		t.Error("deploy/ssot-history 应在清单里,且必须是可选的")
	}
}

// 子目录必须递归进去。早先的版本遇到子目录直接跳过,而且**不报告** ——
// 备份"成功"但内容不全,只有在需要它的那天才会发现。
func TestAddPathRecursesIntoSubdirectories(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		filepath.Join(dir, "顶层.txt"),
		filepath.Join(dir, "a", "一层.txt"),
		filepath.Join(deep, "三层.txt"),
	} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var included, oddities []string
	n, err := addPath(tw, dir, &included, &oddities)
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("三层目录里共 3 个文件,只打了 %d 个:%v", n, included)
	}
	joined := strings.Join(included, " ")
	for _, want := range []string{"顶层.txt", "一层.txt", "三层.txt"} {
		if !strings.Contains(joined, want) {
			t.Errorf("漏了 %s:%v", want, included)
		}
	}
}

// 非普通文件不打包,但**要报出来** —— 静默跳过和"这里本来就没东西"
// 在结果上分不开。
func TestAddPathReportsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "link.txt")); err != nil {
		t.Skip("这个文件系统建不了符号链接")
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var included, oddities []string
	n, err := addPath(tw, dir, &included, &oddities)
	if err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	if n != 1 {
		t.Errorf("只该打包那个普通文件,打了 %d 个:%v", n, included)
	}
	if len(oddities) != 1 || !strings.Contains(oddities[0], "link.txt") {
		t.Errorf("符号链接必须被报出来,得到 %v", oddities)
	}
}
