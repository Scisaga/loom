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
	var included, missing, skipped []string
	srcs := []backupSrc{
		{path: must},
		{path: filepath.Join(dir, "还不存在"), optional: true},
	}
	for _, src := range srcs {
		n, err := addPath(tw, src.path, &included)
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
	var included, missing []string
	for _, src := range []backupSrc{{path: filepath.Join(dir, "缺的")}} {
		n, err := addPath(tw, src.path, &included)
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
	var included []string
	n, err := addPath(tw, hist, &included)
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
