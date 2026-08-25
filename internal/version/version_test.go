package version

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Base 必须永远能给出平台与 Go 版本 —— 这两个不依赖 VCS 戳。
func TestBaseAlwaysHasPlatform(t *testing.T) {
	c := Base()
	if c.Platform == "" || !strings.Contains(c.Platform, "/") {
		t.Fatalf("Platform 应形如 os/arch,得到 %q", c.Platform)
	}
	if !strings.HasPrefix(c.Go, "go") {
		t.Fatalf("Go 应形如 goX.Y,得到 %q", c.Go)
	}
}

// Self 要么给出哈希,要么给出理由 —— 不许两个都空。
// 静默降级正是本包要挡的东西。
func TestSelfBinaryOrReason(t *testing.T) {
	c := Self()
	if c.Binary == "" && c.BinaryErr == "" {
		t.Fatal("Binary 与 BinaryErr 同时为空:算不出哈希却没说原因")
	}
	if c.Binary != "" && len(c.Binary) != 64 {
		t.Fatalf("sha256 应为 64 个十六进制字符,得到 %d 个", len(c.Binary))
	}
}

func TestShort(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"abc", "abc"},
		{"808e8fdd78f7", "808e8fdd78f7"},
		{"808e8fdd78f76d0b5b9fb8c5dd21f150e5fffd55", "808e8fdd78f7"},
	} {
		if got := Short(c.in); got != c.want {
			t.Errorf("Short(%q) = %q,想要 %q", c.in, got, c.want)
		}
	}
}

// commit 缺失时必须明写 commit=?,不能悄悄少印一段 —— 否则一行
// "loom · linux/amd64" 看起来像是正常输出。
func TestLineNamesMissingCommit(t *testing.T) {
	got := Coordinate{Platform: "linux/amd64", Go: "go1.27"}.Line()
	if !strings.Contains(got, "commit=?") {
		t.Fatalf("缺 commit 时应印 commit=?,得到 %q", got)
	}
}

func TestLineDirtyAndBinary(t *testing.T) {
	c := Coordinate{
		Commit:   "808e8fdd78f76d0b5b9fb8c5dd21f150e5fffd55",
		Dirty:    true,
		Binary:   "792db49ad8f6000000000000000000000000000000000000000000000000abcd",
		Platform: "linux/amd64",
		Go:       "go1.27",
	}
	got := c.Line()
	for _, want := range []string{"808e8fdd78f7", "+dirty", "bin 792db49ad8f6"} {
		if !strings.Contains(got, want) {
			t.Errorf("Line() 少了 %q:%s", want, got)
		}
	}
}

// 脏构建和认不出 commit 都必须报出来,这是"不许静默降级"在版本上的落点。
func TestWarnings(t *testing.T) {
	if w := (Coordinate{Commit: "abc"}).Warnings(); len(w) != 0 {
		t.Fatalf("干净坐标不该有警告,得到 %v", w)
	}
	if w := (Coordinate{}).Warnings(); len(w) != 1 {
		t.Fatalf("缺 commit 应有 1 条警告,得到 %v", w)
	}
	if w := (Coordinate{Commit: "abc", Dirty: true, BinaryErr: "x"}).Warnings(); len(w) != 2 {
		t.Fatalf("脏 + 读不到二进制应有 2 条警告,得到 %v", w)
	}
}

// Traceable 是发布前的闸门:发出去的东西将来出问题,能不能用 git 复现。
func TestTraceable(t *testing.T) {
	for _, c := range []struct {
		name string
		c    Coordinate
		want bool
	}{
		{"有 commit 且干净", Coordinate{Commit: "abc"}, true},
		{"认不出 commit", Coordinate{}, false},
		{"脏工作区", Coordinate{Commit: "abc", Dirty: true}, false},
		{"两样都缺", Coordinate{Dirty: true}, false},
	} {
		if got := c.c.Traceable(); got != c.want {
			t.Errorf("%s:Traceable()=%v,想要 %v", c.name, got, c.want)
		}
	}
}

// OfFile 读的是**文件**不是本进程 —— 发布器钉住时发的是历史二进制,
// 它的 commit 只有那个文件自己知道。
func TestOfFileReadsTheFileNotOurselves(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("拿不到自己的路径")
	}
	c, err := OfFile(self)
	if err != nil {
		t.Fatalf("读测试二进制的构建信息失败:%v", err)
	}
	if c.Go == "" {
		t.Error("应能读出 Go 版本")
	}
	if c.Platform == "" || !strings.Contains(c.Platform, "/") {
		t.Errorf("Platform 应形如 os/arch,得到 %q", c.Platform)
	}
}

// 读不出来要报错,**不能返回一个空坐标当作"没问题"** ——
// 那正好会让闸门把不可追溯的二进制放过去。
func TestOfFileFailsLoudly(t *testing.T) {
	if _, err := OfFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("文件不存在应报错")
	}
	notGo := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(notGo, []byte("我不是 Go 二进制"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OfFile(notGo); err == nil {
		t.Error("非 Go 二进制应报错,而不是返回空坐标")
	}
}
