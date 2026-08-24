package version

import (
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
