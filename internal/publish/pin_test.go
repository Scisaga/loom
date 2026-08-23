package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinRoundTrip(t *testing.T) {
	dir := t.TempDir()

	if p, _, err := ReadPin(dir); err != nil || p != nil {
		t.Fatalf("没钉住时应当是 (nil, nil),得到 (%v, %v)", p, err)
	}

	want := &Pin{Snapshot: "abc123", SHA256: "deadbeef", Reason: "新版起得来但选路是错的"}
	if err := WritePin(dir, want, []byte("#!/bin/true\n")); err != nil {
		t.Fatal(err)
	}
	got, bin, err := ReadPin(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Snapshot != want.Snapshot || got.Reason != want.Reason {
		t.Fatalf("读回来不对:%+v", got)
	}
	if b, _ := os.ReadFile(bin); string(b) != "#!/bin/true\n" {
		t.Fatalf("二进制内容不对:%q", b)
	}

	if err := ClearPin(dir); err != nil {
		t.Fatal(err)
	}
	if p, _, err := ReadPin(dir); err != nil || p != nil {
		t.Fatalf("解除后应当读不到,得到 (%v, %v)", p, err)
	}
	// 二进制也要删掉 —— 留着只会让人以为还钉着。
	if _, err := os.Stat(filepath.Join(dir, pinBin)); !os.IsNotExist(err) {
		t.Fatal("解除钉住后二进制应当一并删掉")
	}
}

// 记录在、二进制不在是**半个状态**:发不出去也退不回来。
// 必须报错,不能默默回落到当前二进制 —— 那正好是钉住要防的事。
func TestPinHalfStateIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := WritePin(dir, &Pin{Snapshot: "abc123", Reason: "x"}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, pinBin))

	_, _, err := ReadPin(dir)
	if err == nil {
		t.Fatal("二进制不见了应当报错,而不是当成没钉住")
	}
	if !strings.Contains(err.Error(), "不见了") {
		t.Fatalf("错误消息要说清是什么半状态,得到:%v", err)
	}
}

// 目录没配就是没启用这个功能,不是错误。
func TestPinEmptyDir(t *testing.T) {
	if p, _, err := ReadPin(""); err != nil || p != nil {
		t.Fatalf("空目录应当是 (nil, nil),得到 (%v, %v)", p, err)
	}
}
