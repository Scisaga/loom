//go:build !windows

package publish

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPushImmutablePublishesEveryMirrorWithoutLatestPointer(t *testing.T) {
	firstRoot, secondRoot := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	first, err := ParseTarget(firstRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseTarget(secondRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	mirrors, err := NewMirrorSet(first, second)
	if err != nil {
		t.Fatal(err)
	}
	path := "distribution/sha256/" + strings.Repeat("a", 64)
	body := []byte(`{"schema":1}`)
	if err := PushImmutable(mirrors, map[string][]byte{path: body}); err != nil {
		t.Fatal(err)
	}
	if err := PushImmutable(mirrors, map[string][]byte{path: body}); err != nil {
		t.Fatalf("exact 重放不幂等: %v", err)
	}
	for _, root := range []string{firstRoot, secondRoot} {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("镜像没有 exact bytes: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, "current.json")); !os.IsNotExist(err) {
			t.Fatal("不可变发布错误地产生 latest/current pointer")
		}
	}
	if err := PushImmutable(first, map[string][]byte{path: []byte(`{"schema":2}`)}); err == nil {
		t.Fatal("同 typed-hash 路径的冲突 bytes 被覆盖")
	}
}
