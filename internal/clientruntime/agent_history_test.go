package clientruntime

import (
	"context"
	"loom/internal/agent"
	"os"
	"path/filepath"
	"testing"
)

// §5.6：不再写入或复用旧完整路径样本；每个激活代次只有自己的选择状态。
func TestWindowsClientDoesNotReuseFullPathHistory(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "agent", "measurements-old.jsonl")
	if err := os.MkdirAll(filepath.Dir(old), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("obsolete full path samples"), 0600); err != nil {
		t.Fatal(err)
	}
	var previous string
	for range 2 {
		a, err := StartWindowsAgent(context.Background(), &agent.Config{Node: "demo-client"}, root)
		if err != nil {
			t.Fatal(err)
		}
		if a.statePath == previous {
			t.Fatal("reused old generation")
		}
		previous = a.statePath
		if err := a.Stop(); err != nil {
			t.Fatal(err)
		}
		files, err := os.ReadDir(filepath.Dir(a.statePath))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.Name() != "state.json" {
				t.Fatal("unexpected measurement history", f.Name())
			}
		}
	}
	body, err := os.ReadFile(old)
	if err != nil || string(body) != "obsolete full path samples" {
		t.Fatal("changed old diagnostic history")
	}
}
