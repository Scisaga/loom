package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProfileDraftDoesNotEnterFormalIndexBeforeCommit(t *testing.T) {
	store := newConnectionProfileTestStore(t)
	before := store.Snapshot()
	draft, err := store.BeginDraft("演示待加入网络")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("draft changed formal entries or selected/connected profile")
	}
	if _, err := store.ResolveRoot(draft.ID); err == nil {
		t.Fatal("uncommitted draft resolved as a formal profile")
	}
	root, err := store.ResolveDraftRoot(draft.ID)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "identity-marker")
	if err := os.WriteFile(identity, []byte("demo-protected-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := loadConnectionProfiles(store.base, writeConnectionProfileTestFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.Draft()
	if err != nil || recovered == nil || *recovered != draft {
		t.Fatalf("draft was not recoverable after restart: %+v %v", recovered, err)
	}
	renamed, err := reopened.BeginDraft("恢复后的本地名称")
	if err != nil || renamed.ID != draft.ID {
		t.Fatalf("retry allocated a different identity: %+v %v", renamed, err)
	}
	if _, err := os.Stat(identity); err != nil {
		t.Fatal("retry moved or removed the original identity", err)
	}
	committed, err := reopened.CommitDraft(draft.ID)
	if err != nil || committed.Name != renamed.Name {
		t.Fatal("commit failed", err)
	}
	after := reopened.Snapshot()
	if len(after.Profiles) != len(before.Profiles)+1 || after.Selected != draft.ID || after.LastConnected != before.LastConnected {
		t.Fatalf("commit changed connection or lost new profile: %+v", after)
	}
	if remaining, err := reopened.Draft(); err != nil || remaining != nil {
		t.Fatalf("committed draft was still pending: %+v %v", remaining, err)
	}
}

func TestProfileDraftIndexCommitFailurePreservesRecovery(t *testing.T) {
	store := newConnectionProfileTestStore(t)
	draft, err := store.BeginDraft("演示网络")
	if err != nil {
		t.Fatal(err)
	}
	root, _ := store.ResolveDraftRoot(draft.ID)
	identity := filepath.Join(root, "identity-marker")
	original := []byte("demo-protected-ready-identity")
	if err := os.WriteFile(identity, original, 0o600); err != nil {
		t.Fatal(err)
	}
	before := store.Snapshot()
	marker, err := os.ReadFile(store.draftPath())
	if err != nil {
		t.Fatal(err)
	}
	write := store.writeFile
	store.writeFile = func(path string, body []byte) error {
		if path == store.indexPath() {
			return errors.New("demo atomic index failure")
		}
		return write(path, body)
	}
	if _, err := store.CommitDraft(draft.ID); err == nil || !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatal("failed draft commit changed the formal index")
	}
	body, err := os.ReadFile(identity)
	if err != nil || !bytes.Equal(body, original) {
		t.Fatal("failed commit destroyed the joined identity", err)
	}
	store.writeFile = write
	if _, err := store.CommitDraft(draft.ID); err != nil {
		t.Fatal(err)
	}
	// §13.5：模拟索引提交后、草稿标记删除前崩溃；重启不能重复生成正式条目。
	if err := os.WriteFile(store.draftPath(), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := loadConnectionProfiles(store.base, writeConnectionProfileTestFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if draft, err := reopened.Draft(); err != nil || draft != nil || len(reopened.Snapshot().Profiles) != 2 {
		t.Fatalf("committed draft was duplicated after recovery: %+v %v", draft, err)
	}
}

func TestProfileDraftRejectsCorruptRecoveryMetadata(t *testing.T) {
	for _, kind := range []string{"schema", "unknown", "trailing", "duplicate", "legacy", "path", "control", "missing-root"} {
		t.Run(kind, func(t *testing.T) {
			store := newConnectionProfileTestStore(t)
			draft, err := store.BeginDraft("演示网络")
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(store.draftPath())
			if err != nil {
				t.Fatal(err)
			}
			text := string(body)
			switch kind {
			case "schema":
				text = strings.Replace(text, `"schema":1`, `"schema":2`, 1)
			case "unknown":
				text = strings.Replace(text, `"schema":1`, `"schema":1,"secret":"forbidden"`, 1)
			case "trailing":
				text += `{}`
			case "duplicate":
				text = strings.Replace(text, `"schema":1`, `"schema":1,"schema":1`, 1)
			case "legacy":
				text = strings.ReplaceAll(text, draft.ID, "legacy")
			case "path":
				text = strings.ReplaceAll(text, draft.ID, "../demo")
			case "control":
				text = strings.ReplaceAll(text, draft.Name, `bad\nname`)
			case "missing-root":
				root, _ := store.ResolveDraftRoot(draft.ID)
				if err := os.Remove(root); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(store.draftPath(), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Draft(); err == nil {
				t.Fatal("corrupt recovery metadata accepted")
			}
			if _, err := store.BeginDraft("新邀请"); err == nil {
				t.Fatal("corrupt recovery metadata was replaced with a fresh identity")
			}
		})
	}
}

func TestProfileDraftCannotStartAfterFormalIndexChanges(t *testing.T) {
	store := newConnectionProfileTestStore(t)
	if err := os.WriteFile(store.indexPath(), []byte("demo-corrupted-index"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginDraft("新加入请求"); err == nil {
		t.Fatal("draft creation bypassed a changed formal index")
	}
	if _, err := os.Stat(store.draftPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("draft metadata appeared after formal index corruption", err)
	}
}
