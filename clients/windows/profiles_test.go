package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// §13.5：测试以同目录临时文件模拟宿主注入的原子写入，故障发生在替换前。
func writeConnectionProfileTestFile(path string, body []byte) (retErr error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".profiles-test-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func newConnectionProfileTestStore(t *testing.T) *connectionProfileStore {
	t.Helper()
	store, err := loadConnectionProfiles(t.TempDir(), writeConnectionProfileTestFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestConnectionProfilesPreserveLegacyIdentityAndIsolateRoots(t *testing.T) {
	base := t.TempDir()
	identity := filepath.Join(base, "join", "identity.json.dpapi")
	if err := os.MkdirAll(filepath.Dir(identity), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("demo-encrypted-identity-preserved-byte-for-byte")
	if err := os.WriteFile(identity, original, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(identity)
	if err != nil {
		t.Fatal(err)
	}
	store, err := loadConnectionProfiles(base, writeConnectionProfileTestFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	initial := store.Snapshot()
	if initial.Schema != 1 || len(initial.Profiles) != 1 || initial.Profiles[0].Name != "Loom 网络" || initial.Selected != "legacy" || initial.LastConnected != "legacy" {
		t.Fatalf("unexpected initial profiles: %+v", initial)
	}
	root, err := store.ResolveRoot("legacy")
	if err != nil || root != base {
		t.Fatalf("legacy root changed: %q, %v", root, err)
	}
	first, err := store.Add("工作网络")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Add("演示网络")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.ID == "legacy" || second.ID == "legacy" || !validConnectionProfileID(first.ID) || !validConnectionProfileID(second.ID) {
		t.Fatalf("profiles did not receive independent identifiers: %+v / %+v", first, second)
	}
	firstRoot, err := store.ResolveRoot(first.ID)
	if err != nil || firstRoot != filepath.Join(base, "profiles", first.ID) {
		t.Fatalf("unexpected first profile root %q: %v", firstRoot, err)
	}
	secondRoot, err := store.ResolveRoot(second.ID)
	if err != nil || secondRoot == firstRoot || secondRoot == base {
		t.Fatalf("profile root isolation failed: %q: %v", secondRoot, err)
	}
	for _, subpath := range []string{"join/identity.json.dpapi", "state/preference.json", "state/agent/measurements.json"} {
		path := filepath.Join(firstRoot, filepath.FromSlash(subpath))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("demo-profile-specific-state"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(secondRoot, filepath.FromSlash(subpath))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("profile state leaked across roots: %s", subpath)
		}
	}
	if err := store.Rename(first.ID, "工作网络（本地名称）"); err != nil {
		t.Fatal(err)
	}
	if err := store.Select(first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLastConnected(second.ID); err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadConnectionProfiles(base, writeConnectionProfileTestFile, nil)
	if err != nil || !reflect.DeepEqual(reloaded.Snapshot(), store.Snapshot()) {
		t.Fatalf("index did not round trip: %v", err)
	}
	after, err := os.Stat(identity)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("original identity was replaced or touched: %v", err)
	}
	body, err := os.ReadFile(identity)
	if err != nil || !bytes.Equal(body, original) {
		t.Fatalf("original identity changed: %v", err)
	}
	copy := store.Snapshot()
	copy.Profiles[0].Name = "不应污染存储"
	if store.Snapshot().Profiles[0].Name != "Loom 网络" {
		t.Fatal("snapshot aliases mutable store data")
	}
}

func TestConnectionProfilesRemoveOnlyUpdatesIndex(t *testing.T) {
	store := newConnectionProfileTestStore(t)
	profile, err := store.Add("保留网络")
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.ResolveRoot(profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "identity-marker")
	if err := os.WriteFile(marker, []byte("demo-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Select("legacy"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("legacy"); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if len(snapshot.Profiles) != 1 || snapshot.Selected != profile.ID || snapshot.LastConnected != "" {
		t.Fatalf("removing legacy damaged other profile selection: %+v", snapshot)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("removing legacy deleted another identity: %v", err)
	}
	if _, err := store.ResolveRoot("legacy"); err == nil {
		t.Fatal("removed legacy identifier still resolves")
	}
	if err := store.SetLastConnected(profile.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(profile.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("index-only remove unexpectedly deleted identity: %v", err)
	}
	reloaded, err := loadConnectionProfiles(store.base, writeConnectionProfileTestFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty := reloaded.Snapshot()
	if len(empty.Profiles) != 0 || empty.Selected != "" || empty.LastConnected != "" {
		t.Fatalf("empty index incorrectly recreated legacy: %+v", empty)
	}
	fresh, err := reloaded.Add("全新网络")
	if err != nil || fresh.ID == "legacy" || fresh.ID == profile.ID {
		t.Fatalf("new profile reused a deleted identity root: %+v, %v", fresh, err)
	}
}

func TestConnectionProfilesMissingIndexDoesNotHideExistingIdentities(t *testing.T) {
	store := newConnectionProfileTestStore(t)
	profile, err := store.Add("保留身份网络")
	if err != nil {
		t.Fatal(err)
	}
	root, err := store.ResolveRoot(profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "join", "identity.json.dpapi")
	if err := os.MkdirAll(filepath.Dir(identity), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("demo-encrypted-profile-identity")
	if err := os.WriteFile(identity, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.indexPath()); err != nil {
		t.Fatal(err)
	}
	writes := 0
	if _, err := loadConnectionProfiles(store.base, func(string, []byte) error { writes++; return nil }, nil); err == nil || writes != 0 {
		t.Fatalf("missing index hid an existing profile: writes=%d err=%v", writes, err)
	}
	if _, err := os.Stat(store.indexPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing index was silently recreated: %v", err)
	}
	body, err := os.ReadFile(identity)
	if err != nil || !bytes.Equal(body, original) {
		t.Fatalf("existing profile identity was modified: %v", err)
	}
	// §13.5：空目录不代表多身份已存在，仍允许旧单身份首次登记为 legacy。
	empty := t.TempDir()
	if err := os.Mkdir(filepath.Join(empty, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	initialized, err := loadConnectionProfiles(empty, writeConnectionProfileTestFile, nil)
	if err != nil || initialized.Snapshot().Selected != legacyConnectionProfile {
		t.Fatalf("empty profiles directory blocked legacy initialization: %v", err)
	}
}

func TestConnectionProfilesRejectCorruptIndexWithoutOverwriting(t *testing.T) {
	valid := `{"schema":1,"profiles":[{"id":"legacy","name":"Loom 网络"}],"selected":"legacy","last_connected":"legacy"}`
	for name, body := range map[string]string{
		"schema":          strings.Replace(valid, `"schema":1`, `"schema":2`, 1),
		"unknown":         strings.Replace(valid, `"schema":1`, `"schema":1,"extra":true`, 1),
		"unknown_profile": strings.Replace(valid, `"id":"legacy"`, `"id":"legacy","path":"../other"`, 1),
		"trailing":        valid + `{}`,
		"truncated":       valid[:len(valid)-1],
		"empty":           "",
		"null":            "null",
		"null_list":       `{"schema":1,"profiles":null,"selected":""}`,
		"missing_select":  `{"schema":1,"profiles":[]}`,
		"null_select":     `{"schema":1,"profiles":[],"selected":null}`,
		"null_last":       `{"schema":1,"profiles":[],"selected":"","last_connected":null}`,
		"duplicate_field": strings.Replace(valid, `"schema":1`, `"schema":1,"schema":1`, 1),
		"duplicate_name":  `{"schema":1,"profiles":[{"id":"legacy","name":"Demo"},{"id":"00112233445566778899aabbccddeeff","name":"demo"}],"selected":"legacy"}`,
		"duplicate_id":    `{"schema":1,"profiles":[{"id":"legacy","name":"一"},{"id":"legacy","name":"二"}],"selected":"legacy"}`,
		"path_id":         strings.ReplaceAll(valid, `legacy`, `../outside`),
		"unknown_select":  strings.Replace(valid, `"selected":"legacy"`, `"selected":"00112233445566778899aabbccddeeff"`, 1),
		"unknown_last":    strings.Replace(valid, `"last_connected":"legacy"`, `"last_connected":"00112233445566778899aabbccddeeff"`, 1),
		"control_name":    strings.Replace(valid, `Loom 网络`, `bad\u000aname`, 1),
		"invalid_utf8":    strings.Replace(valid, `Loom 网络`, "bad\xffname", 1),
		"oversized":       strings.Repeat(" ", maxConnectionIndexBytes) + valid,
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "state", "profiles.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			writes := 0
			_, err := loadConnectionProfiles(base, func(string, []byte) error { writes++; return nil }, nil)
			if err == nil || writes != 0 {
				t.Fatalf("corrupt index accepted or overwritten: writes=%d err=%v", writes, err)
			}
			actual, err := os.ReadFile(path)
			if err != nil || string(actual) != body {
				t.Fatalf("corrupt index was modified: %v", err)
			}
		})
	}
}

func TestConnectionProfilesAtomicFailureKeepsDiskAndMemory(t *testing.T) {
	store := newConnectionProfileTestStore(t)
	before := store.Snapshot()
	disk, err := os.ReadFile(store.indexPath())
	if err != nil {
		t.Fatal(err)
	}
	store.writeFile = func(path string, body []byte) error {
		file, err := os.CreateTemp(filepath.Dir(path), ".profiles-failed-*")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		defer file.Close()
		if _, err := file.Write(body); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		return errors.New("demo replacement failure")
	}
	if err := store.Rename("legacy", "失败修改"); err == nil {
		t.Fatal("failed replacement reported success")
	}
	if _, err := store.Add("失败新配置"); err == nil {
		t.Fatal("failed addition reported success")
	}
	if err := store.Remove("legacy"); err == nil {
		t.Fatal("failed removal reported success")
	}
	after, err := os.ReadFile(store.indexPath())
	if err != nil || !bytes.Equal(disk, after) || !reflect.DeepEqual(before, store.Snapshot()) {
		t.Fatalf("atomic failure changed durable or in-memory state: %v", err)
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(store.indexPath()), ".profiles-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary index leaked: %v, %v", matches, err)
	}
}

func TestConnectionProfilesRejectInvalidMutationsAndStaleWriters(t *testing.T) {
	store := newConnectionProfileTestStore(t)
	for _, name := range []string{"", " ", " lead", "tail ", "line\nfeed", "nul\x00", "bidi\u202e", strings.Repeat("名", 65), "Loom 网络"} {
		if _, err := store.Add(name); err == nil {
			t.Errorf("invalid/duplicate name accepted: %q", name)
		}
	}
	for _, id := range []string{"", "..", "../legacy", `..\legacy`, "LEGACY", "/tmp", `C:\outside`, strings.Repeat("a", 31), strings.Repeat("A", 32), strings.Repeat("a", 32)} {
		if _, err := store.ResolveRoot(id); err == nil {
			t.Errorf("invalid/unregistered root accepted: %q", id)
		}
		if err := store.Select(id); err == nil {
			t.Errorf("invalid selection accepted: %q", id)
		}
	}
	if err := store.SetLastConnected(""); err != nil {
		t.Fatal(err)
	}
	stale, err := loadConnectionProfiles(store.base, writeConnectionProfileTestFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Rename("legacy", "已更新网络"); err != nil {
		t.Fatal(err)
	}
	if err := stale.Rename("legacy", "覆盖其他操作"); err == nil {
		t.Fatal("stale store overwrote newer index")
	}
	if err := os.WriteFile(store.indexPath(), []byte("corrupt after load"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Rename("legacy", "覆盖损坏索引"); err == nil {
		t.Fatal("store silently overwrote corruption after load")
	}
}

func TestConnectionProfilesRejectLinksAndPlatformUnsafePaths(t *testing.T) {
	for _, part := range []string{"state", "profiles", "profile", "index"} {
		t.Run(part, func(t *testing.T) {
			store := newConnectionProfileTestStore(t)
			outside := t.TempDir()
			path := filepath.Join(store.base, part)
			if part == "profile" {
				profile, err := store.Add("演示网络")
				if err != nil {
					t.Fatal(err)
				}
				path, err = store.ResolveRoot(profile.ID)
				if err != nil {
					t.Fatal(err)
				}
			} else if part == "index" {
				path = store.indexPath()
				outside = filepath.Join(outside, "profiles.json")
				if err := os.WriteFile(outside, store.body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Skipf("creating a symlink requires native platform privileges: %v", err)
			}
			if _, err := loadConnectionProfiles(store.base, writeConnectionProfileTestFile, nil); err == nil {
				t.Fatal("linked profile state accepted")
			}
		})
	}
	base := t.TempDir()
	blocked := filepath.Join(base, "state")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := loadConnectionProfiles(base, writeConnectionProfileTestFile, func(path string) error {
		if path == blocked {
			return errors.New("demo reparse point rejected")
		}
		return nil
	})
	if err == nil {
		t.Fatal("platform path protection callback was bypassed")
	}
}

func TestConnectionProfilesConcurrentSnapshotsAndSelection(t *testing.T) {
	store := newConnectionProfileTestStore(t)
	profile, err := store.Add("第二网络")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Go(func() {
			for iteration := 0; iteration < 12; iteration++ {
				id := "legacy"
				if iteration%2 == 0 {
					id = profile.ID
				}
				if err := store.Select(id); err != nil {
					t.Error(err)
					return
				}
				if _, err := store.ResolveRoot(store.Snapshot().Selected); err != nil {
					t.Error(fmt.Errorf("concurrent selection did not resolve: %w", err))
					return
				}
			}
		})
	}
	workers.Wait()
}
