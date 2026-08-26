package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"loom/internal/snapshot"
)

func TestPrepareBinaryUpgradeStagesVerifiedCandidateWithoutChangingLiveBinary(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "loom")
	if err := os.WriteFile(live, []byte("old-binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("#!/bin/sh\n[ \"$1\" = selfcheck ]\n")
	sum := sha256.Sum256(body)
	want := snapshot.BinaryRef{
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		SHA256: hex.EncodeToString(sum[:]), Size: len(body),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+want.Path() {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	candidate, err := prepareBinaryUpgrade(server.Client(), server.URL, &snapshot.Manifest{
		Binaries: []snapshot.BinaryRef{want},
	}, live, false)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.cleanup()
	if candidate == nil || candidate.staged == "" {
		t.Fatal("锁外准备没有留下已验证候选")
	}
	if filepath.Dir(candidate.staged) != dir {
		t.Fatalf("候选必须与 live binary 同目录，才能锁内原子 rename:%s", candidate.staged)
	}
	if got, err := os.ReadFile(live); err != nil || string(got) != "old-binary\n" {
		t.Fatalf("prepare 阶段改动了 live binary:%q err=%v", got, err)
	}
	if got, err := fileSum(candidate.staged); err != nil || got != want.SHA256 {
		t.Fatalf("候选没有保持签名哈希:got=%s err=%v", got, err)
	}
}

func TestStaleUnitsUsesExecutableIdentityAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "loom")
	old := filepath.Join(dir, "loom-old")
	for path, body := range map[string]string{live: "new", old: "old"} {
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	procRoot := filepath.Join(dir, "proc")
	pid := 101
	exe := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(old, exe); err != nil {
		t.Fatal(err)
	}
	ctl := fakeBinarySystemctl(pid, nil)

	stale, err := staleUnitsWith(live, procRoot, []string{"loom-agent"}, ctl)
	if err != nil || len(stale) != 1 || stale[0] != "loom-agent" {
		t.Fatalf("旧 inode 没被识别:stale=%v err=%v", stale, err)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(live, exe); err != nil {
		t.Fatal(err)
	}
	stale, err = staleUnitsWith(live, procRoot, []string{"loom-agent"}, ctl)
	if err != nil || len(stale) != 0 {
		t.Fatalf("同一 inode 被误报:stale=%v err=%v", stale, err)
	}

	queryFailure := func(args ...string) (string, error) {
		return "", errors.New("systemd unavailable")
	}
	if _, err := staleUnitsWith(live, procRoot, []string{"loom-agent"}, queryFailure); err == nil {
		t.Fatal("systemd 查询失败不能按‘没有 stale unit’继续")
	}
}

func TestRestartBinaryUnitsRequiresCommandSuccessAndNewProcessInode(t *testing.T) {
	for _, tc := range []struct {
		name          string
		restartErr    bool
		switchOnStart bool
		wantErr       bool
	}{
		{name: "restart-error-even-if-old-process-stays-active", restartErr: true, wantErr: true},
		{name: "restart-success-but-old-inode", wantErr: true},
		{name: "restart-success-and-new-inode", switchOnStart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			live := filepath.Join(dir, "loom")
			old := filepath.Join(dir, "loom-old")
			for path, body := range map[string]string{live: "new", old: "old"} {
				if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			procRoot := filepath.Join(dir, "proc")
			pid := 202
			exe := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
			if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(old, exe); err != nil {
				t.Fatal(err)
			}
			base := fakeBinarySystemctl(pid, nil)
			ctl := func(args ...string) (string, error) {
				if args[0] == "restart" {
					if tc.restartErr {
						return "injected", errors.New("restart failed")
					}
					if tc.switchOnStart {
						if err := os.Remove(exe); err != nil {
							return "", err
						}
						if err := os.Symlink(live, exe); err != nil {
							return "", err
						}
					}
					return "", nil
				}
				return base(args...)
			}
			err := restartBinaryUnitsWith(live, procRoot, []string{"loom-agent"}, ctl, func() {})
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got=%v", tc.wantErr, err)
			}
		})
	}
}

func TestLoadedActiveUnitWithoutUnitFileStillUsesInodeGateAndRestarts(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "loom")
	old := filepath.Join(dir, "loom-old")
	for path, body := range map[string]string{live: "new", old: "old"} {
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	procRoot := filepath.Join(dir, "proc")
	pid := 303
	exe := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(old, exe); err != nil {
		t.Fatal(err)
	}

	restarts := 0
	base := fakeBinarySystemctl(pid, nil)
	ctl := func(args ...string) (string, error) {
		switch args[0] {
		case "list-units":
			unit := args[len(args)-1]
			return unit + " loaded active running test", nil
		case "list-unit-files":
			// 磁盘上的 unit 文件已丢，但 systemd 仍 loaded/active。
			return "", nil
		case "restart":
			restarts++
			if err := os.Remove(exe); err != nil {
				return "", err
			}
			if err := os.Symlink(live, exe); err != nil {
				return "", err
			}
			return "", nil
		default:
			return base(args...)
		}
	}

	stale, err := staleUnitsWith(live, procRoot, []string{"loom-publisher"}, ctl)
	if err != nil || len(stale) != 1 || stale[0] != "loom-publisher" {
		t.Fatalf("unit 文件缺失的 loaded 旧进程被漏掉:stale=%v err=%v", stale, err)
	}
	if err := restartBinaryUnitsWith(live, procRoot, []string{"loom-publisher"}, ctl, func() {}); err != nil {
		t.Fatal(err)
	}
	if restarts != 1 {
		t.Fatalf("unit 文件缺失的 loaded 进程没有被重启:restarts=%d", restarts)
	}
}

func fakeBinarySystemctl(pid int, states map[string]string) binarySystemctl {
	return func(args ...string) (string, error) {
		unit := ""
		if len(args) > 1 {
			unit = args[len(args)-1]
		}
		switch args[0] {
		case "list-units":
			return unit + " loaded active running test", nil
		case "list-unit-files":
			return unit + " enabled enabled", nil
		case "is-active":
			if state := states[unit]; state != "" {
				return state, nil
			}
			return "active", nil
		case "show":
			return strconv.Itoa(pid), nil
		case "restart":
			return "", nil
		default:
			return "", errors.New("unexpected systemctl: " + strings.Join(args, " "))
		}
	}
}
