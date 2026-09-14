//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"loom/internal/clientsecret"
)

func windowsV2AcceptanceRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("LOOM_ACCEPT_V2_PROFILE_ROOT")
	if root == "" {
		var err error
		root, err = localAppDataRoot()
		if err != nil {
			t.Fatal(err)
		}
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !localWindowsPath(root) {
		t.Fatal("LOOM_ACCEPT_V2_PROFILE_ROOT 必须是本机规范绝对路径")
	}
	return root
}

func TestWindowsV2PortableMixedLifecycleLive(t *testing.T) {
	if os.Getenv("LOOM_ACCEPT_V2_MIXED_LIFECYCLE") != "1" {
		t.Skip("set LOOM_ACCEPT_V2_MIXED_LIFECYCLE=1 on an ordinary-user active v2 profile")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("Portable Mixed v2 lifecycle 必须以普通用户执行")
	}
	root := windowsV2AcceptanceRoot(t)
	protector := clientsecret.UserProtector{}
	state, err := windowsV2Installed(root, protector)
	if err != nil || state == nil || state.Envelope.Payload.State != "active" {
		t.Fatalf("Portable Mixed 验收要求 active Windows v2 LKG: %v", err)
	}
	if listener, err := net.Listen("tcp", "127.0.0.1:1080"); err != nil {
		t.Fatal("验收前必须断开其他 Loom 数据面")
	} else {
		_ = listener.Close()
	}
	workload, err := prepareWindowsV2ClientAt(root, protector, editionPortableMixed, state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	done := make(chan error, 1)
	go func() { done <- workload(ctx) }()
	started := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		connection, dialErr := net.DialTimeout("tcp", "127.0.0.1:1080", 200*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			started = true
			break
		}
		select {
		case runErr := <-done:
			cancel()
			t.Fatalf("Portable Mixed 在 listener ready 前退出: %v", runErr)
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !started {
		cancel()
		<-done
		t.Fatal("Portable Mixed 未在期限内打开本地 1080 listener")
	}
	select {
	case runErr := <-done:
		cancel()
		t.Fatalf("Portable Mixed 未通过 startup grace: %v", runErr)
	case <-time.After(dataPlaneStartupGrace + 500*time.Millisecond):
	}
	cancel()
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("Portable Mixed 停止失败: %v", runErr)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Portable Mixed 未在期限内停止")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		t.Fatal("Portable Mixed 停止后残留 1080 listener")
	}
	_ = listener.Close()
	paths, err := filepath.Glob(filepath.Join(root, "runtime", ".sing-box-active-*.json"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("Portable Mixed 停止后残留明文 runtime config: %v", err)
	}
	t.Log("Portable Mixed v2 使用 User DPAPI LKG 启动 1080，并在停止后清理 listener/runtime plaintext")
}

func TestWindowsV2TombstoneCleanupLive(t *testing.T) {
	scope := os.Getenv("LOOM_ACCEPT_V2_TOMBSTONE_SCOPE")
	if scope == "" {
		t.Skip("set LOOM_ACCEPT_V2_TOMBSTONE_SCOPE=user|machine after a certified tombstone")
	}
	root := windowsV2AcceptanceRoot(t)
	var protector clientsecret.Protector
	switch scope {
	case "user":
		protector = clientsecret.UserProtector{}
	case "machine":
		if !windows.GetCurrentProcessToken().IsElevated() {
			t.Fatal("machine tombstone cleanup 验收需要提升权限")
		}
		protector = clientsecret.MachineProtector{}
	default:
		t.Fatal("LOOM_ACCEPT_V2_TOMBSTONE_SCOPE 只能是 user 或 machine")
	}
	state, err := windowsV2Installed(root, protector)
	if err != nil || state == nil || state.Envelope.Payload.State == "active" ||
		state.Envelope.Payload.Tombstone == nil {
		t.Fatalf("验收根目录没有 certified Windows v2 tombstone: %v", err)
	}
	if len(state.Enrollment.Configs) != 0 || len(state.Enrollment.Credentials) != 0 ||
		len(state.Enrollment.CurrentSecretArtifactRefs) != 0 {
		t.Fatal("tombstone LKG 仍保留 runtime config 或 credential")
	}
	for _, path := range []string{windowsV2IdentityPath(root), windowsV2ReportJournalPath(root)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("tombstone cleanup 后仍保留 protected runtime material: %v", err)
		}
	}
	paths, err := filepath.Glob(filepath.Join(root, "runtime", ".sing-box-active-*.json"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("tombstone cleanup 后仍保留明文 runtime config: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "tls"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "ca-v2-") && strings.HasSuffix(entry.Name(), ".crt") {
			t.Fatal("tombstone cleanup 后仍保留 v2 runtime CA")
		}
	}
	t.Log("certified tombstone 保留公开 LKG 证据，并清除了 CNG descriptor、credential、runtime config 与 report journal")
}
