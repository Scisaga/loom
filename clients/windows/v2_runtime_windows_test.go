//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/clientsecret"
	"loom/internal/windowsv2"
	"loom/internal/wire"
)

func TestWindowsV2PublicCAUsesContentAddressedGenerationAndBoundedCleanup(t *testing.T) {
	root := t.TempDir()
	firstHash := wire.HashRaw("loom-test-windows-v2-ca", []byte("first"))
	secondHash := wire.HashRaw("loom-test-windows-v2-ca", []byte("second"))
	first, err := windowsV2PublicCAPath(root, firstHash)
	if err != nil {
		t.Fatal(err)
	}
	second, err := windowsV2PublicCAPath(root, secondHash)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(filepath.Base(first), "ca-v2-") {
		t.Fatal("v2 public CA path 未绑定 artifact generation")
	}
	if err := writeWindowsV2PublicCA(first, []byte("first-public-ca")); err != nil {
		t.Fatal(err)
	}
	if err := writeWindowsV2PublicCA(second, []byte("second-public-ca")); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(root, "tls", "ca.crt")
	if err := os.WriteFile(legacy, []byte("v1-public-ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupWindowsV2PublicCAs(root, second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(first); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("旧 v2 CA 未清理: %v", err)
	}
	for _, path := range []string{second, legacy} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("清理越过保留边界 %s: %v", filepath.Base(path), err)
		}
	}
}

func TestWindowsV2PreflightCAIsAnExplicitTemporaryFile(t *testing.T) {
	path, err := writeWindowsV2TemporaryCA([]byte("public-ca"))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("preflight CA 不是普通临时文件: %v", err)
	}
	if err := removeWindowsV2RuntimeFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preflight CA 未清理: %v", err)
	}
}

func TestWindowsV2TerminalStartupFinishesCrashInterruptedCleanup(t *testing.T) {
	root := t.TempDir()
	caPath, err := windowsV2PublicCAPath(root,
		wire.HashRaw("loom-test-windows-v2-ca", []byte("terminal")))
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{
		caPath:                           []byte("public-ca"),
		windowsV2JournalPath(root):       []byte("protected-enrollment-placeholder"),
		windowsV2ReportJournalPath(root): []byte("protected-report-placeholder"),
		filepath.Join(root, "runtime", ".sing-box-active-crash.json"): []byte("runtime-secret"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := &windowsv2.StateV1{Envelope: wire.DeviceViewEnvelopeV2{
		Payload: wire.DeviceViewPayloadV2{State: "revoked",
			Tombstone: &wire.DeviceTombstoneViewV1{Reason: "test"}},
	}}
	if _, err := prepareWindowsV2ClientAt(root, clientsecret.UserProtector{},
		editionPortableMixed, state); err == nil {
		t.Fatal("certified tombstone 被当作 active workload")
	}
	for _, path := range []string{caPath, windowsV2JournalPath(root), windowsV2ReportJournalPath(root),
		filepath.Join(root, "runtime", ".sing-box-active-crash.json")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("启动恢复未清理 %s: %v", filepath.Base(path), err)
		}
	}
}
