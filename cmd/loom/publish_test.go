package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"loom/internal/publish"
	"loom/internal/snapshot"
)

func TestManualPublishBinaryFlagFailsClosedBeforeReadingFiles(t *testing.T) {
	err := cmdPublish([]string{
		"missing-ssot.yaml",
		"-o", "/tmp/not-used",
		"-key", "missing-key",
		"-binary", "deploy/staging/loom",
	})
	if err == nil || !strings.Contains(err.Error(), "loom publish -binary 已禁用") ||
		!strings.Contains(err.Error(), "loom release") {
		t.Fatalf("手工 publish 不得绕过 release gate:%v", err)
	}
}

func TestPublishCommandsRejectDisabledSSOTHistory(t *testing.T) {
	if err := cmdPublish([]string{
		"missing-ssot.yaml", "-o", "/tmp/not-used", "-key", "missing-key", "-ssot-history", "",
	}); err == nil || !strings.Contains(err.Error(), "不允许关闭 -ssot-history") {
		t.Fatalf("手工 publish 不得静默关闭回滚存档:%v", err)
	}
	if err := cmdPublisher([]string{
		"-target", "/tmp/not-used", "-key", "missing-key", "-ssot-history", "", "-once",
	}); err == nil || !strings.Contains(err.Error(), "不允许关闭 -ssot-history") {
		t.Fatalf("publisher 不得静默关闭回滚存档:%v", err)
	}
}

func TestManualPublishConsumesReleasedBinaryInsteadOfStrippingManifest(t *testing.T) {
	ssot, err := os.ReadFile(filepath.Join("..", "..", "testdata", "matrix", "ssot.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ssotPath := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(ssotPath, ssot, 0o600); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "platform.key")
	if err := os.WriteFile(keyPath, []byte(b64(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := publish.ReadBinaryCandidate(exe)
	if err != nil {
		t.Fatal(err)
	}
	releaseDir := t.TempDir()
	if err := publish.WriteReleaseCandidate(releaseDir, candidate, publish.Release{
		Reason: "manual publish binding regression", ReleasedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	oldLock := publishTransactionLockPath
	publishTransactionLockPath = filepath.Join(t.TempDir(), "publisher.lock")
	defer func() { publishTransactionLockPath = oldLock }()
	target := filepath.Join(t.TempDir(), "dist")
	if err := cmdPublish([]string{
		ssotPath, "-o", target, "-key", keyPath,
		"-pin-dir", t.TempDir(), "-release-dir", releaseDir,
		"-ssot-history", t.TempDir(), "-allow-dirty",
	}); err != nil {
		t.Fatal(err)
	}
	curBody, err := os.ReadFile(filepath.Join(target, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cur publish.Current
	if err := json.Unmarshal(curBody, &cur); err != nil {
		t.Fatal(err)
	}
	manifestBody, err := os.ReadFile(filepath.Join(target, cur.Snapshot, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man snapshot.Manifest
	if err := json.Unmarshal(manifestBody, &man); err != nil {
		t.Fatal(err)
	}
	var got *snapshot.BinaryRef
	for i := range man.Binaries {
		if man.Binaries[i].OS == runtime.GOOS && man.Binaries[i].Arch == runtime.GOARCH {
			got = &man.Binaries[i]
			break
		}
	}
	if got == nil || got.SHA256 != candidate.SHA256 || got.Size != candidate.Size {
		t.Fatalf("手工 publish 丢了已 release 二进制:got=%+v want_sha=%s want_size=%d",
			got, candidate.SHA256, candidate.Size)
	}
	if _, err := os.Stat(filepath.Join(target, candidate.SHA256)); err == nil {
		t.Fatal("二进制不应脱离 bin/ 内容寻址目录")
	}
	if _, err := os.Stat(filepath.Join(target, "bin", candidate.SHA256)); err != nil {
		t.Fatalf("已 release 二进制没有进入分发树:%v", err)
	}
}
