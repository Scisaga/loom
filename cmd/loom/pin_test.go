package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/publish"
	"loom/internal/snapshot"
)

func TestRequestedSnapshotIDIsBoundAfterSignatureVerification(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	man := &snapshot.Manifest{ID: "bbbbbbbbbbbb", Bundles: []snapshot.BundleRef{}}
	body, err := man.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := snapshot.Sign(man, priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := verifyRequestedSnapshotManifest("aaaaaaaaaaaa", body, sig, pub); err == nil {
		t.Fatal("不可信分发点把合法签名的 Y 放在 X 路径下时必须拒绝")
	}
	if got, err := verifyRequestedSnapshotManifest(man.ID, body, sig, pub); err != nil || got.ID != man.ID {
		t.Fatalf("路径与已验签 manifest 一致时应通过:got=%+v err=%v", got, err)
	}
}

func TestStageSelfcheckBinaryDoesNotFollowPrecreatedSymlink(t *testing.T) {
	for _, purpose := range []string{"pin", "rollback"} {
		t.Run(purpose, func(t *testing.T) {
			dir := t.TempDir()
			sentinel := filepath.Join(t.TempDir(), "sentinel")
			if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			// 旧实现使用固定名并会跟随这类 symlink。CreateTemp
			// 必须用 O_EXCL 选择另一个唯一 inode。
			trap := filepath.Join(dir, ".loom-"+purpose+"-check-*")
			if err := os.Symlink(sentinel, trap); err != nil {
				t.Fatal(err)
			}
			stage, cleanup, err := stageSelfcheckBinary(dir, purpose, []byte("candidate"))
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if stage == trap {
				t.Fatal("CreateTemp 意外重用了预置 symlink")
			}
			if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
				t.Fatalf("root 自检暂存跟随 symlink 覆写了 sentinel:%q err=%v", got, err)
			}
			if got, err := os.ReadFile(stage); err != nil || string(got) != "candidate" {
				t.Fatalf("唯一暂存文件内容不对:%q err=%v", got, err)
			}
		})
	}
}

func TestRollbackAtomicReplacementDoesNotFollowTargetSymlink(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "ssot.yaml")
	if err := os.Symlink(sentinel, target); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicDurable(target, []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("原子替换跟随了目标 symlink:%q err=%v", got, err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "replacement" {
		t.Fatalf("目标没被新 inode 替换:%q err=%v", got, err)
	}
}

func TestSnapshotIDGrammar(t *testing.T) {
	for _, id := range []string{"", "abc", "AAAAAAAAAAAA", "zzzzzzzzzzzz", "aaaaaaaaaaaaa", "../aaaaaaaaa"} {
		if validSnapshotID(id) {
			t.Fatalf("非法 snapshot id 被接受:%q", id)
		}
	}
	if !validSnapshotID("0123456789ab") {
		t.Fatal("合法 snapshot id 被拒绝")
	}
}

func TestReleaseAndPinMutationsSharePublisherLock(t *testing.T) {
	oldLock := publishTransactionLockPath
	publishTransactionLockPath = filepath.Join(t.TempDir(), "publisher.lock")
	defer func() { publishTransactionLockPath = oldLock }()

	releaseDir := t.TempDir()
	releaseState := filepath.Join(releaseDir, "current.json")
	if err := os.WriteFile(releaseState, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinDir := t.TempDir()
	if err := publish.WritePin(pinDir, &publish.Pin{Snapshot: "aaaaaaaaaaaa", Reason: "keep"}, []byte("binary")); err != nil {
		t.Fatal(err)
	}

	unlock, err := publish.AcquireLock(publishTransactionLockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := cmdRelease([]string{"-clear", "-dir", releaseDir}); err == nil || !strings.Contains(err.Error(), "发布锁") {
		t.Fatalf("release mutation 未与 publisher 共享锁:%v", err)
	}
	if _, err := os.Stat(releaseState); err != nil {
		t.Fatalf("未取锁却清掉了 release:%v", err)
	}
	if err := cmdPin([]string{"-clear", "-dir", pinDir}); err == nil || !strings.Contains(err.Error(), "发布锁") {
		t.Fatalf("pin mutation 未与 publisher 共享锁:%v", err)
	}
	if p, _, err := publish.ReadPin(pinDir); err != nil || p == nil {
		t.Fatalf("未取锁却清掉了 pin:p=%+v err=%v", p, err)
	}
}

func TestRollbackCommitsPinBeforeSSOTAndFailsSafe(t *testing.T) {
	oldLock := publishTransactionLockPath
	publishTransactionLockPath = filepath.Join(t.TempDir(), "publisher.lock")
	defer func() { publishTransactionLockPath = oldLock }()
	ssotPath := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(ssotPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinDir := t.TempDir()
	p := &publish.Pin{Snapshot: "aaaaaaaaaaaa", Reason: "rollback"}
	writer := func(path string, body []byte, mode os.FileMode) error {
		if path == ssotPath {
			return errors.New("injected ssot write failure")
		}
		return writeFileAtomicDurable(path, body, mode)
	}
	_, _, _, err := commitRollbackState(ssotPath, pinDir, p, []byte("binary"), []byte("target"), writer)
	if err == nil || !strings.Contains(err.Error(), "publisher 会保持阻断") {
		t.Fatalf("SSOT 失败后必须明确处于安全阻断:%v", err)
	}
	if got, err := os.ReadFile(ssotPath); err != nil || string(got) != "old" {
		t.Fatalf("SSOT 失败时原文本不应被破坏:%q err=%v", got, err)
	}
	gotPin, _, err := publish.ReadPin(pinDir)
	if err != nil || gotPin == nil || gotPin.Snapshot != p.Snapshot {
		t.Fatalf("必须先落 pin，使 publisher 在中间态 fail-closed:p=%+v err=%v", gotPin, err)
	}
}

func TestRollbackMutationDoesNothingWhenPublishLockBusy(t *testing.T) {
	oldLock := publishTransactionLockPath
	publishTransactionLockPath = filepath.Join(t.TempDir(), "publisher.lock")
	defer func() { publishTransactionLockPath = oldLock }()
	ssotPath := filepath.Join(t.TempDir(), "ssot.yaml")
	if err := os.WriteFile(ssotPath, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinDir := t.TempDir()
	unlock, err := publish.AcquireLock(publishTransactionLockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	_, _, _, err = commitRollbackState(ssotPath, pinDir,
		&publish.Pin{Snapshot: "aaaaaaaaaaaa", Reason: "rollback"},
		[]byte("binary"), []byte("target"), writeFileAtomicDurable)
	if err == nil || !strings.Contains(err.Error(), "发布锁") {
		t.Fatalf("rollback 必须在 publish.lock 竞争时非阻塞失败:%v", err)
	}
	if p, _, err := publish.ReadPin(pinDir); err != nil || p != nil {
		t.Fatalf("未取锁时不得写 pin:p=%+v err=%v", p, err)
	}
	if got, _ := os.ReadFile(ssotPath); string(got) != "old" {
		t.Fatalf("未取锁时不得写 SSOT:%q", got)
	}
}
