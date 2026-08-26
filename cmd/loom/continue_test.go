package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 续跑的子进程正常情况下不会再换二进制(哈希已经对上了),所以深度天然
// 是 1。但**"正常情况"是个假设**,而这个假设错了的代价是 fork 炸弹 ——
// 每一层都再起一个子进程,直到机器躺下。所以显式挡一道,并且钉住。
func TestContinuePullRefusesToNest(t *testing.T) {
	t.Setenv(contEnv, "1")
	_, err := continuePull("/bin/true", nil, "snapshot-a", nil)
	if err == nil {
		t.Fatal("已经在续跑里了还要再续跑,必须拒绝")
	}
	if !strings.Contains(err.Error(), "套娃") {
		t.Errorf("错误要说清楚为什么拒绝,得到:%v", err)
	}
}

// 标记必须真的传给子进程 —— 传不下去的话上面那道防护形同虚设。
// 用一个只做一件事的脚本来验:把它看到的环境变量写进文件。
func TestContinuePullMarksTheChild(t *testing.T) {
	if os.Getenv(contEnv) != "" {
		t.Skip("外层已经设了这个变量")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "seen")
	script := filepath.Join(dir, "probe.sh")
	// $1 是 continuePull 硬塞的 "pull",这里不关心。
	body := "#!/bin/sh\nprintf '%s' \"$" + contEnv + "\" > " + out + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	lock := testDeployLock(t)
	if _, err := continuePull(script, nil, "snapshot-a", lock); err != nil {
		t.Fatalf("子进程该正常退出:%v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1" {
		t.Fatalf("子进程看到的 %s = %q,应该是 \"1\"", contEnv, got)
	}
}

// 单个布尔环境变量不能把一次普通 pull 伪装成续跑；必须有结构化阶段通道。
func TestContinuationRequiresStructuredChannel(t *testing.T) {
	t.Setenv(contEnv, "1")
	if _, err := continuationReporterFromEnv(); err == nil {
		t.Fatal("只有环境布尔标记不能绕过锁")
	}
	statusPath := filepath.Join(t.TempDir(), "continuation.json")
	t.Setenv(contStatusEnv, statusPath)
	t.Setenv(contSnapshotEnv, "snapshot-a")
	reporter, err := continuationReporterFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	_ = reporter
	status, err := readContinuationStatus(statusPath, "snapshot-a")
	if err != nil || status.Phase != continuationPreConfig {
		t.Fatalf("子进程必须先给出可验证的 pre_config 阶段，得到 %+v(err=%v)", status, err)
	}
}

func testDeployLock(t *testing.T) *nodeDeployLock {
	t.Helper()
	lock, busy, err := acquireNodeDeployLock(filepath.Join(t.TempDir(), "deploy.lock"))
	if err != nil || busy || lock == nil {
		t.Fatalf("测试部署锁失败:lock=%v busy=%v err=%v", lock, busy, err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	return lock
}

// deploy.Script 成功后，applied 的 mkdir/write 仍可能因只读文件系统或磁盘满
// 失败。此时配置已经是新版；父进程若一概恢复 .prev，会主动制造旧代码 + 新
// 配置。committed/configuring/unknown 都必须保留新二进制。
func TestContinuationFailureAfterConfigMayHaveStartedNeverRestoresBinary(t *testing.T) {
	for _, phase := range []continuationPhase{"", continuationConfiguring, continuationCommitted} {
		t.Run(string(phase), func(t *testing.T) {
			called := false
			status := continuationStatus{
				Version: continuationProtocolVersion, Phase: phase, Snapshot: "snapshot-a",
			}
			err := handleContinuationFailure("/not/touched", status, errors.New("injected applied write failure"),
				func(string) error { called = true; return nil })
			if err == nil {
				t.Fatal("续跑失败必须向上返回")
			}
			if called {
				t.Fatalf("阶段 %q 不能恢复旧二进制", phase)
			}
			if !strings.Contains(err.Error(), "保留新二进制") {
				t.Fatalf("错误必须解释安全取舍，得到:%v", err)
			}
		})
	}
}

func TestAppliedWriteFailureLeavesNewBinaryOnDisk(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "loom")
	if err := os.WriteFile(bin, []byte("new-binary-for-new-config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".prev", []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	status := continuationStatus{
		Version: continuationProtocolVersion, Phase: continuationCommitted, Snapshot: "snapshot-a",
	}
	_ = handleContinuationFailure(bin, status, errors.New("injected applied write failure"), restorePreviousFile)
	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-binary-for-new-config" {
		t.Fatalf("配置已提交后不得换回旧二进制，磁盘得到 %q", got)
	}
	if _, err := os.Stat(bin + ".prev"); err != nil {
		t.Fatalf("保留新二进制时也应保留人工回退副本:%v", err)
	}
}

func TestContinuationFailureBeforeConfigRestoresBinary(t *testing.T) {
	called := false
	status := continuationStatus{
		Version: continuationProtocolVersion, Phase: continuationPreConfig, Snapshot: "snapshot-a",
	}
	err := handleContinuationFailure("/fake/loom", status, errors.New("injected download failure"),
		func(path string) error {
			called = path == "/fake/loom"
			return nil
		})
	if err == nil || !called {
		t.Fatalf("能证明配置未触碰时应恢复旧版，called=%v err=%v", called, err)
	}
	if !strings.Contains(err.Error(), "配置提交前失败") {
		t.Fatalf("错误没有报告精确阶段:%v", err)
	}
}

func TestRestorePreviousFileAfterContinuationFailure(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "loom")
	if err := os.WriteFile(bin, []byte("new-but-continuation-failed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".prev", []byte("known-good"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := restorePreviousFile(bin); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(bin)
	if err != nil || string(b) != "known-good" {
		t.Fatalf("continuation 失败后没有恢复 .prev:%q(err=%v)", b, err)
	}
	if _, err := os.Stat(bin + ".prev"); !os.IsNotExist(err) {
		t.Fatalf(".prev 应通过原子 rename 被消费,得到:%v", err)
	}
}

func TestRestorePreviousFileRefusesMissingOrEmptyFallback(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "loom")
	if err := restorePreviousFile(bin); err == nil {
		t.Fatal("没有 .prev 时不能声称已经恢复")
	}
	if err := os.WriteFile(bin+".prev", nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := restorePreviousFile(bin); err == nil {
		t.Fatal("空 .prev 不能覆盖当前二进制")
	}
}
