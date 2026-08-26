package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/rollout"
)

func TestDeployLockMakesApplyInvalidationVisibleBeforePullReadsCoordinates(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "deploy.lock")
	statePath := filepath.Join(dir, "applied")
	rolloutPath := filepath.Join(dir, "rollout.json")
	if err := os.WriteFile(statePath, []byte("old-snapshot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &rollout.Record{Snapshot: "old-snapshot", Stage: rollout.Verified}
	if err := rec.Write(rolloutPath); err != nil {
		t.Fatal(err)
	}

	// holder 模拟已进入事务、正准备失效坐标的 manual apply。并发 pull
	// 拿不到锁，因此不能在这里读取并缓存 old-snapshot。
	holder, busy, err := acquireNodeDeployLock(lockPath)
	if err != nil || busy {
		t.Fatalf("apply 取锁:busy=%v err=%v", busy, err)
	}
	if contender, busy, err := acquireNodeDeployLock(lockPath); err != nil || !busy || contender != nil {
		t.Fatalf("并发 pull 应在读坐标前被挡住:lock=%v busy=%v err=%v", contender, busy, err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rolloutPath); err != nil {
		t.Fatal(err)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}

	pullLock, busy, err := acquireNodeDeployLock(lockPath)
	if err != nil || busy {
		t.Fatalf("apply 提交后 pull 应取得锁:busy=%v err=%v", busy, err)
	}
	defer pullLock.Close()
	applied, previous, err := readPullCoordinates(statePath, rolloutPath)
	if err != nil {
		t.Fatal(err)
	}
	if applied != "" || previous != nil {
		t.Fatalf("pull 读到了 apply 失效前的 stale 坐标:applied=%q rollout=%+v", applied, previous)
	}
}

func TestInheritedDeployLockSurvivesParentClose(t *testing.T) {
	if os.Getenv("LOOM_TEST_INHERITED_LOCK") == "1" {
		path := os.Getenv("LOOM_TEST_LOCK_PATH")
		lock, err := inheritNodeDeployLock(path)
		if err != nil {
			t.Fatalf("子进程采用继承锁:%v", err)
		}
		defer lock.Close()
		if err := os.WriteFile(os.Getenv("LOOM_TEST_READY"), []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(os.Getenv("LOOM_TEST_RELEASE")); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("等待父进程 release 超时")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "deploy.lock")
	ready := filepath.Join(dir, "ready")
	release := filepath.Join(dir, "release")
	parent, busy, err := acquireNodeDeployLock(path)
	if err != nil || busy {
		t.Fatalf("父进程取锁:busy=%v err=%v", busy, err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInheritedDeployLockSurvivesParentClose$")
	cmd.Env = append(os.Environ(),
		"LOOM_TEST_INHERITED_LOCK=1",
		"LOOM_TEST_LOCK_PATH="+path,
		"LOOM_TEST_READY="+ready,
		"LOOM_TEST_RELEASE="+release,
	)
	if _, err := parent.inheritTo(cmd); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, ready)
	// 模拟旧版父 pull 在等待 continuation 时退出。继承 fd 的新版子进程
	// 必须继续把 apply/pull 挡在事务外。
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if contender, busy, err := acquireNodeDeployLock(path); err != nil || !busy || contender != nil {
		t.Fatalf("父 fd 关闭后子进程没有继续持锁:lock=%v busy=%v err=%v", contender, busy, err)
	}
	if err := os.WriteFile(release, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	lock, busy, err := acquireNodeDeployLock(path)
	if err != nil || busy {
		t.Fatalf("子进程退出后锁未释放:busy=%v err=%v", busy, err)
	}
	_ = lock.Close()
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待 %s 超时", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
