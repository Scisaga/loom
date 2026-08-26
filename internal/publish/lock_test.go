package publish

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishLockRejectsConcurrentTransactionAndReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publisher.lock")
	unlock, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(path); err == nil || !strings.Contains(err.Error(), "另一笔发布事务") {
		t.Fatalf("第二名签名者必须 fail-closed:%v", err)
	}
	unlock()

	unlockAgain, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("事务结束后锁应可重新取得:%v", err)
	}
	unlockAgain()
}

func TestPublishLockRejectsRelativePath(t *testing.T) {
	if _, err := AcquireLock("relative.lock"); err == nil {
		t.Fatal("发布锁不能落到随工作目录漂移的相对路径")
	}
}
