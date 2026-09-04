//go:build !windows

package publish

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// LockPath 串行化中控上每一次 Build→Push→Verify→存档/历史事务。
//
// snapshot ID 不含时间/作者；两名签名者可为同一 ID 生成不同 manifest/sig，
// 逐文件交错后留下不配对的签名。锁只覆盖一次实际发布，不覆盖 daemon 的
// 整个生命周期，因此手工 publish 在 daemon 空闲时仍可使用。
const LockPath = "/var/lib/loom/publisher.lock"

func AcquireLock(path string) (func(), error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("发布锁路径不安全:%q", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建发布锁目录:%w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开发布锁 %s:%w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("发布锁 %s 已被占用；另一笔发布事务正在运行，请稍后重试", path)
		}
		return nil, fmt.Errorf("取得发布锁 %s:%w", path, err)
	}
	return func() { _ = f.Close() }, nil
}
