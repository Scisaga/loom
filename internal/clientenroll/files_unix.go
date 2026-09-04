//go:build !windows

package clientenroll

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func lockStateDir(dir string) (*os.File, error) {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("[§11 安全存储] state-dir 必须是绝对且已清理的路径:%q", dir)
	}
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, enrollmentLock)
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开设备加入锁:%w", err)
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		lock.Close()
		return nil, errors.New("[§11 安全存储] 设备加入锁必须是私有普通文件")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		lock.Close()
		return nil, errors.New("[§11 安全存储] 设备加入锁不得有硬链接")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		lock.Close()
		return nil, fmt.Errorf("获取设备加入锁:%w", err)
	}
	return lock, nil
}

func unlockState(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func secureDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("创建设备身份目录:%w", err)
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("[§11 安全存储] 设备身份目录必须是非链接且权限 0700 的目录")
	}
	return nil
}

func readRegularFile(path string, limit int64, private bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > limit ||
		(private && before.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("[§11 安全存储] %s 必须是权限正确、有界的普通文件", path)
	}
	if stat, ok := before.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return nil, fmt.Errorf("[§11 安全存储] %s 不得有硬链接", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		return nil, fmt.Errorf("[§11 安全存储] %s 在读取期间发生变化", path)
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != after.Size() || int64(len(body)) > limit {
		return nil, fmt.Errorf("[§11 安全存储] 读取 %s 失败或超出边界", path)
	}
	return body, nil
}

func writePrivateAtomic(path string, body []byte, mode os.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("[§11 安全存储] 拒绝覆盖非普通文件 %s", path)
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
			return fmt.Errorf("[§11 安全存储] 拒绝覆盖硬链接 %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
