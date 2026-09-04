//go:build windows

package clientenroll

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockStateDir(dir string) (*os.File, error) {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("[§11 安全存储] state-dir 必须是绝对且已清理的路径:%q", dir)
	}
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, enrollmentLock), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开设备加入锁:%w", err)
	}
	if ok, err := windowsSingleLink(lock); err != nil || !ok {
		lock.Close()
		return nil, errors.New("[§11 安全存储] 设备加入锁必须是无硬链接的普通文件")
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		lock.Close()
		return nil, fmt.Errorf("获取设备加入锁:%w", err)
	}
	return lock, nil
}

func unlockState(lock *os.File) {
	if lock == nil {
		return
	}
	_ = windows.UnlockFileEx(windows.Handle(lock.Fd()), 0, 1, 0, new(windows.Overlapped))
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
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("[§11 安全存储] 设备身份目录必须是非链接目录")
	}
	return nil
}

func readRegularFile(path string, limit int64, _ bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > limit {
		return nil, fmt.Errorf("[§11 安全存储] %s 必须是有界普通文件", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if ok, err := windowsSingleLink(f); err != nil || !ok {
		return nil, fmt.Errorf("[§11 安全存储] %s 不得有硬链接", path)
	}
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

func writePrivateAtomic(path string, body []byte, _ os.FileMode) (retErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("[§11 安全存储] 拒绝覆盖非普通文件 %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer func() {
		_ = f.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func windowsSingleLink(file *os.File) (bool, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false, err
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &handleInfo); err != nil {
		return false, err
	}
	return handleInfo.NumberOfLinks == 1, nil
}
