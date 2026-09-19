//go:build !windows

package clientdist

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

func readRegularBounded(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("检查客户端制品 %s:%w", path, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > limit {
		return nil, fmt.Errorf("[§10.3 原子安装] 客户端制品 %s 必须是有界、非链接的普通文件", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("打开客户端制品 %s:%w", path, err)
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		return nil, fmt.Errorf("[§10.3 原子安装] 客户端制品 %s 在验证期间发生变化", path)
	}
	if stat, ok := after.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return nil, fmt.Errorf("[§10.3 原子安装] 客户端制品 %s 不得是硬链接", path)
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != after.Size() || int64(len(body)) > limit {
		return nil, fmt.Errorf("读客户端制品 %s 失败", path)
	}
	return body, nil
}
