package report

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// listenControlUISocket 只接管精确的 root-only Unix socket。残留 socket
// 可以清理，但活跃 listener 或同名普通文件必须失败关闭，避免把
// 管理 handler 意外接到不受信边界。
func listenControlUISocket(path string) (net.Listener, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("拒绝覆盖非 socket 路径 %s", path)
		}
		connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("Unix socket %s 已有活跃 listener", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("清理残留 Unix socket %s: %w", path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("检查 Unix socket %s: %w", path, err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return listener, nil
}

func removeControlUISocket(path string) {
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
}
