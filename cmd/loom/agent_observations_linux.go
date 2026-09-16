//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"loom/internal/agent"
	"loom/internal/clientv2"
)

// inotify 只监听同机 daemon 的原子回执文件替换；不另开网络轮询或探测。
func startAgentDeviceObservations(ctx context.Context, cfg *agent.Config, dir string, log io.Writer) (*agent.ObservationCache, func(), error) {
	empty := func() {}
	if ctx == nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || cfg == nil || len(cfg.Peers) != 0 || cfg.SelfReport != "" {
		return nil, empty, errors.New("[Agent v2] 缺正确的本机状态或仍含旧报告来源")
	}
	cache, err := agent.NewObservationCache(cfg)
	if err != nil {
		return nil, empty, err
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, empty, err
	}
	file := os.NewFile(uintptr(fd), "agent-observation-events")
	if file == nil {
		_ = unix.Close(fd)
		return nil, empty, errors.New("[Agent v2] 无法监听本机文件事件")
	}
	var once sync.Once
	done := make(chan struct{})
	closeWatcher := func() { once.Do(func() { close(done); _ = file.Close() }) }
	if _, err := unix.InotifyAddWatch(fd, dir, unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF); err != nil {
		closeWatcher()
		return nil, empty, err
	}
	load := func() error {
		raw, ca, err := clientv2.LinuxAgentObservationInput(filepath.Join(dir, "state.json"), cfg.Node)
		if err != nil {
			return err
		}
		if err := cache.Ingest(ctx, raw, ca, time.Now().UTC()); err != nil {
			fmt.Fprintln(log, "[Agent v2] 无效或过期观测未参与选路:", err)
		}
		return nil
	}
	if err := load(); err != nil {
		closeWatcher()
		return nil, empty, err
	}
	go func() {
		select {
		case <-ctx.Done():
			closeWatcher()
		case <-done:
		}
	}()
	go func() {
		defer closeWatcher()
		buffer := make([]byte, 64<<10)
		for {
			_, err := file.Read(buffer)
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, os.ErrClosed) {
					fmt.Fprintln(log, "[Agent v2] 本机观测事件失败:", err)
				}
				return
			}
			if err := load(); err != nil {
				fmt.Fprintln(log, "[Agent v2] 本机观测更新被拒绝:", err)
			}
		}
	}()
	return cache, closeWatcher, nil
}
