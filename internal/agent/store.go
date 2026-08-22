package agent

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"loom/internal/measure"
)

// store 是度量文件的并发安全外壳,外加一次启动时的压实。
//
// 度量是追加日志,不压实会无限长大 —— 一天 ~9000 行、按天累积。压实只在
// 启动时做一次:运行中重写文件要处理"重写到一半崩了"的窗口,而启动时
// 重写失败最多是这次没起来,不会丢已有数据。
type store struct {
	mu        sync.Mutex
	path      string
	retention time.Duration
	now       func() time.Time
}

func (s *store) append(ms []measure.Measurement) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return measure.Append(s.path, ms)
}

func (s *store) load() ([]measure.Measurement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := measure.Load(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return ms, err
}

func (s *store) compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ms, err := measure.Load(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	cut := s.now().Add(-s.retention)
	kept := ms[:0]
	for i := range ms {
		t, err := time.Parse(time.RFC3339, ms[i].TS)
		if err != nil || t.Before(cut) {
			continue
		}
		kept = append(kept, ms[i])
	}
	if len(kept) == len(ms) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".compact"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := measure.Append(tmp, kept); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
