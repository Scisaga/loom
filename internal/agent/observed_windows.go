//go:build windows

package agent

import (
	"context"
	"errors"
	"time"
)

// §16.1.2：Windows 没有服务器 report 适配器。必须拒绝观测源配置，不能静默降级。
func validateObservationPlatform(cfg *Config) error {
	if len(cfg.Peers) > 0 || cfg.SelfReport != "" {
		return errors.New("[§16.1.2] Windows Agent 不支持服务器观测源")
	}
	return nil
}

type observed struct{}

func newObserved() *observed                                                     { return &observed{} }
func (*observed) unreachable(string, time.Time, time.Duration) map[string]string { return nil }
func (*observed) len() int                                                       { return 0 }
func pollPeers(context.Context, *Config, *observed, []byte, time.Time, time.Duration, func(string, ...any)) {
}
