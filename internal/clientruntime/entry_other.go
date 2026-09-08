//go:build !windows

package clientruntime

import (
	"context"
	"errors"
	"time"

	"loom/internal/agent"
)

func entrySource(string) string { return "" }
func pingWindowsEntry(context.Context, agent.ClientEntry) (time.Duration, error) {
	return 0, errors.New("Windows 入口 ping 仅在 Windows 上执行")
}
