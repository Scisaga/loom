//go:build windows

package main

import (
	"context"
	"errors"
	"time"

	"loom/internal/clientreport"
	"loom/internal/nodepresence"
)

const windowsPresenceSendTimeout = 4 * time.Second

// windowsPresenceWorker 与分钟级 Observation worker 完全分离。它只依赖已登记
// Device 身份和 HTTPS report 入口，不读取或等待 WireGuard/Hysteria 数据面（§16.4）。
type windowsPresenceWorker struct {
	interval time.Duration
	now      func() time.Time
	sign     func(time.Time) (nodepresence.Heartbeat, error)
	send     func(context.Context, *nodepresence.Heartbeat) clientreport.Result
	result   func(clientreport.Result)
}

func newWindowsPresenceWorker(node string, keyPEM []byte,
	send func(context.Context, *nodepresence.Heartbeat) clientreport.Result,
	result func(clientreport.Result),
) *windowsPresenceWorker {
	return &windowsPresenceWorker{
		interval: nodepresence.Period,
		now:      time.Now,
		sign: func(at time.Time) (nodepresence.Heartbeat, error) {
			return nodepresence.Sign(node, at, keyPEM)
		},
		send:   send,
		result: result,
	}
}

func (worker *windowsPresenceWorker) Run(ctx context.Context) {
	if worker == nil || worker.interval <= 0 || worker.now == nil || worker.sign == nil || worker.send == nil {
		if worker != nil && worker.result != nil {
			worker.result(clientreport.Result{Err: errors.New("[§16.4 Windows 在线心跳] worker 配置不完整")})
		}
		return
	}
	ticker := time.NewTicker(worker.interval)
	defer ticker.Stop()
	var previous time.Time

	pulse := func() bool {
		at := nextWindowsPresenceTimestamp(worker.now(), previous)
		heartbeat, err := worker.sign(at)
		result := clientreport.Result{}
		if err != nil {
			result.Err = errors.New("[§16.4 Windows 在线心跳] 无法使用已登记身份签名")
		} else {
			// 成功构造就推进本 worker 的签名时间；传输失败时也不重放旧包。
			previous = at
			attempt, cancel := context.WithTimeout(ctx, windowsPresenceSendTimeout)
			result = worker.send(attempt, &heartbeat)
			cancel()
		}
		if ctx.Err() != nil {
			return false
		}
		if worker.result != nil {
			worker.result(result)
		}
		return true
	}

	// 进程已启动且身份已登记时立即建立首个 lease；随后保持五秒节拍（§16.4）。
	if !pulse() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !pulse() {
				return
			}
		}
	}
}

func nextWindowsPresenceTimestamp(now, previous time.Time) time.Time {
	now = now.UTC()
	if !now.After(previous) {
		return previous.Add(time.Nanosecond).UTC()
	}
	return now
}
