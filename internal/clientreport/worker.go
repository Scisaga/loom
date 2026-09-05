package clientreport

import (
	"context"
	"errors"
	"time"
)

const Period = time.Minute

// Worker 串行采集和发送；wake 只保留一次激活/恢复通知，不缓存旧报告。
type Worker struct {
	Sample   func(context.Context, time.Time) (*Observation, error)
	Send     func(context.Context, *Observation) Result
	Result   func(Result)
	wake     chan struct{}
	interval time.Duration
}

func NewWorker(sample func(context.Context, time.Time) (*Observation, error), send func(context.Context, *Observation) Result,
	result func(Result)) *Worker {
	return &Worker{Sample: sample, Send: send, Result: result, wake: make(chan struct{}, 1), interval: Period}
}

func (worker *Worker) Trigger() {
	select {
	case worker.wake <- struct{}{}:
	default:
	}
}

func nextTimestamp(now, previous time.Time) time.Time {
	now = now.UTC()
	if !now.After(previous) {
		return previous.Add(time.Nanosecond).UTC()
	}
	return now
}

func (worker *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(worker.interval)
	defer ticker.Stop()
	var previousTS, notBefore time.Time
	waitForTick := false
	worker.Trigger()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			waitForTick = false
		case <-worker.wake:
			if waitForTick {
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		if time.Now().Before(notBefore) {
			continue
		}
		at := nextTimestamp(time.Now(), previousTS)
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		observation, err := worker.Sample(attempt, at)
		if err == nil && observation == nil {
			cancel()
			continue
		} // 尚未激活、切换中或已退出，不刷新旧报告。
		result := Result{Err: errors.New("[D98 上报] 无法生成可信本机状态")}
		if err == nil {
			previousTS = at // 成功构造即推进；发送失败也不能重放这个时间戳。
			result = worker.Send(attempt, observation)
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		if worker.Result != nil {
			worker.Result(result)
		}
		notBefore = time.Now().Add(result.RetryAfter)
		waitForTick = result.Err != nil
	}
}
