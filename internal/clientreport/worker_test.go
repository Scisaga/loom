package clientreport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestDefaultPeriodAndFailureWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sent := make(chan time.Time, 8)
		worker := NewWorker(func(_ context.Context, at time.Time) (*Observation, error) {
			return &Observation{Node: "demo-client", TS: at.Format(time.RFC3339Nano)}, nil
		}, func(_ context.Context, observation *Observation) Result {
			at, err := time.Parse(time.RFC3339Nano, observation.TS)
			if err != nil {
				t.Error(err)
			}
			sent <- at
			return Result{Status: 503, Err: errors.New("unavailable")}
		}, nil)
		go worker.Run(ctx)
		synctest.Wait()
		var previous time.Time
		select {
		case previous = <-sent:
		default:
			t.Fatal("missing initial attempt")
		}
		for range 2 {
			worker.Trigger()
			time.Sleep(59 * time.Second)
			synctest.Wait()
			select {
			case <-sent:
				t.Fatal("failure retried before the next 60-second period")
			default:
			}
			time.Sleep(time.Second)
			synctest.Wait()
			select {
			case at := <-sent:
				if at.Sub(previous) != time.Minute {
					t.Fatal("default reporter period is not 60 seconds")
				}
				previous = at
			default:
				t.Fatal("missing periodic attempt")
			}
		}
		cancel()
		synctest.Wait()
		worker.Trigger()
		time.Sleep(time.Minute)
		synctest.Wait()
		select {
		case <-sent:
			t.Fatal("stopped worker kept reporting")
		default:
		}
	})
}

func TestStrictlyIncreasingNanoTimestamps(t *testing.T) {
	now := time.Now().UTC()
	previous := now
	for _, clock := range []time.Time{now, now.Add(-time.Hour), now.Add(time.Second)} {
		next := nextTimestamp(clock, previous)
		if !next.After(previous) || next.Location() != time.UTC {
			t.Fatal("timestamp did not advance")
		}
		parsed, err := time.Parse(time.RFC3339Nano, next.Format(time.RFC3339Nano))
		if err != nil || !parsed.Equal(next) {
			t.Fatal("lost timestamp precision")
		}
		previous = next
	}
}

func TestWorkerSerialEventsAndFailureWait(t *testing.T) {
	var mu sync.Mutex
	snapshot := "initial"
	sent := make(chan *Observation, 16)
	worker := NewWorker(func(ctx context.Context, at time.Time) (*Observation, error) {
		mu.Lock()
		defer mu.Unlock()
		return &Observation{Node: "demo-client", TS: at.Format(time.RFC3339Nano), Applied: snapshot}, nil
	}, func(ctx context.Context, o *Observation) Result { sent <- o; return Result{Status: 204} }, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); worker.Run(ctx) }()
	next := func() *Observation {
		select {
		case o := <-sent:
			return o
		case <-time.After(time.Second):
			t.Fatal("no report")
		}
		return nil
	}
	first := next()
	mu.Lock()
	snapshot = "restored"
	mu.Unlock()
	worker.Trigger()
	second := next()
	firstAt, _ := time.Parse(time.RFC3339Nano, first.TS)
	secondAt, _ := time.Parse(time.RFC3339Nano, second.TS)
	if second.Applied != "restored" || !secondAt.After(firstAt) {
		t.Fatal("event replayed stale state/time")
	}
	cancel()
	<-done
	// 所有错误只等待下一周期。即使连续激活通知到达，也不能紧密重试。
	for _, retryAfter := range []time.Duration{0, time.Second} {
		sent = make(chan *Observation, 16)
		worker = NewWorker(func(ctx context.Context, at time.Time) (*Observation, error) {
			return &Observation{TS: at.Format(time.RFC3339Nano)}, nil
		},
			func(ctx context.Context, o *Observation) Result {
				sent <- o
				return Result{Status: 503, RetryAfter: retryAfter, Err: errors.New("unavailable")}
			}, nil)
		worker.interval = 100 * time.Millisecond
		ctx, cancel = context.WithCancel(context.Background())
		done = make(chan struct{})
		go func() { defer close(done); worker.Run(ctx) }()
		next()
		for range 10 {
			worker.Trigger()
		}
		select {
		case <-sent:
			t.Fatal("error retried immediately")
		case <-time.After(50 * time.Millisecond):
		}
		if retryAfter > 0 {
			select {
			case <-sent:
				t.Fatal("Retry-After ignored")
			case <-time.After(200 * time.Millisecond):
			}
		} else {
			next()
		}
		cancel()
		<-done
	}
}

func TestWorkerReportsHealthTimeoutWithFreshSendBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		sent := false
		worker := NewWorker(func(ctx context.Context, at time.Time) (*Observation, error) {
			<-ctx.Done()
			return &Observation{Node: "demo-client", TS: at.Format(time.RFC3339Nano)}, nil
		}, func(ctx context.Context, o *Observation) Result {
			if ctx.Err() != nil {
				t.Fatal("health timeout canceled the failure report")
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) != 5*time.Second {
				t.Fatal("report lost its send budget")
			}
			sent = true
			cancel()
			return Result{}
		}, nil)
		worker.Run(ctx)
		if !sent {
			t.Fatal("health timeout was not reported")
		}
	})
}
