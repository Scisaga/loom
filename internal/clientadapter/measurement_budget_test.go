package clientadapter

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNodeMeasurementBudgetSharesInflightAndCancelsOnlyAfterLastConsumer(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	budget, err := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 2, Concurrent: 1, Bytes: 1024, Timeout: time.Second}, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	started, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	run := func(ctx context.Context) (string, error) {
		calls.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-finish:
			markMeasurementCompletion(ctx)
			return "demo-result", nil
		}
	}
	first, cancel := context.WithCancel(context.Background())
	first, firstTiming := captureMeasurementTime(first, func() time.Time { return at })
	firstDone := make(chan error, 1)
	go func() { _, err := runMeasurementOn(first, budget, "demo-same", 512, run); firstDone <- err }()
	<-started
	secondDone := make(chan error, 1)
	second, secondTiming := captureMeasurementTime(context.Background(), func() time.Time { return at.Add(time.Hour) })
	go func() {
		value, err := runMeasurementOn(second, budget, "demo-same", 512, run)
		if value != "demo-result" && err == nil {
			err = errors.New("lost shared result")
		}
		secondDone <- err
	}()
	// Wait for actual registration, without assuming goroutine scheduling order.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		budget.mu.Lock()
		joined := budget.flights["demo-same"].waiters == 2
		budget.mu.Unlock()
		if joined {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("second consumer did not join")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if !errors.Is(<-firstDone, context.Canceled) {
		t.Fatal("cancelled caller was not released")
	}
	if _, err := runMeasurementOn(context.Background(), budget, "demo-other", 256, func(context.Context) (string, error) { t.Fatal("concurrency cap bypassed"); return "", nil }); !errors.Is(err, ErrMeasurementDeferred) {
		t.Fatal(err)
	}
	close(finish)
	if err := <-secondDone; err != nil || calls.Load() != 1 {
		t.Fatal("one cancellation cancelled the shared measurement", err, calls.Load())
	}
	if !firstTiming.timing.completed.IsZero() || !secondTiming.timing.completed.Equal(at) {
		t.Fatal("actual completion mutated a canceled consumer or borrowed a later consumer's clock")
	}
}

func TestMeasurementTimingFallbackKeepsTheSameFlightBoundary(t *testing.T) {
	for _, early := range []bool{false, true} {
		at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		clock := at
		budget, err := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 1, Concurrent: 1, Bytes: 1024, Timeout: time.Second}, func() time.Time { return clock })
		if err != nil {
			t.Fatal(err)
		}
		ctx, captured := captureMeasurementTime(context.Background(), func() time.Time { return clock })
		_, err = runMeasurementOn(ctx, budget, "demo-completion", 128, func(pending context.Context) (int, error) {
			if early {
				markMeasurementCompletion(pending)
			}
			clock = at.Add(time.Second)
			return 1, nil
		})
		want := at.Add(time.Second)
		if early {
			want = at
		}
		if err != nil || !captured.timing.completed.Equal(want) {
			t.Fatal("unmarked fallback or marked original completion changed", early, err)
		}
	}
}

func TestNodeMeasurementBudgetDoesNotRenewSamplesOrResetOnAClockRollback(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 2, Concurrent: 1, Bytes: 1024, Timeout: time.Second}, func() time.Time { return at })
	calls := 0
	run := func(context.Context) (int, error) { calls++; return calls, nil }
	for _, key := range []string{"demo-one", "demo-two"} {
		if _, err := runMeasurementOn(context.Background(), budget, key, 512, run); err != nil {
			t.Fatal(err)
		}
	}
	at = at.Add(-time.Second)
	if _, err := runMeasurementOn(context.Background(), budget, "demo-three", 512, run); !errors.Is(err, ErrMeasurementDeferred) {
		t.Fatal("clock rollback replenished the budget", err)
	}
	at = at.Add(time.Minute + time.Second)
	if value, err := runMeasurementOn(context.Background(), budget, "demo-three", 512, run); err != nil || value != 3 {
		t.Fatal("a real new measurement did not get a fresh opportunity", err, value)
	}
	if calls != 3 {
		t.Fatal("budget rejection ran a network request")
	}
}

func TestLastMeasurementConsumerWaitsForActualCleanupWithoutHoldingBudgetLock(t *testing.T) {
	budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 2, Concurrent: 1, Bytes: 1024, Timeout: time.Second}, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, cleaning, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := runMeasurementOn(ctx, budget, "demo-cleanup", 512, func(pending context.Context) (int, error) {
			close(started)
			<-pending.Done()
			close(cleaning)
			<-release
			return 0, pending.Err()
		})
		done <- err
	}()
	<-started
	cancel()
	select {
	case <-cleaning:
	case <-time.After(5 * time.Second):
		t.Fatal("last cancellation never reached actual work")
	}
	select {
	case <-done:
		t.Fatal("consumer returned with actual cleanup still running")
	default:
	}
	budget.mu.Lock()
	active := budget.active
	budget.mu.Unlock()
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) || active != 1 {
		t.Fatal("cleanup result or shared concurrency ownership changed", err)
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.active != 0 {
		t.Fatal("consumer returned before actual operation released the budget")
	}
}

func TestNodeMeasurementSocketAllowanceCoversReadsAndWrites(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	connection := &measuredConnection{Conn: left, quota: &measurementSockets{rx: 4, tx: 4}}
	go func() { right.Write([]byte("demo-more")) }()
	body := make([]byte, 16)
	n, err := connection.Read(body)
	if err != nil || n != 4 || string(body[:n]) != "demo" {
		t.Fatal(n, err)
	}
	if _, err := connection.Read(body); !errors.Is(err, errMeasurementBytes) {
		t.Fatal("read exceeded its reserved bytes", err)
	}
	go func() { var value [4]byte; right.Read(value[:]) }()
	if n, err := connection.Write([]byte("demo-more")); n != 4 || !errors.Is(err, errMeasurementBytes) {
		t.Fatal("write exceeded its reserved bytes", n, err)
	}
}
