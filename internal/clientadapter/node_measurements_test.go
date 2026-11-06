package clientadapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

func TestNodeMeasurementProgressDoesNotWaitForSlowWorkAndJoinsCancellation(t *testing.T) {
	for _, stop := range []string{"finish", "cancel", "consumer-error"} {
		t.Run(stop, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			at := time.Now().UTC().Truncate(time.Millisecond)
			budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 8, Concurrent: 2, Bytes: 4096, Timeout: 5 * time.Second}, func() time.Time { return at })
			ctx = WithMeasurementBudget(ctx, budget)
			started, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
			observed, done := make(chan control.Observation, 2), make(chan error, 1)
			failure := errors.New("demo consumer replaced its input")
			var callbacks atomic.Int32
			template := control.Observation{Level: "resource", ResourceID: "demo-fast", Target: "192.0.2.1:443", Action: "hysteria2_echo", SpecDigest: "sha256:" + strings.Repeat("a", 64)}
			fast := nodeMeasurement{template: template, run: func(context.Context) (*int64, *control.HY2Transfer, bool, error) {
				<-started
				return nil, nil, true, nil
			}}
			template.ResourceID = "demo-slow"
			slow := nodeMeasurement{template: template, run: func(ctx context.Context) (*int64, *control.HY2Transfer, bool, error) {
				defer close(exited)
				close(started)
				select {
				case <-release:
					return nil, nil, true, nil
				case <-ctx.Done():
					return nil, nil, false, ctx.Err()
				}
			}}
			go func() {
				samples, err := observeNodeJobs(ctx, []nodeMeasurement{fast, slow}, nil, "demo-network", func() time.Time { return at }, DefaultMeasurementTiming, func(batch []control.Observation) error {
					callbacks.Add(1)
					for _, sample := range batch {
						observed <- sample
					}
					if stop == "consumer-error" {
						return failure
					}
					return nil
				})
				if err == nil && len(samples) != 2 {
					err = errors.New("completed round lost independent work")
				}
				done <- err
			}()
			select {
			case sample := <-observed:
				if sample.ResourceID != "demo-fast" || sample.Result != "available" || sample.ObservedAt != at.UnixMilli() || sample.ValidUntil != at.Add(DefaultMeasurementTiming.SuccessValidity).UnixMilli() {
					t.Fatal("first completion lost its original successful evidence")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("fast result waited for slow work")
			}
			if stop != "consumer-error" {
				select {
				case <-done:
					t.Fatal("background exploration stopped after first usable entry")
				default:
				}
			}
			switch stop {
			case "finish":
				close(release)
			case "cancel":
				cancel()
			}
			select {
			case err := <-done:
				if stop == "finish" && err != nil || stop == "cancel" && !errors.Is(err, context.Canceled) || stop == "consumer-error" && !errors.Is(err, failure) {
					t.Fatal("completion/cancellation outcome changed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled actual work was not joined")
			}
			select {
			case <-exited:
			default:
				t.Fatal("callback or caller returned before actual work exited")
			}
			if stop != "finish" && callbacks.Load() != 1 {
				t.Fatal("cancellation manufactured a failure or delivered a late callback")
			}
		})
	}
}

func TestMeasurementDeltasDeduplicatePreviousCopiesAndDiscardOldNetwork(t *testing.T) {
	at := time.Now().UnixMilli()
	old := control.Observation{Level: "resource", ResourceID: "demo-entry", Target: "192.0.2.1:443", Action: "hysteria2_echo", SpecDigest: "sha256:" + strings.Repeat("a", 64), NetworkGeneration: "demo-old-network", Result: "available", ObservedAt: at, ValidUntil: at + 60000}
	copy := old
	copy.ResourceID = "demo-other"
	values := MergeNodeMeasurements([]control.Observation{old, copy, old}, []control.Observation{old})
	if len(values) != 2 || values[0].ObservedAt != old.ObservedAt || values[0].ValidUntil != old.ValidUntil {
		t.Fatal("reused cache copies duplicated or renewed an original sample")
	}
	fresh := old
	fresh.NetworkGeneration, fresh.ObservedAt, fresh.ValidUntil = "demo-new-network", at+1, at+60001
	values = MergeNodeMeasurements(values, []control.Observation{fresh})
	if len(values) != 1 || values[0] != fresh {
		t.Fatal("old-network cache entries survived a current completion")
	}
	conflict := old
	conflict.Result = "unavailable"
	task := nodeMeasurement{template: old, run: func(context.Context) (*int64, *control.HY2Transfer, bool, error) {
		t.Fatal("conflicting originals started a new network request")
		return nil, nil, false, nil
	}}
	if _, err := observeNodeJobs(context.Background(), []nodeMeasurement{task}, []control.Observation{old, conflict}, old.NetworkGeneration, time.Now, DefaultMeasurementTiming, nil); err == nil {
		t.Fatal("same-time conflicting originals were silently merged")
	}
}

func TestCoalescedNodeMeasurementsKeepOneOriginalTimeAndDuration(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 8, Concurrent: 2, Bytes: 4096, Timeout: 5 * time.Second}, func() time.Time { return at })
	ctx := WithMeasurementBudget(context.Background(), budget)
	timing := MeasurementTiming{time.Second, time.Minute, time.Minute, 30 * time.Second, 5 * time.Second}
	started, finish := make(chan struct{}, 1), make(chan struct{})
	var clock atomic.Int64
	clock.Store(at.UnixMilli())
	var calls atomic.Int32
	task := nodeMeasurement{template: control.Observation{Level: "egress", Target: "https://demo.example/health", Action: "https_request", SpecDigest: "sha256:" + strings.Repeat("a", 64)}}
	task.run = func(pending context.Context) (*int64, *control.HY2Transfer, bool, error) {
		_, err := runMeasurementOn(pending, budget, "demo-shared", 128, func(pending context.Context) (int, error) {
			calls.Add(1)
			started <- struct{}{}
			select {
			case <-pending.Done():
				return 0, pending.Err()
			case <-finish:
				return 1, nil
			}
		})
		return nil, nil, err == nil, err
	}
	type result struct {
		samples []control.Observation
		err     error
	}
	first, second := make(chan result, 1), make(chan result, 1)
	go func() {
		samples, err := observeNodeJobs(ctx, []nodeMeasurement{task}, nil, "demo-underlay", func() time.Time { return time.UnixMilli(clock.Load()) }, timing, nil)
		first <- result{samples, err}
	}()
	<-started
	go func() {
		// A later consumer's wall time must not re-date the shared operation.
		samples, err := observeNodeJobs(ctx, []nodeMeasurement{task}, nil, "demo-underlay", func() time.Time { return at.Add(20 * time.Second) }, timing, nil)
		second <- result{samples, err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		budget.mu.Lock()
		joined := budget.flights["demo-shared"] != nil && budget.flights["demo-shared"].waiters == 2
		budget.mu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			close(finish)
			t.Fatal("second consumer did not coalesce")
		}
		time.Sleep(time.Millisecond)
	}
	clock.Store(at.Add(time.Second).UnixMilli())
	close(finish)
	a, b := <-first, <-second
	if a.err != nil || b.err != nil || len(a.samples) != 1 || len(b.samples) != 1 || calls.Load() != 1 {
		t.Fatal("shared measurement failed", a.err, b.err, calls.Load())
	}
	left, right := a.samples[0], b.samples[0]
	if left.ObservedAt != clock.Load() || right.ObservedAt != left.ObservedAt || right.ValidUntil != left.ValidUntil || *right.DurationMS != *left.DurationMS {
		t.Fatal("coalescing renewed a sample or timed only a consumer's remaining wait")
	}
}

func TestNodeMeasurementsShareConcurrencyAcrossRolesAndCancelWithoutFailures(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 32, Concurrent: 2, Bytes: 8192, Timeout: 5 * time.Second}, func() time.Time { return at })
	ctx := WithMeasurementBudget(context.Background(), budget)
	timing := MeasurementTiming{time.Second, time.Minute, time.Minute, 30 * time.Second, 5 * time.Second}
	started, permits := make(chan struct{}, 8), make(chan struct{})
	var active, maximum atomic.Int32
	var clock atomic.Int64
	clock.Store(at.UnixMilli())
	tasks := []nodeMeasurement{}
	for index := range 5 {
		template := control.Observation{Level: "link", ResourceID: fmt.Sprintf("demo-resource-%d", index), LinkID: fmt.Sprintf("demo-link-%d", index), Target: net.JoinHostPort(netip.MustParsePrefix("fc00::/7").Addr().Next().String(), "53"), Action: "wireguard_echo", SpecDigest: "sha256:" + strings.Repeat("a", 64)}
		if index == 0 {
			template.Level, template.LinkID, template.Target = "resource", "", "192.0.2.1:443"
		} else if index == 4 {
			template.Level, template.ResourceID, template.LinkID, template.Target, template.Action = "egress", "", "", "https://demo.example/health", "https_request"
		}
		task := nodeMeasurement{template: template}
		task.run = func(pending context.Context) (*int64, *control.HY2Transfer, bool, error) {
			_, err := runMeasurementOn(pending, budget, fmt.Sprintf("demo-operation-%d", index), 128, func(pending context.Context) (int, error) {
				n := active.Add(1)
				defer active.Add(-1)
				for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
				}
				started <- struct{}{}
				select {
				case <-pending.Done():
					return 0, pending.Err()
				case <-permits:
				}
				if index == 0 {
					return 0, errors.New("demo authentication failure")
				}
				return 1, nil
			})
			var rtt *int64
			if err == nil && template.Level != "egress" {
				rtt = new(int64(0))
			}
			return rtt, nil, err == nil, err
		}
		tasks = append(tasks, task)
	}
	type result struct {
		samples []control.Observation
		err     error
	}
	done := make(chan result, 1)
	go func() {
		samples, err := observeNodeJobs(ctx, tasks, nil, "demo-underlay", func() time.Time { return time.UnixMilli(clock.Load()) }, timing, nil)
		done <- result{samples, err}
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(permits)
			t.Fatal("role measurements did not start concurrently")
		}
	}
	select {
	case <-started:
		close(permits)
		t.Fatal("roles bypassed their shared concurrency limit")
	default:
	}
	clock.Store(at.Add(time.Second).UnixMilli())
	close(permits)
	completed := <-done
	if completed.err != nil || len(completed.samples) != len(tasks) || maximum.Load() != 2 || active.Load() != 0 {
		t.Fatal("node measurements lost independent work", completed.err, len(completed.samples), maximum.Load())
	}
	for _, sample := range completed.samples {
		if sample.ObservedAt != clock.Load() || sample.ValidUntil <= sample.ObservedAt || sample.Validate() != nil {
			t.Fatal("sample did not preserve its actual completion", sample)
		}
		if sample.ResourceID == "demo-resource-0" && (sample.Result != "unavailable" || sample.RoundTripMS != nil) {
			t.Fatal("failed role borrowed another operation's RTT")
		}
	}
	// Cancellation interrupts actual in-flight role work and does not turn the
	// old complete cache into a new collection of failures.
	for len(started) != 0 {
		<-started
	}
	permits = make(chan struct{})
	cancelled, cancel := context.WithCancel(ctx)
	go func() {
		samples, err := observeNodeJobs(cancelled, tasks, completed.samples, "demo-underlay", func() time.Time { return at.Add(time.Hour) }, timing, nil)
		done <- result{samples, err}
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("cancellation fixture did not start")
		}
	}
	cancel()
	stopped := <-done
	if !errors.Is(stopped.err, context.Canceled) || len(stopped.samples) != 0 {
		t.Fatal("cancelled round manufactured failures", stopped.err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("last cancelled consumers left actual work running")
	}
}

func TestNodeMeasurementsRepeatBeforeExpiryAndDoNotRenewDeferredSamples(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	timing := MeasurementTiming{ActivePeriod: 10 * time.Second, IdlePeriod: time.Minute, SuccessValidity: 10 * time.Minute, FailureValidity: 30 * time.Second, RoundTimeout: time.Second}
	calls := 0
	deferRequest := false
	task := nodeMeasurement{active: true, template: control.Observation{Level: "egress", Target: "https://demo.example/health", Action: "https_request", SpecDigest: "sha256:" + strings.Repeat("a", 64)}, run: func(context.Context) (*int64, *control.HY2Transfer, bool, error) {
		calls++
		if deferRequest {
			return nil, nil, false, ErrMeasurementDeferred
		}
		return nil, nil, true, nil
	}}
	now := func() time.Time { return at }
	first, err := observeNodeJobs(context.Background(), []nodeMeasurement{task}, nil, "demo-network", now, timing, nil)
	if err != nil || calls != 1 || len(first) != 1 {
		t.Fatal("initial measurement", err, calls)
	}
	at = at.Add(11 * time.Second)
	second, err := observeNodeJobs(context.Background(), []nodeMeasurement{task}, first, "demo-network", now, timing, nil)
	if err != nil || calls != 2 || second[0].ObservedAt == first[0].ObservedAt {
		t.Fatal("validity stopped continuous measurement", err, calls)
	}
	at = at.Add(11 * time.Second)
	deferRequest = true
	third, err := observeNodeJobs(context.Background(), []nodeMeasurement{task}, second, "demo-network", now, timing, nil)
	if err != nil || len(third) != 1 || third[0].ObservedAt != second[0].ObservedAt || third[0].ValidUntil != second[0].ValidUntil || third[0].Result != "available" {
		t.Fatal("budget delay became failure or renewed a sample", err)
	}
}

func TestNodeMeasurementOldestIdleWorkEventuallyWinsUnderAnActiveLoad(t *testing.T) {
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	budget, _ := NewMeasurementBudget(MeasurementLimits{Window: 10 * time.Second, Requests: 1, Concurrent: 1, Bytes: 64, Timeout: time.Second}, func() time.Time { return at })
	ctx := WithMeasurementBudget(context.Background(), budget)
	timing := MeasurementTiming{ActivePeriod: time.Second, IdlePeriod: 10 * time.Second, SuccessValidity: time.Minute, FailureValidity: 10 * time.Second, RoundTimeout: time.Second}
	calls := []string{}
	tasks := []nodeMeasurement{}
	for _, name := range []string{"demo-active", "demo-pending", "demo-idle-one", "demo-idle-two"} {
		task := nodeMeasurement{active: name == "demo-active" || name == "demo-pending", template: control.Observation{Level: "egress", Target: "https://" + name + ".example/", Action: "https_request", SpecDigest: "sha256:" + strings.Repeat("a", 64)}}
		task.run = func(pending context.Context) (*int64, *control.HY2Transfer, bool, error) {
			_, err := runMeasurementOn(pending, budget, name, 16, func(context.Context) (int, error) { calls = append(calls, name); return 1, nil })
			return nil, nil, err == nil, err
		}
		tasks = append(tasks, task)
	}
	var samples []control.Observation
	for round := 0; round < 8; round++ {
		var err error
		samples, err = observeNodeJobs(ctx, tasks, samples, "demo-network", func() time.Time { return at }, timing, nil)
		if err != nil {
			t.Fatal(err)
		}
		at = at.Add(10 * time.Second)
	}
	if len(calls) != 8 || len(samples) != 4 {
		t.Fatal("active work starved idle measurements or exceeded the node budget", calls, len(samples))
	}
}

func TestNodeMeasurementCadenceDoesNotDependOnSampleValidity(t *testing.T) {
	for _, result := range []string{"available", "unavailable"} {
		for _, active := range []bool{false, true} {
			for _, validity := range []time.Duration{time.Second, time.Minute} {
				t.Run(fmt.Sprintf("%s-active-%v-validity-%s", result, active, validity), func(t *testing.T) {
					observed := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
					at := observed.Add(3 * time.Second)
					timing := MeasurementTiming{ActivePeriod: 10 * time.Second, IdlePeriod: time.Minute, SuccessValidity: validity, FailureValidity: validity, RoundTimeout: time.Second}
					sample := control.Observation{Level: "egress", Target: "https://demo.example/", Action: "https_request", SpecDigest: "sha256:" + strings.Repeat("a", 64), NetworkGeneration: "demo-network", Result: result, ObservedAt: observed.UnixMilli(), ValidUntil: observed.Add(validity).UnixMilli()}
					calls := 0
					budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 4, Concurrent: 1, Bytes: 128, Timeout: time.Second}, func() time.Time { return at })
					ctx := WithMeasurementBudget(context.Background(), budget)
					task := nodeMeasurement{active: active, template: sample, run: func(pending context.Context) (*int64, *control.HY2Transfer, bool, error) {
						_, err := runMeasurementOn(pending, budget, "demo-cadence", 16, func(context.Context) (int, error) { calls++; return 1, nil })
						return nil, nil, true, err
					}}
					samples, err := observeNodeJobs(ctx, []nodeMeasurement{task}, []control.Observation{sample}, sample.NetworkGeneration, func() time.Time { return at }, timing, nil)
					if err != nil || calls != 0 || len(samples) != 1 || !reflect.DeepEqual(samples[0], sample) {
						t.Fatal("expiry triggered an early probe or renewed the original sample", calls, err)
					}
					period := timing.IdlePeriod
					if active {
						period = timing.ActivePeriod
					}
					if result == "unavailable" {
						period = timing.RecoveryPeriod()
					}
					at = observed.Add(period - time.Millisecond)
					samples, err = observeNodeJobs(ctx, []nodeMeasurement{task}, samples, sample.NetworkGeneration, func() time.Time { return at }, timing, nil)
					if err != nil || calls != 0 || !reflect.DeepEqual(samples[0], sample) {
						t.Fatal("cadence adopted a validity deadline", calls, err)
					}
					at = observed.Add(period)
					samples, err = observeNodeJobs(ctx, []nodeMeasurement{task}, samples, sample.NetworkGeneration, func() time.Time { return at }, timing, nil)
					if err != nil || calls != 1 || len(samples) != 1 || samples[0].ObservedAt != at.UnixMilli() || samples[0].ValidUntil != at.Add(validity).UnixMilli() {
						t.Fatal("period or original completed validity was changed", calls, err)
					}
				})
			}
		}
	}
}
