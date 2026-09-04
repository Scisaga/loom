package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"loom/internal/clientupdate"
)

type loopPuller struct {
	result clientupdate.Result
	err    error
	called chan struct{}
}

func (p *loopPuller) PullOnce(context.Context) (clientupdate.Result, error) {
	select {
	case p.called <- struct{}{}:
	default:
	}
	return p.result, p.err
}

func TestActiveUpdateLoopActivatesOnlyVerifiedPulls(t *testing.T) {
	for _, test := range []struct {
		name        string
		pullErr     error
		wantPrepare bool
	}{
		{name: "verified", wantPrepare: true},
		{name: "failed", pullErr: errors.New("untrusted current")},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			puller := &loopPuller{
				result: clientupdate.Result{Generation: 7, Snapshot: "111111111111"},
				err:    test.pullErr, called: make(chan struct{}, 1),
			}
			harness := &activationHarness{}
			managerHarness := newActivationHarnessManager(t, harness)
			prepared := make(chan struct{}, 1)
			done := make(chan error, 1)
			go func() {
				done <- runActiveUpdateLoop(ctx, puller, time.Hour, nil, func() (*clientActivation, error) {
					prepared <- struct{}{}
					return activationFixture(t, "8"), nil
				}, managerHarness.preflight, managerHarness.run, 10*time.Millisecond)
			}()
			select {
			case <-puller.called:
			case <-time.After(time.Second):
				t.Fatal("update loop did not pull immediately")
			}
			if test.wantPrepare {
				select {
				case <-prepared:
				case <-time.After(time.Second):
					t.Fatal("verified pull did not prepare a candidate")
				}
				deadline := time.Now().Add(time.Second)
				for {
					starts, _ := harness.counts()
					if starts == 1 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("verified candidate was not activated")
					}
					time.Sleep(time.Millisecond)
				}
				// A runner start event precedes the manager's startup-grace commit.
				// Wait past that boundary so cancellation exercises active shutdown.
				time.Sleep(20 * time.Millisecond)
			} else {
				select {
				case <-prepared:
					t.Fatal("failed pull prepared a candidate")
				case <-time.After(20 * time.Millisecond):
				}
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUpdateLoopRejectsIncompleteWiring(t *testing.T) {
	if err := runActiveUpdateLoop(context.Background(), nil, time.Second, nil, func() (*clientActivation, error) {
		return nil, nil
	}, func(context.Context, *clientActivation) error { return nil },
		func(context.Context, *clientActivation) error { return nil }, time.Millisecond); err == nil {
		t.Fatal("nil puller was accepted")
	}
}
