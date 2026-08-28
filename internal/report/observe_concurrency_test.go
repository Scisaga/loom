package report

import (
	"testing"
	"time"
)

func TestParallelProbeIsBoundedAndCompletesEveryProbe(t *testing.T) {
	count := probeConcurrency + 3
	entered := make(chan int, count)
	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		parallelProbe(count, func(i int) {
			entered <- i
			<-release
		})
		close(done)
	}()

	seen := map[int]bool{}
	for len(seen) < probeConcurrency {
		select {
		case index := <-entered:
			seen[index] = true
		case <-time.After(time.Second):
			t.Fatalf("only %d probes entered; expected concurrency %d", len(seen), probeConcurrency)
		}
	}
	select {
	case index := <-entered:
		t.Fatalf("probe %d exceeded concurrency bound %d", index, probeConcurrency)
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bounded probe batch did not complete after release")
	}
	for len(entered) > 0 {
		seen[<-entered] = true
	}
	if len(seen) != count {
		t.Fatalf("parallelProbe ran %d unique probes, want %d", len(seen), count)
	}
}
