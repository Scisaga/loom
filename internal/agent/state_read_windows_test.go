//go:build windows

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsStateImmediateReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	d := Decl{ID: "demo-service", Selector: "demo-selector", Candidates: []Cand{{Tag: "demo-candidate"}}}
	s, err := newStateStore(context.Background(), path, "demo-client", []Decl{d}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = ReadState(path)
			}
		}
	}()
	defer func() { close(stop); <-done }()
	for range 100 {
		if _, err := ReadState(path); err != nil {
			t.Fatal(err)
		}
		if err := s.observe(context.Background(), Selection{Declaration: d.ID, Selector: d.Selector, Candidate: "demo-candidate"}, time.Now()); err != nil {
			info, _ := os.Stat(path)
			t.Fatalf("replace failed: %v mode=%v", err, info.Mode())
		}
	}
}
