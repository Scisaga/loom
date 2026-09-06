//go:build windows

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/clientcore"
	"loom/internal/clientreport"
	"loom/internal/clientruntime"
)

func healthReporterFixture(t *testing.T) (*windowsReporter, string, clientRuntimeState) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "preference.json")
	if _, err := clientcore.EnsurePreference(path); err != nil {
		t.Fatal(err)
	}
	r := &windowsReporter{worker: clientreport.NewWorker(nil, nil, nil)}
	state := clientRuntimeState{Applied: "0123456789ab", Ready: true, Exited: make(chan struct{}), Health: &clientruntime.WindowsHealthPlan{}}
	r.update(state)
	return r, path, state
}

func TestWindowsHealthSampleFailureAndRecovery(t *testing.T) {
	r, path, _ := healthReporterFixture(t)
	for _, problems := range [][]string{nil, {"端到端探测 DNS 解析失败"}, nil} {
		r.check = func(context.Context, *clientruntime.WindowsHealthPlan) []string { return problems }
		_, got, ok := r.sampleHealth(context.Background(), path)
		if !ok || (len(got) == 0) != (len(problems) == 0) {
			t.Fatalf("health transition: %v, %v", got, ok)
		}
	}
}

func TestWindowsHealthDiscardsResultDuringActivationChange(t *testing.T) {
	for _, kind := range []string{"replacement", "stop", "process exit", "preference"} {
		t.Run(kind, func(t *testing.T) {
			r, path, state := healthReporterFixture(t)
			exited := make(chan struct{})
			state.Exited = exited
			r.update(state)
			entered, release := make(chan struct{}), make(chan struct{})
			r.check = func(ctx context.Context, _ *clientruntime.WindowsHealthPlan) []string {
				close(entered)
				select {
				case <-ctx.Done():
				case <-release:
				}
				return nil
			}
			done := make(chan bool, 1)
			go func() { _, _, ok := r.sampleHealth(context.Background(), path); done <- ok }()
			<-entered
			switch kind {
			case "replacement":
				state.Applied = "abcdef012345"
				r.update(state)
			case "stop":
				r.update(clientRuntimeState{})
			case "process exit":
				close(exited)
			case "preference":
				if err := clientcore.WritePreference(path, clientcore.Preference{Schema: clientcore.PreferenceSchema, Mode: clientcore.Direct}); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			select {
			case ok := <-done:
				if ok {
					t.Fatal("old probe appeared healthy after data-plane change")
				}
			case <-time.After(time.Second):
				t.Fatal("probe blocked activation change")
			}
		})
	}
}
