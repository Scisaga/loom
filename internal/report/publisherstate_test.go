package report

import (
	"os"
	"testing"
	"time"
)

func TestPublisherStateHealthSemantics(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 500_000_000, time.UTC)
	base := PublisherState{
		PID: os.Getpid(), UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
		LastSuccess: now.Add(-time.Hour).Format(time.RFC3339Nano),
	}
	cases := []struct {
		name string
		edit func(*PublisherState)
		bad  bool
	}{
		{"healthy", func(*PublisherState) {}, false},
		{"interval extends heartbeat", func(p *PublisherState) {
			p.IntervalSeconds = 120
			p.UpdatedAt = now.Add(-5 * time.Minute).Format(time.RFC3339)
		}, false},
		{"legacy heartbeat stale", func(p *PublisherState) {
			p.UpdatedAt = now.Add(-3 * time.Minute).Format(time.RFC3339)
		}, true},
		{"future heartbeat", func(p *PublisherState) {
			p.UpdatedAt = now.Add(2 * time.Minute).Format(time.RFC3339)
		}, true},
		{"invalid pid", func(p *PublisherState) { p.PID = 0 }, true},
		{"never succeeded", func(p *PublisherState) { p.LastSuccess = "" }, true},
		{"current nano error", func(p *PublisherState) {
			p.LastSuccess = "2026-08-26T11:00:00Z"
			p.LastError = "boom"
			p.LastErrorAt = "2026-08-26T11:00:00.1Z"
		}, true},
		{"recovered", func(p *PublisherState) {
			p.LastSuccess = "2026-08-26T11:00:00.1Z"
			p.LastError = "old"
			p.LastErrorAt = "2026-08-26T11:00:00Z"
		}, false},
		{"bad error timestamp", func(p *PublisherState) {
			p.LastError = "boom"
			p.LastErrorAt = "bad"
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := base
			tc.edit(&got)
			if bad := got.Unhealthy(now); bad != tc.bad {
				t.Fatalf("Unhealthy=%v, want %v: %+v", bad, tc.bad, got)
			}
		})
	}
}
