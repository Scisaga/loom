package report_test

import (
	"os"
	"testing"
	"time"

	"loom/internal/publish"
	"loom/internal/report"
)

// report 不能直接 import publish（会形成 report→publish→render→report），
// 这条外部测试把两边的线格式与纯判定钉在一起，防止 UI 再漂出第二套真值。
func TestPublisherHealthMatchesPublishFindings(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	cases := []report.PublisherState{
		{PID: os.Getpid(), UpdatedAt: now.Format(time.RFC3339), LastSuccess: now.Add(-time.Hour).Format(time.RFC3339)},
		{PID: os.Getpid(), UpdatedAt: now.Add(-5 * time.Minute).Format(time.RFC3339), IntervalSeconds: 120, LastSuccess: now.Add(-time.Hour).Format(time.RFC3339)},
		{PID: os.Getpid(), UpdatedAt: now.Format(time.RFC3339), LastSuccess: "2026-08-26T11:00:00Z", LastError: "boom", LastErrorAt: "2026-08-26T11:00:00.1Z"},
		{PID: 0, UpdatedAt: now.Format(time.RFC3339), LastSuccess: now.Add(-time.Hour).Format(time.RFC3339)},
	}
	for _, s := range cases {
		p := publish.Health{
			Version: s.Version, PID: s.PID, StartedAt: s.StartedAt,
			UpdatedAt: s.UpdatedAt, IntervalSeconds: s.IntervalSeconds,
			LastSuccess: s.LastSuccess, LastSnapshot: s.LastSnapshot, LastSSOT: s.LastSSOT,
			LastError: s.LastError, LastErrorAt: s.LastErrorAt,
		}
		_, publishBad := p.Findings(now)
		if reportBad := s.Unhealthy(now); reportBad != publishBad {
			t.Fatalf("report=%v publish=%v for %+v", reportBad, publishBad, s)
		}
	}
}
