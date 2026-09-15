package webui

import (
	"time"
)

func misakaDepsWithTrafficHistory() Deps {
	d := misakaDeps()
	view := d.Snapshot()
	start := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	view.TrafficHistory = &TrafficHistoryView{
		WindowStart: start.Format(time.RFC3339),
		WindowEnd:   start.Add(24 * time.Hour).Format(time.RFC3339),
		BucketWidth: "1h",
		Source:      "control-retained independently verified loom-traffic-v1 deltas",
		Buckets: []TrafficBucketView{
			{
				Start: start.Format(time.RFC3339), End: start.Add(time.Hour).Format(time.RFC3339),
				Samples: 4, Resets: 1,
				Nodes: []TrafficNodeTotalsView{
					{Node: "demo-d", RXBytes: 1024, TXBytes: 2048, Bytes: 3072, Samples: 2, Resets: 1},
					{Node: "demo-e", RXBytes: 2048, TXBytes: 1024, Bytes: 3072, Samples: 2},
				},
				Links: []TrafficLinkTotalsView{{From: "demo-d", To: "demo-e", TXBytes: 1024, ReportingEndpoints: 2}},
			},
			{
				Start: start.Add(time.Hour).Format(time.RFC3339), End: start.Add(2 * time.Hour).Format(time.RFC3339),
				Samples: 1,
				Nodes:   []TrafficNodeTotalsView{{Node: "demo-d", RXBytes: 1024, TXBytes: 1024, Bytes: 2048, Samples: 1}},
				Links:   []TrafficLinkTotalsView{{From: "demo-e", To: "demo-d", TXBytes: 2048, ReportingEndpoints: 1}},
			},
			{
				Start: start.Add(2 * time.Hour).Format(time.RFC3339), End: start.Add(3 * time.Hour).Format(time.RFC3339),
				Gaps: 1,
			},
		},
	}
	d.Snapshot = func() View { return view }
	return d
}
