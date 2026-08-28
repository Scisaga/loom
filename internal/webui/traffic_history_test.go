package webui

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestOverviewShowsRetainedFleetBucketsAndKeepsCurrentCountersSeparate(t *testing.T) {
	d := misakaDepsWithTrafficHistory()
	body := misakaRequest(t, d, http.MethodGet, "/", nil, false).Body.String()
	for _, want := range []string{
		"Fleet forwarding · last 24 hours",
		"Node-interface delta total",
		"8.00 KiB",
		"2 <small>/ 3",
		"Fleet node-interface WireGuard byte deltas by retained time bucket",
		"hop-weighted",
		"not unique application payload volume",
		"Current local interface counters",
		"Current cumulative counters by local interface",
		"Direct self /status only",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Overview retained/current traffic boundary missing %q", want)
		}
	}
	if got := strings.Count(body, `<i class=historytotal`); got != 2 {
		t.Fatalf("Overview rendered %d fleet history bars, want two sampled buckets (the missing bucket must not get a bar)", got)
	}
	if !strings.Contains(body, `class=historymissing`) {
		t.Fatal("Overview did not distinguish the missing bucket from a sampled zero bucket")
	}
}

func TestNodeDetailShowsRXTXBucketsAndResetGapBoundary(t *testing.T) {
	d := misakaDepsWithTrafficHistory()
	body := misakaRequest(t, d, http.MethodGet, "/nodes/jm24", nil, false).Body.String()
	for _, want := range []string{
		"current cumulative counters · retained history attached",
		"Retained forwarding history",
		"Historical RX",
		"Historical TX",
		"2.00 KiB",
		"3.00 KiB",
		"5.00 KiB",
		"2 <small>/ 3",
		"Missing bucket ≠ zero traffic",
		"Node-attributed quality: 1 reset transition(s) · 0 long gap(s)",
		"Window-wide bucket flags: 1 reset transition(s) · 1 long gap(s)",
		"Rejected transitions contribute no bytes",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Node history is missing %q", want)
		}
	}
	if got := strings.Count(body, `<i class=historyrx`); got != 2 {
		t.Fatalf("Node detail rendered %d RX bars, want one for each sampled bucket", got)
	}
	if got := strings.Count(body, `<i class=historytx`); got != 2 {
		t.Fatalf("Node detail rendered %d TX bars, want one for each sampled bucket", got)
	}
	if !strings.Contains(body, `B R0 G1`) {
		t.Fatal("Node chart does not expose the non-attributed fleet bucket gap marker")
	}
}

func TestTopologyComparesLinkTXSamplesAndDoesNotBarMissingLink(t *testing.T) {
	d := misakaDepsWithTrafficHistory()
	view := d.Snapshot()
	view.Nodes = append(view.Nodes, NodeView{ID: "gz02", Health: "unknown"})
	view.Links = append(view.Links, LinkView{
		From: "jm24", To: "gz02", Kind: "tunnel", State: "unknown", Source: "SSOT persistent WG",
	})
	d.Snapshot = func() View { return view }

	body := misakaRequest(t, d, http.MethodGet, "/topology", nil, false).Body.String()
	for _, want := range []string{
		"WireGuard link forwarding · last 24 hours",
		"sum of endpoint TX deltas",
		"3.00 KiB",
		"jm24 ↔ sg02",
		"2 / 3 buckets",
		"1 both endpoints · 1 one endpoint",
		"jm24 ↔ gz02",
		"No retained TX delta · no bar",
		"0 sample buckets",
		"Sender TX is not added again as receiver RX",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Topology link traffic is missing %q", want)
		}
	}
	if got := strings.Count(body, `<i class=linkbarfill`); got != 1 {
		t.Fatalf("Topology rendered %d link bars, want only the one link with retained evidence", got)
	}
}

func TestTopologyAttributesResetAndGapToSpecificQualityOnlyLinks(t *testing.T) {
	d := misakaDepsWithTrafficHistory()
	view := d.Snapshot()
	view.TrafficHistory.Buckets = []TrafficBucketView{{
		Start: view.TrafficHistory.WindowStart, End: view.TrafficHistory.WindowEnd,
		Links: []TrafficLinkTotalsView{
			{From: "jm24", To: "sg02", Resets: 1},
			{From: "gz02", To: "hz01", Gaps: 2},
		},
	}}
	d.Snapshot = func() View { return view }
	body := misakaRequest(t, d, http.MethodGet, "/topology", nil, false).Body.String()
	for _, want := range []string{"jm24 ↔ sg02", "R1 · G0", "gz02 ↔ hz01", "R0 · G2"} {
		if !strings.Contains(body, want) {
			t.Errorf("quality-only topology is missing %q", want)
		}
	}
	if strings.Contains(body, `class=linkbarfill`) {
		t.Fatal("quality-only link evidence produced a zero-traffic bar")
	}
}

func TestTrafficHistoryAbsenceAndEmptyBucketsDoNotInventCharts(t *testing.T) {
	d := misakaDeps()
	topology := misakaRequest(t, d, http.MethodGet, "/topology", nil, false).Body.String()
	if !strings.Contains(topology, "No centrally retained link history in this view") {
		t.Fatal("nil history is not explicit on Topology")
	}
	if strings.Contains(topology, `<i class=linkbarfill`) {
		t.Fatal("nil history produced a link bar")
	}

	view := d.Snapshot()
	view.TrafficHistory = &TrafficHistoryView{
		WindowStart: "2026-08-27T12:00:00Z", WindowEnd: "2026-08-28T12:00:00Z",
		BucketWidth: "1h", Buckets: []TrafficBucketView{{
			Start: "2026-08-27T12:00:00Z", End: "2026-08-27T13:00:00Z", Resets: 1, Gaps: 1,
		}},
	}
	d.Snapshot = func() View { return view }
	topology = misakaRequest(t, d, http.MethodGet, "/topology", nil, false).Body.String()
	if !strings.Contains(topology, "No link bucket contains an accepted TX delta") {
		t.Fatal("empty retained link buckets are not explained")
	}
	if strings.Contains(topology, `<i class=linkbarfill`) {
		t.Fatal("empty retained link buckets produced a comparison bar")
	}

	node := misakaRequest(t, d, http.MethodGet, "/nodes/jm24", nil, false).Body.String()
	for _, want := range []string{"No accepted historical delta for jm24", "accepted samples in 0 / 1 buckets", "1 reset transition(s), 1 long gap(s)", "No chart is drawn"} {
		if !strings.Contains(node, want) {
			t.Errorf("empty node history is missing %q", want)
		}
	}
	if strings.Contains(node, `<i class=historyrx`) || strings.Contains(node, `<i class=historytx`) {
		t.Fatal("empty node history produced bars")
	}
}

func TestResetOnlyNodeBucketStaysMissingRatherThanZeroTraffic(t *testing.T) {
	d := misakaDepsWithTrafficHistory()
	view := d.Snapshot()
	view.TrafficHistory = &TrafficHistoryView{
		WindowStart: "2026-08-27T12:00:00Z", WindowEnd: "2026-08-28T12:00:00Z",
		BucketWidth: "1h", Buckets: []TrafficBucketView{{
			Start: "2026-08-27T12:00:00Z", End: "2026-08-27T13:00:00Z",
			Resets: 1, Nodes: []TrafficNodeTotalsView{{Node: "jm24", Resets: 1}},
		}},
	}
	d.Snapshot = func() View { return view }

	for _, path := range []string{"/", "/nodes/jm24"} {
		body := misakaRequest(t, d, http.MethodGet, path, nil, false).Body.String()
		if !strings.Contains(body, "No accepted") || strings.Contains(body, "class=historychart") {
			t.Fatalf("%s turned a reset-only bucket into sampled zero traffic", path)
		}
	}
}

func TestTrafficHistoryAggregatesSaturateAtMaxInt64(t *testing.T) {
	if got := trafficNodeBytes(TrafficNodeTotalsView{RXBytes: maxCounterValue, TXBytes: maxCounterValue}); got != maxCounterValue {
		t.Fatalf("node traffic total = %d, want saturated MaxInt64", got)
	}

	d := misakaDeps()
	view := d.Snapshot()
	view.TrafficHistory = &TrafficHistoryView{
		WindowStart: "2026-08-28T10:00:00Z", WindowEnd: "2026-08-28T12:00:00Z", BucketWidth: "1h",
		Buckets: []TrafficBucketView{{
			Start: "2026-08-28T10:00:00Z", End: "2026-08-28T11:00:00Z", Samples: 2,
			Nodes: []TrafficNodeTotalsView{
				{Node: "jm24", RXBytes: maxCounterValue, TXBytes: maxCounterValue, Samples: 1},
				{Node: "sg02", RXBytes: maxCounterValue, TXBytes: maxCounterValue, Samples: 1},
			},
			Links: []TrafficLinkTotalsView{
				{From: "jm24", To: "sg02", TXBytes: maxCounterValue, ReportingEndpoints: 1},
				{From: "sg02", To: "jm24", TXBytes: maxCounterValue, ReportingEndpoints: 2},
			},
		}},
	}
	d.Snapshot = func() View { return view }

	for _, path := range []string{"/", "/nodes/jm24", "/topology"} {
		body := misakaRequest(t, d, http.MethodGet, path, nil, false).Body.String()
		if !strings.Contains(body, byteSize(maxCounterValue)) {
			t.Errorf("%s did not render the saturated traffic total", path)
		}
		if strings.Contains(body, "height:-") || strings.Contains(body, "width:-") {
			t.Errorf("%s emitted a negative chart size after counter saturation", path)
		}
	}
}

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
					{Node: "jm24", RXBytes: 1024, TXBytes: 2048, Bytes: 3072, Samples: 2, Resets: 1},
					{Node: "sg02", RXBytes: 2048, TXBytes: 1024, Bytes: 3072, Samples: 2},
				},
				Links: []TrafficLinkTotalsView{{From: "jm24", To: "sg02", TXBytes: 1024, ReportingEndpoints: 2}},
			},
			{
				Start: start.Add(time.Hour).Format(time.RFC3339), End: start.Add(2 * time.Hour).Format(time.RFC3339),
				Samples: 1,
				Nodes:   []TrafficNodeTotalsView{{Node: "jm24", RXBytes: 1024, TXBytes: 1024, Bytes: 2048, Samples: 1}},
				Links:   []TrafficLinkTotalsView{{From: "sg02", To: "jm24", TXBytes: 2048, ReportingEndpoints: 1}},
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
