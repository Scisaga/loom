package webui

import (
	"net/http"
	"strings"
	"testing"
)

func TestZeroCurrentCountersAreSampledIdleNotMissing(t *testing.T) {
	d := misakaDeps()
	view := d.Snapshot()
	view.Nodes[0].TrafficTrusted = true
	view.Nodes[0].TrafficObservedAt = view.Nodes[0].ObservedAt
	view.Nodes[0].Tunnels[0].RxBytes = 0
	view.Nodes[0].Tunnels[0].TxBytes = 0
	view.Nodes[0].Tunnels[0].CounterPresent = true
	view.Nodes[0].Tunnels[0].TrafficTrusted = true
	view.Nodes[0].Tunnels[0].CounterSource = "direct /status"
	d.Snapshot = func() View { return view }

	overview := misakaRequest(t, d, http.MethodGet, "/", nil, false).Body.String()
	for _, want := range []string{
		"Current cumulative counters by local interface",
		"Idle · 0 B sampled",
		`class="current-counter-row idle"`,
		`title="wg-loom-demo-e 0 B · idle"`,
		`<small>RX</small><b class=mono>0 B</b>`,
		`<small>TX</small><b class=mono>0 B</b>`,
	} {
		if !strings.Contains(overview, want) {
			t.Errorf("Overview sampled-zero state is missing %q", want)
		}
	}
	if strings.Contains(overview, "Current local counters are not present") {
		t.Fatal("Overview treated a sampled zero counter as missing evidence")
	}

	detail := misakaRequest(t, d, http.MethodGet, "/nodes/demo-d", nil, false).Body.String()
	for _, want := range []string{
		"WG RX total", "WG TX total", "Idle · 0 B sampled",
		`class=counterchart`, `title="wg-loom-demo-e RX 0 B · idle"`,
		"Direct-self /status counter evidence.",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("Node detail sampled-zero state is missing %q", want)
		}
	}
	if strings.Contains(detail, "No current cumulative counters for this node") {
		t.Fatal("Node detail treated a sampled zero counter as missing evidence")
	}
}

func TestAbsentTunnelEvidenceStillReportsMissingCurrentCounters(t *testing.T) {
	d := misakaDeps()
	view := d.Snapshot()
	view.Nodes[0].Tunnels = []TunnelView{{
		Interface: "wg-loom-demo-e", CarrierPresent: true, State: "down", CounterPresent: false,
	}}
	d.Snapshot = func() View { return view }

	overview := misakaRequest(t, d, http.MethodGet, "/", nil, false).Body.String()
	if !strings.Contains(overview, "Current local counters are not present in this view") {
		t.Fatal("Overview did not report genuinely absent counter evidence")
	}
	detail := misakaRequest(t, d, http.MethodGet, "/nodes/demo-d", nil, false).Body.String()
	if !strings.Contains(detail, "No current cumulative counters for this node") {
		t.Fatal("Node detail did not report genuinely absent counter evidence")
	}
	if !strings.Contains(detail, "wg-loom-demo-e") || !strings.Contains(detail, "down") {
		t.Fatal("Node detail dropped the down tunnel row while excluding its absent counter")
	}
	if !strings.Contains(detail, `<td class=mono>wg-loom-demo-e<td class=bad>down<td>interface down<td>—<td>—`) {
		t.Fatal("down tunnel row represented absent counters as sampled zero bytes")
	}
	if strings.Contains(overview, "Idle · 0 B sampled") || strings.Contains(detail, "Idle · 0 B sampled") {
		t.Fatal("missing counter evidence was mislabeled as sampled idle")
	}
	if got := trafficExport(view); len(got.Current) != 0 || got.CurrentObservedAt != "" {
		t.Fatalf("traffic export included a down tunnel without counter evidence: %+v", got)
	}
}

func TestNodeDetailLabelsIndependentlySignedRelayCounterEvidence(t *testing.T) {
	d := misakaDeps()
	view := d.Snapshot()
	node := &view.Nodes[0]
	node.Self = false
	node.Reached = false
	node.TrafficTrusted = true
	node.TrafficVerified = true
	node.Tunnels[0].TrafficTrusted = true
	node.Tunnels[0].TrafficVerified = true
	node.Tunnels[0].CounterSource = "independently signed relay"
	d.Snapshot = func() View { return view }

	body := misakaRequest(t, d, http.MethodGet, "/nodes/demo-d", nil, false).Body.String()
	if !strings.Contains(body, "Independently signed loom-traffic-v1 relay counter evidence.") {
		t.Fatal("Node detail did not identify independently signed relay counters")
	}
	if strings.Contains(body, "Direct-self /status counter evidence.") {
		t.Fatal("relayed counters were mislabeled as direct-self")
	}
	if !strings.Contains(body, "direct non-WireGuard, service/sing-box and Hysteria2 traffic are excluded") {
		t.Fatal("relay wording lost the non-WireGuard exclusion boundary")
	}
	if !strings.Contains(body, "Serving host traffic JSON") || strings.Contains(body, "This node traffic JSON") {
		t.Fatal("remote node detail mislabeled the serving host's node-local traffic endpoint")
	}
}

func TestCurrentCounterScalingDoesNotOverflow(t *testing.T) {
	if got := counterHeight(maxCounterValue, maxCounterValue); got != 100 {
		t.Fatalf("counterHeight(MaxInt64) = %d, want 100", got)
	}
	if got := counterHeight(maxCounterValue/2, maxCounterValue); got < 49 || got > 50 {
		t.Fatalf("counterHeight(MaxInt64/2) = %d, want about 50", got)
	}
	if got := overviewCounterWidth(maxCounterValue, maxCounterValue); got != 100 {
		t.Fatalf("overviewCounterWidth(MaxInt64) = %d, want 100", got)
	}
	if got := overviewCounterWidth(maxCounterValue/2, maxCounterValue); got < 49 || got > 50 {
		t.Fatalf("overviewCounterWidth(MaxInt64/2) = %d, want about 50", got)
	}
	if rx, tx := overviewCounterSegmentWidths(maxCounterValue, maxCounterValue); rx != 50 || tx != 50 {
		t.Fatalf("overviewCounterSegmentWidths(MaxInt64, MaxInt64) = %d/%d, want 50/50", rx, tx)
	}
	if rx, tx := overviewCounterSegmentWidths(1, maxCounterValue); rx != 1 || tx != 99 {
		t.Fatalf("overviewCounterSegmentWidths(1, MaxInt64) = %d/%d, want visible 1/99 split", rx, tx)
	}
	if rx, tx := overviewCounterSegmentWidths(0, 0); rx != 0 || tx != 0 {
		t.Fatalf("overviewCounterSegmentWidths(0, 0) = %d/%d, want 0/0", rx, tx)
	}
	if got := tunnelCounterBytes(TunnelView{RxBytes: maxCounterValue, TxBytes: maxCounterValue}); got != maxCounterValue {
		t.Fatalf("saturated tunnel total = %d, want MaxInt64", got)
	}

	d := misakaDeps()
	view := d.Snapshot()
	view.Nodes[0].Tunnels = []TunnelView{
		{Interface: "wg-max", RxBytes: maxCounterValue, CounterPresent: true, OK: true},
		{Interface: "wg-half", RxBytes: maxCounterValue / 2, CounterPresent: true, OK: true},
	}
	d.Snapshot = func() View { return view }
	body := misakaRequest(t, d, http.MethodGet, "/", nil, false).Body.String()
	if !strings.Contains(body, `style="width:100%"`) {
		t.Fatal("Overview did not render the maximum counter at its bounded width")
	}
	if strings.Contains(body, `width:-`) {
		t.Fatal("Overview emitted a negative CSS width after large-counter scaling")
	}
	if strings.Contains(body, `<div class=bars aria-label="Current cumulative counters by local interface">`) {
		t.Fatal("Overview regressed to the oversized current-counter bar chart")
	}
	for _, want := range []string{"wg-max", "wg-half", "RX", "TX", "Combined"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Overview current-counter detail is missing %q", want)
		}
	}
	for _, want := range []string{
		`class=current-counter-fill`,
		`class=current-counter-rx`,
		`class=current-counter-tx`,
		`<i class="counterkey rx"></i>RX`,
		`<i class="counterkey tx"></i>TX`,
		`Stacked segments compare each interface with the busiest interface.`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Overview current-counter color split is missing %q", want)
		}
	}
}

func TestTrafficOnlyRowsDoNotBecomeCarrierFailuresOrTopologyRoles(t *testing.T) {
	d := misakaDeps()
	view := d.Snapshot()
	view.Nodes[0].Tunnels = append(view.Nodes[0].Tunnels, TunnelView{
		Interface: "wg-signed-only", State: "counter-only",
		RxBytes: 10, TxBytes: 20, CounterPresent: true,
		TrafficTrusted: true, TrafficVerified: true,
	})
	view.Nodes = append(view.Nodes, NodeView{
		ID: "traffic-only", Declared: true, Health: "unknown",
		Tunnels: []TunnelView{{
			Interface: "wg-relayed", State: "counter-only", CounterPresent: true,
			TrafficTrusted: true, TrafficVerified: true,
		}},
	})
	d.Snapshot = func() View { return view }

	nodes := misakaRequest(t, d, http.MethodGet, "/nodes", nil, false).Body.String()
	if !strings.Contains(nodes, `traffic-only`) || !strings.Contains(nodes, `not reported<br><span class="tiny dim">—</span>`) {
		t.Fatal("traffic-only evidence incorrectly promoted the node to a topology role")
	}
	if !strings.Contains(nodes, `0 / 0 active`) {
		t.Fatal("traffic-only counter row was counted as a persistent carrier")
	}

	detail := misakaRequest(t, d, http.MethodGet, "/nodes/demo-d", nil, false).Body.String()
	for _, want := range []string{
		`1 / 1 active`,
		`<td class=mono>wg-signed-only<td class=dim>traffic counters only<td>—<td>10 B<td>20 B`,
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("carrier/counter boundary missing %q", want)
		}
	}
	if strings.Contains(detail, `<td class=bad>traffic counters only`) {
		t.Fatal("traffic-only row was painted as a carrier failure")
	}
}

func TestIntentCopyDistinguishesCurrentSSOTFromAppliedInventory(t *testing.T) {
	d := misakaDeps()
	view := d.Snapshot()
	view.IntentSource = "serving node applied inventory"
	view.Nodes[1].Declared = false
	d.Control = nil
	d.Snapshot = func() View { return view }

	for _, path := range []string{"/", "/nodes", "/nodes/demo-e", "/topology"} {
		body := misakaRequest(t, d, http.MethodGet, path, nil, false).Body.String()
		if !strings.Contains(body, "serving node applied inventory") {
			t.Errorf("%s omitted the applied-inventory source", path)
		}
		if strings.Contains(body, "current SSOT") {
			t.Errorf("%s mislabeled a regular node's applied inventory as current SSOT", path)
		}
	}
}
