package webui

import (
	"strings"
	"testing"
)

func TestEvidenceFailureIsVisibleOutsideOverview(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Warnings = []string{"中控 SSOT 元数据不可用:parse failed"}
	v.TrafficHistoryStatus = "unavailable"
	v.TrafficHistoryError = "retained store damaged"
	d.Snapshot = func() View { return v }

	for name, page := range map[string]string{
		"nodes":    pageNodes(d, false, ""),
		"services": pageServices(d, "", false, "", false, nil, false),
		"topology": pageTopology(d, false),
		"paths":    pageRouting(d, false),
	} {
		for _, want := range []string{"Evidence is incomplete", "parse failed", "retained store damaged"} {
			if !strings.Contains(page, want) {
				t.Errorf("%s page hid evidence failure %q", name, want)
			}
		}
		if !strings.Contains(page, `class="status-alert problem evidence-alert"`) || strings.Contains(page, `<ul>`) {
			t.Errorf("%s page did not use the compact evidence alert", name)
		}
	}
}

func TestTrafficHistoryUnsupportedDiffersFromControlStoreFailure(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.TrafficHistory = nil
	v.TrafficHistoryStatus = "not_supported"
	d.Snapshot = func() View { return v }
	if body := pageTopology(d, false); !strings.Contains(body, "History is not retained on this node") || strings.Contains(body, "Retained traffic store unavailable") {
		t.Fatalf("not-supported history was not kept distinct from a store failure: %s", body)
	}

	v.TrafficHistoryStatus = "unavailable"
	v.TrafficHistoryError = "disk read failed"
	if body := pageTopology(d, false); !strings.Contains(body, "Retained traffic store unavailable") || !strings.Contains(body, "disk read failed") {
		t.Fatalf("control-store failure lost its explicit state: %s", body)
	}
}

func TestNodeLifecycleAndEndpointEvidenceStayExplicit(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Nodes[0].PublicEndpoint = "edge.example.net"
	v.Nodes[0].SSHPort = 22
	v.Nodes[1].Decommission = true
	d.Snapshot = func() View { return v }

	nodes := pageNodes(d, false, "")
	for _, want := range []string{"1 <small>trusted</small>", "1 decommissioned", "Decommissioned", "Declared endpoint / SSH port", "UDP ingress unverified"} {
		if !strings.Contains(nodes, want) {
			t.Errorf("Nodes page is missing lifecycle/endpoint boundary %q", want)
		}
	}
	detail, found := pageNodeDetail(d, v.Nodes[0].ID, false)
	if !found || !strings.Contains(detail, "Declared endpoint") || !strings.Contains(detail, "UDP ingress unverified") {
		t.Fatalf("Node detail treats declared endpoint as verified: found=%v", found)
	}
}

func TestTopologyOverlaysOnlyExplicitRoutingEntry(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	d.Snapshot = func() View { return v }

	if body := pageTopology(d, false); strings.Contains(body, `class=route marker-end`) {
		t.Fatal("Topology overlaid all fresh Agent paths by default")
	}
	key := routingRouteKey(v.Routes[0])
	if body := pageTopology(d, false, key); !strings.Contains(body, `class=route marker-end`) || !strings.Contains(body, `1 overlaid`) {
		t.Fatal("Topology did not overlay the explicitly selected Agent path")
	}
}

func TestEventsShowsCurrentStateSeparatelyFromHistory(t *testing.T) {
	d := misakaDeps()
	d.Unresolved = func() []UnresolvedView {
		return []UnresolvedView{{
			Node: "sg02", Kind: "tunnel", Subject: "wg-jm24", State: "failed",
			Detail: "current signed observation", Level: "problem", Lasted: "4m",
		}}
	}
	body := pageEvents(d, eventFilter{}, false)
	for _, want := range []string{"Current unresolved state", "not reconstructed from transition history", "current signed observation", "已 4m"} {
		if !strings.Contains(body, want) {
			t.Errorf("Events page lost current-state boundary %q", want)
		}
	}
}

func TestDeploymentsExplainsIndependentConvergenceClocks(t *testing.T) {
	body := pageDeployments(misakaDeps(), false)
	for _, want := range []string{"Convergence clocks", "45s pull timer", "Policy cadence", "20-minute", "not deployment latency"} {
		if !strings.Contains(body, want) {
			t.Errorf("Deployments page is missing convergence explanation %q", want)
		}
	}
}
