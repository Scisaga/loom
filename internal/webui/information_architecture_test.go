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

func TestEnrollmentAccessUsesCompactIdentityAndBoundaryLayout(t *testing.T) {
	body := pageNodes(misakaDeps(), false, "")
	for _, want := range []string{
		`class="card enrollment-access"`, `class=enrollment-identity-meta`,
		`class=enrollment-public-key`, `class=enrollment-boundary-list`,
		`class=enrollment-key-note`, "Ready · shared by every enrollment",
		"Open enrollment workflow", "Download .pub",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Enrollment access layout is missing %q", want)
		}
	}
	if strings.Contains(body, `<textarea class=compact readonly aria-label="Shared control public key">`) {
		t.Fatal("Enrollment public key still uses the oversized textarea layout")
	}
}

func TestEnrollmentPreflightShowsProgressAndRetryableLocalInterruption(t *testing.T) {
	d := misakaDeps()
	d.Control.Enrollment = &NodeEnrollmentDeps{}
	body := pageNodeAdd(d, nodeAddPageState{
		Phase:      "confirm",
		Connection: EnrollmentConnection{Host: "203.0.113.42", User: "root", Port: 22},
		HostKey: EnrollmentHostKey{
			Algorithm: "ssh-ed25519", PublicKey: "AAAAC3Nza", Fingerprint: "SHA256:test",
		},
		Error: "trusted SSH preflight: SSH preflight was interrupted because the local control service stopped or restarted; retry after it is running again",
	}, true)
	for _, want := range []string{
		`class="green progress-submit"`, `class=button-spinner`, "Checking and installing prerequisites…",
		"data-submit-progress", `form.classList.add("is-submitting")`, "button.disabled=true",
		"Enrollment was interrupted locally — safe to retry",
		"The remote host did not reject enrollment", "@keyframes loom-spin",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Enrollment preflight feedback is missing %q", want)
		}
	}
}

func TestEnrollmentPreflightExplainsAutomaticWireGuardInstallFailure(t *testing.T) {
	d := misakaDeps()
	d.Control.Enrollment = &NodeEnrollmentDeps{}
	body := pageNodeAdd(d, nodeAddPageState{
		Phase: "confirm",
		Error: "install wireguard-tools during trusted SSH preflight: install remote wireguard-tools failed",
	}, true)
	for _, want := range []string{"Automatic WireGuard tools installation failed", "supported package manager", "wireguard-tools", "SSOT was not changed"} {
		if !strings.Contains(body, want) {
			t.Errorf("Missing WireGuard tools guidance is missing %q", want)
		}
	}
}

func TestEnrollmentPreflightExplainsUnnormalizableRemoteNodeID(t *testing.T) {
	d := misakaDeps()
	d.Control.Enrollment = &NodeEnrollmentDeps{}
	body := pageNodeAdd(d, nodeAddPageState{
		Phase: "confirm",
		Error: `remote hostname "---" cannot be normalized into a valid Node ID; require at least one ASCII letter or digit`,
	}, true)
	for _, want := range []string{"Remote hostname cannot be converted to a Node ID", "lowercases", "separator", "SSOT was not changed"} {
		if !strings.Contains(body, want) {
			t.Errorf("Invalid remote Node ID guidance is missing %q", want)
		}
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

func TestTopologySeparatesCarrierEvidenceFromOnDemandIntent(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Nodes = append(v.Nodes, NodeView{ID: "gz02", Declared: true, Health: "healthy", Direction: "bidirectional"})
	v.Links = append(v.Links, LinkView{
		From: "gz02", To: "jm24", Kind: "candidate", State: "unverified",
		Source: "SSOT RouteCandidate.ServerChain · 候选跳，未核验",
	})
	d.Snapshot = func() View { return v }

	body := pageTopology(d, false)
	for _, want := range []string{
		"Persistent WireGuard carriers", "On-demand route hops", "Available by intent",
		"not broken tunnels", "no continuous RTT or heartbeat", "SSOT RouteCandidate.ServerChain",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Topology page lost the carrier/intent boundary %q", want)
		}
	}
	if strings.Contains(body, "candidate</td>") || strings.Contains(body, "unverified</td>") || strings.Contains(body, "时间未记录") {
		t.Fatal("Topology page exposed internal candidate state as a failed or missing carrier observation")
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
