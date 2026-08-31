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
	v.Nodes[0].InboundPort = 61698
	v.Nodes[0].InboundProtocol = "hysteria2"
	v.Nodes[0].IngressKnown = true
	v.Nodes[0].PublicDialable = true
	v.Nodes[1].Decommission = true
	d.Snapshot = func() View { return v }

	nodes := pageNodes(d, false, "")
	for _, want := range []string{"1 <small>trusted</small>", "1 decommissioned", "Decommissioned", "节点地址 / SSH 端口", "公网数据入口", "edge.example.net:61698", "SSOT 已声明 · 公网入站未验证"} {
		if !strings.Contains(nodes, want) {
			t.Errorf("Nodes page is missing lifecycle/endpoint boundary %q", want)
		}
	}
	detail, found := pageNodeDetail(d, v.Nodes[0].ID, false)
	if !found || !strings.Contains(detail, "声明地址") || !strings.Contains(detail, "公网数据入口") || !strings.Contains(detail, "edge.example.net:61698") || !strings.Contains(detail, "公网入站未验证") {
		t.Fatalf("Node detail treats declared endpoint as verified: found=%v", found)
	}
}

func TestNodePublicIngressDistinguishesPublicTunnelOnlyAndClosed(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Nodes = []NodeView{
		{
			ID: "public", Declared: true, PublicEndpoint: "edge.example.net",
			Direction: "bidirectional", InboundPort: 61698, InboundProtocol: "hysteria2", IngressKnown: true, PublicDialable: true,
		},
		{
			ID: "tunnel", Declared: true, PublicEndpoint: "reverse.example.net",
			Direction: "reverse_only", InboundPort: 443, InboundProtocol: "trojan", IngressKnown: true,
		},
		{ID: "closed", Declared: true, PublicEndpoint: "control.example.net", Direction: "bidirectional", IngressKnown: true},
	}
	d.Snapshot = func() View { return v }

	list := pageNodes(d, false, "")
	for _, want := range []string{
		"edge.example.net:61698", "Hysteria2 / UDP", "公网入站未验证",
		"仅隧道内", "Trojan / TCP+TLS · 端口 443", "隧道入站未验证",
		"未开放", "SSOT 未声明 server inbound",
	} {
		if !strings.Contains(list, want) {
			t.Errorf("Nodes page is missing public ingress state %q", want)
		}
	}

	closed, found := pageNodeDetail(d, "closed", false)
	if !found {
		t.Fatal("closed node detail was not rendered")
	}
	if !strings.Contains(closed, "未开放") || !strings.Contains(closed, "SSOT 未声明 server inbound") {
		t.Fatalf("closed node did not explain absent inbound: %s", closed)
	}
	if strings.Contains(closed, "ingress unverified") || strings.Contains(closed, "入站未验证") {
		t.Fatal("node without inbound was mislabeled as an unverified listener")
	}
}

func TestNodePublicIngressDoesNotTurnMissingMetadataIntoClosedIntent(t *testing.T) {
	d := misakaDeps()
	d.Control = nil
	v := d.Snapshot()
	v.Nodes = []NodeView{{ID: "remote", Declared: true, Health: "unknown"}}
	d.Snapshot = func() View { return v }

	list := pageNodes(d, false, "")
	for _, want := range []string{"未知", "当前视图无入口声明信息", "请在中控查看"} {
		if !strings.Contains(list, want) {
			t.Errorf("ordinary node view is missing unknown ingress boundary %q", want)
		}
	}
	if strings.Contains(list, "SSOT 未声明 server inbound") {
		t.Fatal("ordinary node view turned absent metadata into closed desired state")
	}

	detail, found := pageNodeDetail(d, "remote", false)
	if !found || !strings.Contains(detail, "当前视图无入口声明信息") || strings.Contains(detail, "SSOT 未声明 server inbound") {
		t.Fatalf("ordinary node detail misrepresented unknown ingress metadata: found=%v body=%s", found, detail)
	}
}

func TestNodePublicIngressKeepsEndpointButDisablesNewAccessDuringLifecycle(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Nodes = []NodeView{
		{ID: "draining", Declared: true, PublicEndpoint: "drain.example.net", InboundPort: 61698, InboundProtocol: "hysteria2", IngressKnown: true, PublicDialable: true, Drain: true},
		{ID: "gone", Declared: true, PublicEndpoint: "gone.example.net", InboundPort: 443, InboundProtocol: "trojan", IngressKnown: true, PublicDialable: true, Decommission: true},
	}
	d.Snapshot = func() View { return v }

	body := pageNodes(d, false, "")
	for _, want := range []string{
		"drain.example.net:61698", "正在排空 · 不用于新客户端接入",
		"gone.example.net:443", "已下线 · 不用于新客户端接入",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("lifecycle-aware ingress view is missing %q", want)
		}
	}
}

func TestNodeInventoryExplainsRolesDirectionAndStableIdentity(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Nodes[0].Roles = []string{"control", "access", "server", "egress"}
	v.Nodes[0].Direction = "bidirectional"
	v.Nodes[1].Roles = []string{"server", "egress"}
	v.Nodes[1].Direction = "reverse_only"
	d.Snapshot = func() View { return v }

	body := pageNodes(d, false, "")
	for _, want := range []string{
		"<b>本机接管</b> 接管本机流量并执行选路",
		"<b>可作出口</b> 可作为路径末端访问公网",
		"<b>隧道方向</b> 只描述 WireGuard 建连职责",
		"节点 ID</b> 加入时确定，不随系统 hostname 自动变化",
		"中控 + 本机接管 + 转发 + 可作出口",
		"只主动连接，不接受入站",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Nodes role explanation is missing %q", want)
		}
	}
}

func TestNodeInventoryContainsItsWideTableOverflow(t *testing.T) {
	body := pageNodes(misakaDeps(), false, "")
	if !strings.Contains(body, `class="card node-inventory-card"`) {
		t.Fatal("Nodes inventory table is missing its scoped overflow container")
	}
	if !strings.Contains(style, `.node-inventory-card{overflow-x:auto}`) {
		t.Fatal("Nodes inventory overflow rule is missing from the scoped card class")
	}
}

func TestOverviewAttentionNamesProblemAndUnknownNodesWithoutContradiction(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Nodes = []NodeView{
		{ID: "jm24", Declared: true, Health: "problem"},
		{ID: "vm-0-3-ed43", Declared: true, Health: "unknown"},
	}
	d.Snapshot = func() View { return v }
	d.Unresolved = nil

	body := pageOverview(d, false)
	for _, want := range []string{
		"1 个节点存在异常，另有 1 个等待状态上报",
		"异常：<span class=mono>jm24",
		"等待上报：<span class=mono>vm-0-3-ed43",
		"尚未上线时，与它相连的预期隧道也可能让相邻节点暂时显示异常",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Overview attention summary is missing %q", want)
		}
	}
	if strings.Contains(body, "No confirmed fault") {
		t.Fatal("Overview contradicted the node problem state")
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

func TestTopologyProjectsAutomaticRoutingWithoutPathControls(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Routes = append(v.Routes, RouteView{
		Node: "jm24", Declaration: "cn-web", Selector: "svc:cn-web",
		ScopeKind: ScopeService, ScopeID: "cn-web", PolicyID: "local",
		Chain: []string{"jm24"}, ObservedAt: v.ObservedAt, Source: "agent/jm24",
	})
	v.Services = append(v.Services, ServiceView{ID: "cn-web", Name: "Domestic web", PolicyID: "local"})
	d.Snapshot = func() View { return v }

	body := pageTopology(d, false)
	for _, want := range []string{
		`class=route marker-end`, "Automatic routing", "Read-only · automatic Agent decisions",
		"Host → Service → Policy", "International APIs", "jm24 → sg02",
		"Domestic web", "jm24 → local exit", ">LOCAL EXIT</text>",
		"Automatic Agent route · read-only", "View decision evidence",
		"新增节点按 direction 自动进入对应环", "不参与节点排序或改变布局",
		"topology-layout", "topology-status-grid", "Intent matched with signed evidence",
		"动态双环 · 自动路径只读叠加", "指标与交互口径",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Topology automatic routing projection is missing %q", want)
		}
	}
	if got := strings.Count(body, `marker-end="url(#arrow)"`); got != 1 {
		t.Fatalf("Topology drew %d automatic route segment(s), want only the remote-hop decision", got)
	}
	for _, unwanted := range []string{
		`<select name=entry`, "No Agent path overlay", ">Apply</button>", "overlaid",
		"Persistent carriers", "Carrier observation",
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("Topology still presents automatic routes as a client choice %q", unwanted)
		}
	}

	key := routingRouteKey(v.Routes[0])
	focused := pageTopology(d, false, key)
	for _, want := range []string{"Focused automatic decision", "Show all current decisions", "Focused on map"} {
		if !strings.Contains(focused, want) {
			t.Errorf("Topology diagnostic focus is missing %q", want)
		}
	}
}

func TestLivePathsPresentsRulesAsAutomaticReadOnlyDecisions(t *testing.T) {
	body := pageRouting(misakaDeps(), false)
	for _, want := range []string{
		"Automatic routing scopes", "Current automatic decision",
		"not a client path choice", "not client-selectable paths",
		"International APIs", "jm24 → sg02", "Inspect in topology",
		"routing-summary", "routing-decision-card", "routing-decision-table", "route-text",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Live paths automatic routing semantics are missing %q", want)
		}
	}
	for _, unwanted := range []string{`<select name=entry`, ">View</button>", "Overlay in topology"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("Live paths still presents a routing decision as a picker %q", unwanted)
		}
	}
	if strings.Contains(body, `</table></div></div><div class="section routing-candidates">`) {
		t.Fatal("Live paths closes the main content container before the candidate section")
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
		"Hy2 direct · 主动探测", "achieved probe throughput", "not broken tunnels",
		"no continuous RTT or heartbeat", "SSOT RouteCandidate.ServerChain",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Topology page lost the carrier/intent boundary %q", want)
		}
	}
	if strings.Contains(body, "candidate</td>") || strings.Contains(body, "unverified</td>") || strings.Contains(body, "时间未记录") {
		t.Fatal("Topology page exposed internal candidate state as a failed or missing carrier observation")
	}
}

func TestTopologyDirectProbeStatusSeparatesDeclaredFromSampled(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Links = append(v.Links,
		LinkView{From: "jm24", To: "gz02", Kind: "direct-hy2", Samples: 3},
		LinkView{From: "gz02", To: "hz01", Kind: "direct-hy2"},
	)
	d.Snapshot = func() View { return v }

	body := pageTopology(d, false)
	for _, want := range []string{`1 <small>/ 2 sampled</small>`, `1 warming up / unknown`} {
		if !strings.Contains(body, want) {
			t.Errorf("Topology direct-probe status missing %q", want)
		}
	}
	if strings.Contains(body, `2 <small>measured hops</small>`) {
		t.Fatal("Topology counted an expected direct edge with no samples as measured")
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
