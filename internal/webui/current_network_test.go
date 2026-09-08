package webui

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLivePagesExcludeRemovedDevicesAndPathsWithoutChangingEvidence(t *testing.T) {
	d := misakaDeps()
	v := d.Snapshot()
	v.Nodes = append(v.Nodes, NodeView{ID: "removed-device", Health: "healthy"})
	v.Links = append(v.Links, LinkView{From: "demo-d", To: "removed-device", Kind: "tunnel", State: "active"})
	for _, route := range []RouteView{
		{Node: "removed-device", Chain: []string{"removed-device", "demo-e"}},
		{Node: "demo-d", Chain: []string{"demo-d", "removed-device", "demo-e"}},
		{Node: "missing-device", Chain: []string{"missing-device", "demo-e"}},
	} {
		v.Routes = append(v.Routes, route)
		v.Candidates = append(v.Candidates, CandidatePathView{Node: route.Node, Chain: route.Chain, State: "selected"})
	}
	// Local exit selections have no server chain and must remain visible.
	v.Routes = append(v.Routes, RouteView{Node: "demo-d", Declaration: "local-rule"})
	d.Snapshot = func() View { return v }
	d.Unresolved = func() []UnresolvedView {
		return []UnresolvedView{
			{Node: "removed-device", Kind: "agent", Detail: "removed-alert"},
			{Node: "demo-e", Kind: "agent", Detail: "current-alert"},
		}
	}
	d.Events = nil
	before, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/topology", "/topology?entry=removed-device"} {
		body := get(t, Handler(d), path, nil).Body.String()
		for _, removed := range []string{"removed-device", "missing-device", "removed-alert"} {
			if strings.Contains(body, removed) {
				t.Errorf("%s resurrected %s from retained evidence", path, removed)
			}
		}
		for _, want := range []string{`data-node="demo-d"`, `data-node="demo-e"`, "local-rule", "International APIs"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lost current network evidence %q", path, want)
			}
		}
		if path == "/" && !strings.Contains(body, "current-alert") {
			t.Error("overview lost a current device alert")
		}
	}
	after, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("live page rendering mutated the shared evidence snapshot")
	}
	if !strings.Contains(pageNodes(d, false, ""), "removed-device") {
		t.Fatal("retained device evidence is no longer available for diagnostics")
	}
	// Removing every declaration must yield an empty live network, even when
	// observations, applied links and Agent decisions are still retained.
	for i := range v.Nodes {
		v.Nodes[i].Declared = false
	}
	for _, body := range []string{pageOverview(d, false), pageTopology(d, false)} {
		if strings.Contains(body, `data-node=`) || strings.Contains(body, "local-rule") {
			t.Error("empty inventory fell back to displaying retained observations")
		}
	}
}
