package report

import (
	"testing"

	"loom/internal/model"
)

func publicHy2Node(id string) model.Node {
	return model.Node{
		ID: id, PublicEndpoint: id + ".example",
		Server: &model.ServerRole{Direction: model.Bidirectional, InboundPort: 61698},
	}
}

func TestExpectedDirectLinksCoverThreePublicInboundsWithoutExtraPairs(t *testing.T) {
	s := &model.SSOT{Nodes: []model.Node{
		publicHy2Node("demo-b"), publicHy2Node("demo-c"), publicHy2Node("demo-d"),
	}}
	links := ExpectedDirectLinksForSSOT(s)
	if len(links) != 3 {
		t.Fatalf("three nodes should retain exactly three unordered-pair probes: %+v", links)
	}
	want := map[string]bool{
		"demo-d→demo-b": true,
		"demo-b→demo-c":  true,
		"demo-c→demo-d": true,
	}
	wantPairOrder := []string{"demo-b\x00demo-c", "demo-b\x00demo-d", "demo-c\x00demo-d"}
	for i, link := range links {
		delete(want, link.From+"→"+link.To)
		a, b := link.From, link.To
		if b < a {
			a, b = b, a
		}
		if got := a + "\x00" + b; got != wantPairOrder[i] {
			t.Fatalf("probe pair order changed at %d: got %q want %q", i, got, wantPairOrder[i])
		}
	}
	if len(want) != 0 {
		t.Fatalf("public inbound ring is incomplete, missing=%v links=%+v", want, links)
	}
}

func TestExpectedDirectLinksDoNotPretendOneDirectionCoversBothTwoNodeInbounds(t *testing.T) {
	s := &model.SSOT{Nodes: []model.Node{publicHy2Node("a"), publicHy2Node("b")}}
	links := ExpectedDirectLinksForSSOT(s)
	if len(links) != 1 || links[0].From != "a" || links[0].To != "b" {
		t.Fatalf("two-node probe should remain one stable directional observation: %+v", links)
	}
}

func TestExpectedDirectLinksUseNonPublicInnerSourceToCoverPublicInbounds(t *testing.T) {
	nonPublic := func(id string) model.Node {
		return model.Node{ID: id, Server: &model.ServerRole{
			Direction: model.Bidirectional, InboundPort: 61698,
		}}
	}
	for name, nodes := range map[string][]model.Node{
		"one public":  {nonPublic("a"), publicHy2Node("b")},
		"two publics": {nonPublic("a"), publicHy2Node("b"), publicHy2Node("c")},
	} {
		t.Run(name, func(t *testing.T) {
			inbound := map[string]int{}
			for _, link := range ExpectedDirectLinksForSSOT(&model.SSOT{Nodes: nodes}) {
				inbound[link.To]++
			}
			for i := range nodes {
				if nodes[i].PubliclyDialable() && inbound[nodes[i].ID] == 0 {
					t.Errorf("public inbound %s was not covered: %+v", nodes[i].ID, inbound)
				}
			}
		})
	}
}
