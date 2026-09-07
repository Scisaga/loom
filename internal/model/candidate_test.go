package model

import (
	"strings"
	"testing"
)

func TestHybridAccessNodeIsRepresentedAsLocalEgressWithoutSelfHop(t *testing.T) {
	access := Node{
		ID: "access",
		Server: &ServerRole{
			Direction: Bidirectional, EgressCapable: true,
		},
		Access: &AccessRole{Platform: LinuxServer},
	}
	remote := Node{
		ID: "remote", PublicEndpoint: "203.0.113.8",
		Server: &ServerRole{
			Direction: Bidirectional, InboundPort: 4433, EgressCapable: true,
		},
	}
	s := &SSOT{Nodes: []Node{access, remote}}
	d := &AccessDeclaration{
		ID: "best", AddressAxis: FromRequest, EgressAxis: EgressAny,
		AllowedServers: []string{"access", "remote"}, MaxHops: 1,
	}

	candidates, skips := s.EnumerateCandidates(&s.Nodes[0], d)
	if len(skips) != 0 {
		t.Fatalf("local egress was incorrectly reported as unusable: %+v", skips)
	}
	if len(candidates) != 2 || len(candidates[0].ServerChain) != 0 ||
		candidates[0].Tag() != "cand:best:direct" {
		t.Fatalf("local egress was not represented by exactly one zero-hop candidate: %+v", candidates)
	}
	if len(candidates[1].ServerChain) != 1 || candidates[1].ServerChain[0] != "remote" {
		t.Fatalf("remote egress candidate changed while adding local egress: %+v", candidates)
	}

	// A policy may explicitly pin the same hybrid node. The data-plane form is
	// still zero-hop; a one-hop chain would make the access node dial itself.
	d.EgressAxis = "pinned:access"
	d.AllowedServers = []string{"access"}
	candidates, skips = s.EnumerateCandidates(&s.Nodes[0], d)
	if len(skips) != 0 || len(candidates) != 1 || len(candidates[0].ServerChain) != 0 {
		t.Fatalf("pinned local egress did not stay zero-hop: candidates=%+v skips=%+v", candidates, skips)
	}
}

// A fixed-egress policy constrains only the last server in the chain.  Adding
// another eligible relay to allowed_servers must add another complete path;
// it must not turn that relay into an alternative exit.
func TestPinnedEgressRetainsAllAllowedIntermediatePaths(t *testing.T) {
	access := Node{ID: "client", Access: &AccessRole{Platform: WindowsDesktop}}
	server := func(id string, direction Direction) Node {
		return Node{
			ID: id, PublicEndpoint: "192.0.2.1",
			Server: &ServerRole{
				Direction: direction, InboundPort: 4433, EgressCapable: true,
			},
		}
	}
	s := &SSOT{
		Nodes: []Node{
			access,
			server("relay-a", Bidirectional),
			server("relay-b", Bidirectional),
			server("fixed-exit", ReverseOnly),
		},
		Tunnels: []Tunnel{
			{From: "relay-a", To: "fixed-exit", FromAddr: "10.0.0.1/32", ToAddr: "10.0.0.2/32"},
			{From: "relay-b", To: "fixed-exit", FromAddr: "10.0.1.1/32", ToAddr: "10.0.1.2/32"},
		},
	}
	d := &AccessDeclaration{
		ID: "fixed", AddressAxis: FromRequest, EgressAxis: "pinned:fixed-exit",
		AllowedServers: []string{"relay-a", "relay-b", "fixed-exit"}, MaxHops: 2,
	}

	candidates, skips := s.EnumerateCandidates(&s.Nodes[0], d)
	if len(skips) != 0 {
		t.Fatalf("eligible fixed-egress paths were skipped: %+v", skips)
	}
	want := map[string]bool{
		"relay-a>fixed-exit": true,
		"relay-b>fixed-exit": true,
	}
	if len(candidates) != len(want) {
		t.Fatalf("fixed-egress candidates = %+v, want one path through every relay", candidates)
	}
	for i := range candidates {
		candidate := &candidates[i]
		if candidate.Egress() != "fixed-exit" {
			t.Fatalf("relay escaped pinned last-hop constraint: %+v", candidate)
		}
		delete(want, strings.Join(candidate.ServerChain, ">"))
	}
	if len(want) != 0 {
		t.Fatalf("allowed intermediate paths missing: %v", want)
	}
}
