package model

import "testing"

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
