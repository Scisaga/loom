package report

import (
	"sort"
	"strings"

	"loom/internal/model"
)

// expectedConfigFromSSOT derives the control UI's current desired topology.
// It deliberately contains no runtime settings: ordinary nodes use the
// Expected* fields in their applied report config, while the control node uses
// this projection so a just-saved SSOT change appears immediately rather than
// waiting for the control node to pull its own next snapshot.
func expectedConfigFromSSOT(s *model.SSOT) *Config {
	cfg := &Config{}
	if s == nil {
		return cfg
	}
	for i := range s.Nodes {
		cfg.ExpectedNodes = append(cfg.ExpectedNodes, s.Nodes[i].ID)
	}
	for i := range s.Tunnels {
		cfg.ExpectedTunnels = append(cfg.ExpectedTunnels, ExpectedTunnel{
			From: s.Tunnels[i].From, To: s.Tunnels[i].To,
		})
	}
	cfg.ExpectedDirectLinks = ExpectedDirectLinksForSSOT(s)
	for _, access := range s.AccessNodes() {
		cfg.ExpectedRoutes = append(cfg.ExpectedRoutes, ExpectedRoutesForAccess(s, access)...)
	}
	sort.Strings(cfg.ExpectedNodes)
	sort.Slice(cfg.ExpectedTunnels, func(i, j int) bool {
		a := cfg.ExpectedTunnels[i].From + "\x00" + cfg.ExpectedTunnels[i].To
		b := cfg.ExpectedTunnels[j].From + "\x00" + cfg.ExpectedTunnels[j].To
		return a < b
	})
	sort.Slice(cfg.ExpectedRoutes, func(i, j int) bool {
		a := cfg.ExpectedRoutes[i].Access + "\x00" + cfg.ExpectedRoutes[i].Declaration + "\x00" + strings.Join(cfg.ExpectedRoutes[i].Chain, "\x00")
		b := cfg.ExpectedRoutes[j].Access + "\x00" + cfg.ExpectedRoutes[j].Declaration + "\x00" + strings.Join(cfg.ExpectedRoutes[j].Chain, "\x00")
		return a < b
	})
	return cfg
}

// ExpectedDirectLinksForSSOT derives the no-secret inventory shared by the
// renderer and the control UI's live SSOT projection. Keeping it here prevents
// a just-saved/current SSOT view from dropping links that are present in the
// applied report config.
func ExpectedDirectLinksForSSOT(s *model.SSOT) []ExpectedDirectLink {
	if s == nil {
		return nil
	}
	var inner []*model.Node
	for i := range s.Nodes {
		n := &s.Nodes[i]
		runsSingBox := n.IsAccess() || (n.IsServer() && n.Server.InboundPort > 0)
		if n.Decommission || !n.MeshEligible() || !runsSingBox {
			continue
		}
		inner = append(inner, n)
	}
	sort.Slice(inner, func(i, j int) bool { return inner[i].ID < inner[j].ID })
	// When every inner-ring node exposes a public Hysteria2 inbound, the old
	// lexical orientation made the first node only a probe source and the last
	// node only a target. Reverse the single outer pair so every node is dialled
	// at least once, without adding another probe. With two nodes one directed
	// observation cannot cover both inbounds, so the stable lexical direction is
	// retained and the unobserved side remains explicitly unverified.
	allPublicHy2 := len(inner) >= 3
	for _, n := range inner {
		if !n.PubliclyDialable() || n.Server.InboundProtocol.Or() != model.Hysteria2 {
			allPublicHy2 = false
			break
		}
	}

	var out []ExpectedDirectLink
	for i := 0; i < len(inner); i++ {
		for j := i + 1; j < len(inner); j++ {
			a, b := inner[i], inner[j]
			from, to := a, b
			switch {
			case allPublicHy2 && i == 0 && j == len(inner)-1:
				from, to = b, a
			case b.PubliclyDialable() && b.Server.InboundProtocol.Or() == model.Hysteria2:
				// Stable default: lexical a -> b.
			case a.PubliclyDialable() && a.Server.InboundProtocol.Or() == model.Hysteria2:
				from, to = b, a
			default:
				continue
			}
			out = append(out, ExpectedDirectLink{
				From: from.ID, To: to.ID, Transport: "hysteria2", Carrier: "public",
			})
		}
	}
	pairKey := func(link ExpectedDirectLink) string {
		a, b := link.From, link.To
		if b < a {
			a, b = b, a
		}
		return a + "\x00" + b
	}
	sort.Slice(out, func(i, j int) bool {
		return pairKey(out[i]) < pairKey(out[j])
	})
	return out
}

// ExpectedRoutesForAccess mirrors the selectors the current L4 Agent can
// actually receive. The render package uses this same function when filling
// report.expected_routes, and its cross-contract test compares the result with
// the rendered Agent declarations.
func ExpectedRoutesForAccess(s *model.SSOT, access *model.Node) []ExpectedRoute {
	if s == nil || access == nil || !access.IsAccess() {
		return nil
	}
	credentials := s.CredentialByID()
	allowed := map[string]bool{}
	var declarationIDs []string
	for _, credentialID := range access.Access.Credentials {
		credential := credentials[credentialID]
		if credential == nil || credential.Revoked() || credential.Declaration == "" || allowed[credential.Declaration] {
			continue
		}
		allowed[credential.Declaration] = true
		declarationIDs = append(declarationIDs, credential.Declaration)
	}
	sort.Strings(declarationIDs)

	pinned := map[string]bool{}
	for _, mixed := range access.Access.MixedPorts {
		if !mixed.ByService() && mixed.Declaration != "" {
			pinned[mixed.Declaration] = true
		}
	}
	if policy := access.Access.EffectiveDefaultDeclaration(); policy != "" {
		pinned[policy] = true
	}

	declarations := s.DeclarationByID()
	seen := map[string]bool{}
	var out []ExpectedRoute
	add := func(declaration string, chain []string) {
		key := declaration + "\x00" + strings.Join(chain, "\x00")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ExpectedRoute{Access: access.ID, Declaration: declaration,
			Chain: append([]string(nil), chain...)})
	}
	for _, declarationID := range declarationIDs {
		declaration := declarations[declarationID]
		if declaration == nil || !l4AgentObjectiveSupported(declaration.Objective) {
			continue
		}
		if pinned[declarationID] {
			candidates, _ := s.EnumerateCandidates(access, declaration)
			for i := range candidates {
				add(declarationID, candidates[i].ServerChain)
			}
		}
		for _, service := range s.ServicesFor(declarationID) {
			if !serviceHasProbeTarget(service) {
				continue
			}
			candidates, _ := s.EnumerateServiceCandidates(access, declaration, service)
			for i := range candidates {
				add(service.ID, candidates[i].ServerChain)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Declaration != out[j].Declaration {
			return out[i].Declaration < out[j].Declaration
		}
		return strings.Join(out[i].Chain, "\x00") < strings.Join(out[j].Chain, "\x00")
	})
	return out
}

func serviceHasProbeTarget(service *model.Service) bool {
	if service == nil {
		return false
	}
	for _, address := range service.Addresses {
		if !model.IsSuffix(address) {
			return true
		}
	}
	return false
}

func l4AgentObjectiveSupported(objective model.Objective) bool {
	switch objective {
	case model.Latency, model.Stability, model.Throughput:
		return true
	default:
		return false
	}
}
