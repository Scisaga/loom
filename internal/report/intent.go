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
	if access.Access.Platform.UsesTUN() {
		policy := access.Access.DefaultDeclaration
		if policy == "" && len(declarationIDs) == 1 {
			policy = declarationIDs[0]
		}
		if policy != "" {
			pinned[policy] = true
		}
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
