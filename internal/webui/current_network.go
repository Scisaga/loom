package webui

// currentNetworkView projects the live network from current declarations.
// Retained observations remain in the source snapshot for node diagnostics and
// history, but cannot bring removed or paused devices back into live pages.
// Allocate new slices because Snapshot may return shared, cached evidence.
func currentNetworkView(v View) View {
	current := make(map[string]bool, len(v.Nodes))
	nodes := make([]NodeView, 0, len(v.Nodes))
	for _, node := range v.Nodes {
		if node.Declared && !node.Paused {
			current[node.ID] = true
			nodes = append(nodes, node)
		}
	}
	v.Nodes = nodes
	currentPath := func(node string, chain []string) bool {
		if !current[node] {
			return false
		}
		for _, id := range chain {
			if !current[id] {
				return false
			}
		}
		return true
	}
	links := make([]LinkView, 0, len(v.Links))
	for _, link := range v.Links {
		if current[link.From] && current[link.To] {
			links = append(links, link)
		}
	}
	v.Links = links
	routes := make([]RouteView, 0, len(v.Routes))
	for _, route := range v.Routes {
		if currentPath(route.Node, route.Chain) {
			routes = append(routes, route)
		}
	}
	v.Routes = routes
	candidates := make([]CandidatePathView, 0, len(v.Candidates))
	for _, candidate := range v.Candidates {
		if currentPath(candidate.Node, candidate.Chain) {
			candidates = append(candidates, candidate)
		}
	}
	v.Candidates = candidates
	return v
}
