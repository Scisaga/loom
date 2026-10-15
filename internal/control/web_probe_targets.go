package control

import "sort"

// WebBusinessProbeTarget projects the complete shared pool. Matching a Service's
// target scope asserts neither device authorization nor a probe observation.
type WebBusinessProbeTarget struct {
	ID                string   `json:"id"`
	URL               string   `json:"url"`
	MatchedServiceIDs []string `json:"matched_service_ids"`
}

func projectWebBusinessProbeTargets(projection Projection) []WebBusinessProbeTarget {
	targets := make([]WebBusinessProbeTarget, 0, len(projection.NetworkIntent.BusinessProbeTargets))
	records := projectDNSRecords(projection.NetworkIntent.DNSRecords)
	for _, target := range projection.NetworkIntent.BusinessProbeTargets {
		value := WebBusinessProbeTarget{ID: target.ID, URL: target.URL, MatchedServiceIDs: []string{}}
		for _, service := range projection.NetworkIntent.Services {
			if targetMatchesService(target.URL, service, records...) {
				value.MatchedServiceIDs = append(value.MatchedServiceIDs, service.ID)
			}
		}
		sort.Strings(value.MatchedServiceIDs)
		targets = append(targets, value)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return targets
}
