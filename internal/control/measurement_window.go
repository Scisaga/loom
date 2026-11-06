package control

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This request-local inventory contains linear inputs only. Product coordinates
// are evaluated on demand; neither a query graph nor a delivery store is built.
type measurementInventory struct {
	view                    DeviceView
	nodes                   map[string]ViewNode
	resources               []TransportResource
	byResource              map[string]TransportResource
	owned                   map[string]string
	sources, exits, targets []string
	services                map[string][]Service
	policies                map[string][]NetworkPolicy
	links, total            uint64
}

func newMeasurementInventory(view DeviceView) *measurementInventory {
	v := &measurementInventory{view: view, nodes: viewNodes(view), resources: append([]TransportResource{}, view.Resources...), byResource: map[string]TransportResource{}, owned: map[string]string{}, services: map[string][]Service{}, policies: map[string][]NetworkPolicy{}}
	for id, node := range v.nodes {
		if containsString(node.Responsibilities, "forward") {
			v.sources = append(v.sources, id)
		}
		if id != view.DeviceID && containsString(node.Responsibilities, "internet_egress") {
			v.exits = append(v.exits, id)
		}
	}
	sort.Strings(v.sources)
	sort.Strings(v.exits)
	sort.Slice(v.resources, func(i, j int) bool { return v.resources[i].ID < v.resources[j].ID })
	for _, r := range v.resources {
		v.byResource[r.ID] = r
		if r.Kind == "wireguard" {
			v.owned[r.OwnerNodeID] = r.ID
		}
	}
	for _, p := range view.Policies {
		if p.Action == "allow" {
			v.policies[p.ServiceID] = append(v.policies[p.ServiceID], p)
		}
	}
	for _, s := range view.Services {
		if s.Kind == "internet" && len(v.policies[s.ID]) > 0 {
			for _, target := range s.ProbeURLs {
				if _, found := v.services[target]; !found {
					v.targets = append(v.targets, target)
				}
				v.services[target] = append(v.services[target], s)
			}
		}
	}
	sort.Strings(v.targets)
	v.links = uint64(len(v.sources)) * uint64(len(v.resources))
	v.total = v.links + uint64(len(v.exits))*uint64(len(v.targets))
	return v
}
func (v *measurementInventory) egressAllowed(source, target string) bool {
	if source == v.view.DeviceID || !containsString(v.nodes[source].Responsibilities, "internet_egress") {
		return false
	}
	for _, service := range v.services[target] {
		for _, policy := range v.policies[service.ID] {
			if policy.permitsEndpoint(service, source) {
				return true
			}
		}
	}
	return false
}
func (v *measurementInventory) link(source, resource string) (NetworkLink, bool, error) {
	return nodeNetworkLink(v.view.NetworkID, v.nodes[source], v.nodes[v.byResource[resource].OwnerNodeID], v.byResource[resource], v.owned[source])
}

type positionedMeasurementQuery struct {
	query    reportMeasurementQuery
	position uint64
}
type measurementQueryPage struct {
	queries []positionedMeasurementQuery
	next    uint64
}

func measurementQueryKey(query reportMeasurementQuery) (string, error) {
	digest, err := measurementSpecIndex(query.spec)
	if err != nil {
		return "", err
	}
	return query.source + "\x00" + string(digest[:]), nil
}

// Only invalidation uses this semantic slot. Query lookup and dedup retain
// the full current specification; a new resolver/spec cannot revive an old row.
func measurementQuerySlot(query reportMeasurementQuery) string {
	sample := query.spec
	return strings.Join([]string{query.source, sample.Level, sample.ResourceID, sample.LinkID, sample.Target, sample.Action}, "\x00")
}

// A successful page advances over absent/unknown specifications as well. The
// hint is untrusted and influences only ordering after current scope validation.
func deviceMeasurementQueryPage(ctx context.Context, projection Projection, view DeviceView, viewFor func(string) (DeviceView, string, error), start uint64, bounds measurementDeliveryBounds) (measurementQueryPage, error) {
	page := measurementQueryPage{queries: []positionedMeasurementQuery{}}
	if !bounds.valid() {
		return page, errors.New("invalid measurement query bounds")
	}
	inventory := newMeasurementInventory(view)
	if inventory.total == 0 {
		return page, nil
	}
	position := start % inventory.total
	type sourceScope struct {
		view      DeviceView
		resources map[string]TransportResource
		nodes     map[string]ViewNode
		targets   map[string]Service
	}
	sources := map[string]sourceScope{}
	sourceFor := func(id string) (sourceScope, error) {
		if scope, ok := sources[id]; ok {
			return scope, nil
		}
		source, _, err := viewFor(id)
		identity, exists := identityFor(projection, id)
		if err != nil || !exists || source.NetworkID != projection.NetworkID || source.DeviceID != id || source.DevicePublicKey != identity.DevicePublicKey {
			return sourceScope{}, errors.New("measurement source has no current authenticated scope")
		}
		scope := sourceScope{view: source, resources: map[string]TransportResource{}, nodes: viewNodes(source), targets: map[string]Service{}}
		for _, resource := range source.Resources {
			scope.resources[resource.ID] = resource
		}
		// EgressProbes fixes the first target's request/resolver parameters. Reuse
		// that exact rule without expanding all per-source probe specifications.
		for _, service := range finalInternetServices(source) {
			for _, target := range service.ProbeURLs {
				if _, found := scope.targets[target]; !found {
					scope.targets[target] = service
				}
			}
		}
		sources[id] = scope
		return scope, nil
	}
	seen := map[string]bool{}
	used := 0
	for scanned := uint64(0); scanned < min(uint64(bounds.Scans), inventory.total); scanned++ {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		if len(page.queries) >= bounds.Queries {
			break
		}
		var source, target string
		var link NetworkLink
		var allowed bool
		var err error
		if position < inventory.links {
			source = inventory.sources[position/uint64(len(inventory.resources))]
			resource := inventory.resources[position%uint64(len(inventory.resources))]
			link, allowed, err = inventory.link(source, resource.ID)
		} else {
			offset := position - inventory.links
			source = inventory.exits[offset/uint64(len(inventory.targets))]
			target = inventory.targets[offset%uint64(len(inventory.targets))]
			allowed = inventory.egressAllowed(source, target)
		}
		if err != nil {
			return page, err
		}
		if !allowed {
			position = (position + 1) % inventory.total
			continue
		}
		if _, found := sources[source]; !found && len(sources) >= bounds.Sources {
			break
		}
		scope, err := sourceFor(source)
		if err != nil {
			return page, err
		}
		query := reportMeasurementQuery{source: source, publicKey: scope.view.DevicePublicKey}
		if target != "" {
			service, found := scope.targets[target]
			if !found {
				position = (position + 1) % inventory.total
				continue
			}
			spec, err := egressProbeSpec(view.NetworkID, source, target, scope.view.DNSServers, service.IsPublicInternet())
			if err != nil {
				return page, err
			}
			query.spec = Observation{Level: "egress", Target: target, Action: "https_request", SpecDigest: spec}
		} else {
			to := inventory.byResource[link.ResourceID]
			if !containsString(scope.view.Responsibilities, "forward") || !sameContractValue(to, scope.resources[to.ID]) {
				position = (position + 1) % inventory.total
				continue
			}
			if from := inventory.byResource[link.FromResourceID]; from.ID != "" && !sameContractValue(from, scope.resources[from.ID]) {
				position = (position + 1) % inventory.total
				continue
			}
			sourceNode := scope.nodes[source]
			current, ok, err := nodeNetworkLink(view.NetworkID, sourceNode, scope.nodes[to.OwnerNodeID], to, link.FromResourceID)
			if err != nil {
				return page, err
			}
			if !ok || !sameContractValue(current, link) {
				position = (position + 1) % inventory.total
				continue
			}
			spec, err := directedLinkSpec(view.NetworkID, link, sourceNode, to)
			if err != nil {
				return page, err
			}
			recipientSpec, err := directedLinkSpec(view.NetworkID, link, inventory.nodes[source], to)
			if err != nil {
				return page, err
			}
			if recipientSpec != spec {
				position = (position + 1) % inventory.total
				continue
			}
			query.spec = Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)), Action: link.ProbeTarget.Action}
		}
		key, err := measurementQueryKey(query)
		if err != nil {
			return page, err
		}
		if !seen[key] {
			encoded, err := CanonicalEncode(map[string]any{"level": query.spec.Level, "resource_id": query.spec.ResourceID, "link_id": query.spec.LinkID, "target": query.spec.Target, "action": query.spec.Action, "spec_digest": query.spec.SpecDigest})
			if err != nil {
				return page, err
			}
			cost := len(encoded) + len(query.source) + len(query.publicKey)
			if used+cost > bounds.Bytes {
				if len(page.queries) > 0 {
					break
				}
				position = (position + 1) % inventory.total
				continue
			}
			page.queries = append(page.queries, positionedMeasurementQuery{query, position})
			seen[key] = true
			used += cost
		}
		position = (position + 1) % inventory.total
	}
	page.next = position
	return page, nil
}

func selectMeasurementWindow(full DeviceLinkObservations, page measurementQueryPage, samples []DeviceLinkObservation, bounds measurementDeliveryBounds) (DeviceLinkObservations, uint64, error) {
	full.Cursor = measurementCursorSizeValue(page.next)
	full.Reset = true
	full.Removed = []string{}
	full.Observations = []DeviceLinkObservation{}
	base, err := CanonicalEncode(full)
	if err != nil || len(base) > bounds.Bytes {
		return full, 0, errors.New("measurement envelope exceeds byte budget")
	}
	byQuery := map[string]DeviceLinkObservation{}
	for _, sample := range samples {
		key, err := measurementQueryKey(reportMeasurementQuery{source: sample.DeviceID, spec: sample.Observation})
		if err != nil {
			return full, 0, err
		}
		byQuery[key] = sample
	}
	used, next := len(base), page.next
	for _, item := range page.queries {
		key, err := measurementQueryKey(item.query)
		if err != nil {
			return full, 0, err
		}
		sample, found := byQuery[key]
		if !found {
			continue
		}
		encoded, err := CanonicalEncode(sample)
		if err != nil {
			return full, 0, err
		}
		cost := len(encoded)
		if len(full.Observations) > 0 {
			cost++
		}
		if used+cost > bounds.Bytes {
			if len(full.Observations) > 0 {
				next = item.position
				break
			}
			continue
		}
		full.Observations = append(full.Observations, sample)
		used += cost
	}
	sort.Slice(full.Observations, func(i, j int) bool {
		return measurementDeliveryOrder(full.Observations[i]) < measurementDeliveryOrder(full.Observations[j])
	})
	full.Cursor = measurementCursorSizeValue(next)
	return full, next, nil
}

func projectDeviceMeasurementWindow(ctx context.Context, store *ObservationStore, projection Projection, recipient, requestedDigest, cursor string, now time.Time, viewFor func(string) (DeviceView, string, error), bounds measurementDeliveryBounds, previous *measurementSnapshot) (DeviceLinkObservations, uint64, error) {
	view, digest, err := viewFor(recipient)
	if err != nil || view.DeviceID != recipient || digest != requestedDigest {
		return DeviceLinkObservations{}, 0, errors.New("current device View required")
	}
	page, err := deviceMeasurementQueryPage(ctx, projection, view, viewFor, measurementPosition(cursor), bounds)
	if err != nil {
		return DeviceLinkObservations{}, 0, err
	}
	queries := make([]reportMeasurementQuery, 0, len(page.queries))
	for _, item := range page.queries {
		queries = append(queries, item.query)
	}
	samples, checked, generations, err := store.latestMeasurementWindow(ctx, projection.NetworkID, queries, now, MeasurementDeliveryLimit)
	if checked < len(page.queries) {
		page.next = page.queries[checked].position
		page.queries = page.queries[:checked]
	}
	if err != nil {
		return DeviceLinkObservations{}, 0, err
	}
	full := DeviceLinkObservations{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.DeviceID, ViewDigest: digest}
	result, next, err := selectMeasurementWindow(full, page, samples, bounds)
	if err != nil {
		return result, 0, err
	}
	if previous != nil {
		result, err = retainMeasurementWorkingSet(result, previous.values, page, generations, view, now, bounds)
		if err != nil {
			return result, 0, err
		}
	}
	return result, next, result.validateForViewDigest(view, digest)
}

// Newly queried rows get first admission even when their original sample time
// is old. Retained rows remain originals, never evidence of a new measurement.
func retainMeasurementWorkingSet(fresh DeviceLinkObservations, previous []DeviceLinkObservation, page measurementQueryPage, generations map[string]string, view DeviceView, now time.Time, bounds measurementDeliveryBounds) (DeviceLinkObservations, error) {
	queried := map[string]bool{}
	for _, item := range page.queries {
		queried[measurementQuerySlot(item.query)] = true
	}
	inventory := newMeasurementInventory(view)
	retained := []DeviceLinkObservation{}
	for _, row := range previous {
		if row.CurrentUntil <= now.UnixMilli() || row.Observation.ObservedAt > now.UnixMilli() || validateDeliveredMeasurement(view, inventory, row) != nil {
			continue
		}
		if generation, known := generations[row.DeviceID]; known && generation != row.Observation.NetworkGeneration {
			continue
		}
		if queried[measurementQuerySlot(reportMeasurementQuery{source: row.DeviceID, spec: row.Observation})] {
			continue
		}
		retained = append(retained, row)
	}
	sort.Slice(retained, func(i, j int) bool {
		if retained[i].Observation.ObservedAt != retained[j].Observation.ObservedAt {
			return retained[i].Observation.ObservedAt > retained[j].Observation.ObservedAt
		}
		return measurementDeliveryOrder(retained[i]) < measurementDeliveryOrder(retained[j])
	})
	encoded, err := CanonicalEncode(fresh)
	if err != nil {
		return fresh, err
	}
	used := len(encoded)
	for _, row := range retained {
		encoded, err := CanonicalEncode(row)
		if err != nil {
			return fresh, err
		}
		cost := len(encoded)
		if len(fresh.Observations) > 0 {
			cost++
		}
		if used+cost > bounds.Bytes {
			continue
		}
		fresh.Observations = append(fresh.Observations, row)
		used += cost
	}
	sort.Slice(fresh.Observations, func(i, j int) bool {
		return measurementDeliveryOrder(fresh.Observations[i]) < measurementDeliveryOrder(fresh.Observations[j])
	})
	return fresh, nil
}
