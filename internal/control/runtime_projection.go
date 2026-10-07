package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"sort"
)

func digestContractValue(domain string, value any) (string, error) {
	body, err := CanonicalEncode(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func localCandidate(service Service, policy NetworkPolicy, finalExit string, records ...DNSRecord) (RouteCandidate, error) {
	identity := map[string]any{"service_id": service.ID, "first_resource_id": "", "node_chain": []string{}, "link_ids": []string{}, "final_exit": finalExit}
	id, err := digestContractValue("loom-candidate-id-v3\x00", identity)
	if err != nil {
		return RouteCandidate{}, err
	}
	spec, err := digestContractValue("loom-candidate-spec-v3\x00", dnsCandidateSpec(map[string]any{"identity": identity, "service": service, "policy": policy, "resources": []TransportResource{}, "links": []NetworkLink{}}, service, records))
	if err != nil {
		return RouteCandidate{}, err
	}
	return RouteCandidate{ID: id, SpecDigest: spec, Scope: "service:" + service.ID, ServiceID: service.ID,
		FirstResourceID: "", NodeChain: []string{}, LinkIDs: []string{}, FinalExit: finalExit}, nil
}

// servicePermissionValues verifies the selected current values without requiring
// a deleted Policy or Service to reappear. Missing references grant nothing.
func servicePermissionValues(view DeviceView) (map[string]Service, map[string]NetworkPolicy, error) {
	if validateIDSet(view.PolicyIDs) != nil || view.Services == nil || view.Policies == nil {
		return nil, nil, errors.New("service permission values are incomplete")
	}
	services := map[string]Service{}
	for index, service := range view.Services {
		if service.Validate() != nil || index > 0 && view.Services[index-1].ID >= service.ID {
			return nil, nil, errors.New("view Services are invalid or not uniquely sorted")
		}
		services[service.ID] = service
	}
	byService := map[string]NetworkPolicy{}
	inboundPolicies := map[string]bool{}
	for _, credential := range view.InboundCredentials {
		inboundPolicies[credential.PolicyID] = true
	}
	for index, policy := range view.Policies {
		selected := containsString(view.PolicyIDs, policy.ID)
		if policy.Validate() != nil || index > 0 && view.Policies[index-1].ID >= policy.ID || !selected && !inboundPolicies[policy.ID] {
			return nil, nil, errors.New("view Policies are invalid, unassigned or not uniquely sorted")
		}
		if !selected {
			continue
		}
		if _, found := byService[policy.ServiceID]; found {
			return nil, nil, errors.New("device selected multiple Policies for one Service")
		}
		byService[policy.ServiceID] = policy
	}
	return services, byService, nil
}

func matcherRule(matcher ServiceMatcher) map[string]any {
	switch matcher.Kind {
	case "dns_exact":
		return map[string]any{"domain": []string{matcher.Value}}
	case "dns_suffix":
		return map[string]any{"domain_suffix": []string{matcher.Value}}
	case "ip_prefix":
		return map[string]any{"ip_cidr": []string{matcher.Value}}
	default:
		panic("validated Service matcher has an unknown kind")
	}
}

func serviceRule(service Service) map[string]any {
	rules := make([]any, 0, len(service.Matchers))
	for _, matcher := range service.Matchers {
		rules = append(rules, matcherRule(matcher))
	}
	return map[string]any{"type": "logical", "mode": "or", "rules": rules}
}

// ProjectAccessRuntime is the sole permission-to-runtime projection. Host capture,
// listeners and the local API secret are added later by the platform adapter.
// Only the outbound passwords are private inputs of the certified profile;
// identities, transport parameters and ACLs are always rebuilt from the View.
func ProjectAccessRuntime(view DeviceView) ([]RouteCandidate, *RuntimeProfile, error) {
	credentials, err := profileCredentials(view)
	if err != nil {
		return nil, nil, err
	}
	return projectAccessRuntime(view, credentials)
}

func projectAccessRuntime(view DeviceView, credentials map[string]string) ([]RouteCandidate, *RuntimeProfile, error) {
	services, policies, err := servicePermissionValues(view)
	if err != nil {
		return nil, nil, err
	}
	if !containsString(view.Responsibilities, "access") {
		if len(view.PolicyIDs) != 0 {
			return nil, nil, errors.New("non-access device has access policies")
		}
		return []RouteCandidate{}, nil, nil
	}
	if err := validateViewResources(view); err != nil {
		return nil, nil, err
	}
	ids := make([]string, 0, len(policies))
	for id := range policies {
		if _, found := services[id]; found {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	routes := []RouteCandidate{}
	outbounds := []any{map[string]any{"type": "block", "tag": "reject"}}
	rules := []any{}
	// A request that simultaneously identifies two Services is ambiguous. Keep
	// the rejection before every allow rule, including deny-assigned Services.
	for left := range ids {
		for right := left + 1; right < len(ids); right++ {
			rules = append(rules, map[string]any{"type": "logical", "mode": "and", "rules": []any{serviceRule(services[ids[left]]), serviceRule(services[ids[right]])}, "outbound": "reject"})
		}
	}
	for _, id := range ids {
		policy := policies[id]
		if policy.Action != "allow" {
			continue
		}
		exits := []string{}
		if policy.AllowDirect {
			exits = append(exits, "direct")
		}
		// The local hybrid is a logical exit even without a network hop. It
		// has no entry resource and must not inherit the ordinary Direct grant.
		if containsString(view.Responsibilities, "internet_egress") && containsString(policy.LocalEgressDevices, view.DeviceID) && policy.ExitScope.Allows(view.DeviceID) {
			exits = append(exits, view.DeviceID)
		}
		candidates := make([]RouteCandidate, 0, len(exits))
		for _, exit := range exits {
			candidate, err := localCandidate(services[id], policy, exit, view.DNSRecords...)
			if err != nil {
				return nil, nil, err
			}
			candidates = append(candidates, candidate)
		}
		paths, err := transportPaths(view.DeviceID, containsString(view.Responsibilities, "forward"), services[id], policy, view.Resources, view.Links, view.DNSRecords...)
		if err != nil {
			return nil, nil, err
		}
		byPath := map[string]transportPath{}
		for _, path := range paths {
			candidates = append(candidates, path.candidate)
			byPath[path.candidate.ID] = path
		}
		if len(candidates) == 0 {
			continue
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
		members := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			routes = append(routes, candidate)
			members = append(members, candidate.ID)
			if candidate.FirstResourceID == "" {
				outbounds = append(outbounds, map[string]any{"type": "direct", "tag": candidate.ID})
			} else {
				values, err := renderTransportPath(byPath[candidate.ID], view.Resources, credentials)
				if err != nil {
					return nil, nil, err
				}
				outbounds = append(outbounds, values...)
			}
		}
		scope := candidates[0].Scope
		outbounds = append(outbounds, map[string]any{"type": "selector", "tag": scope, "outbounds": members, "default": members[0]})
		rule := serviceRule(services[id])
		rule["outbound"] = scope
		rules = append(rules, rule)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].ID < routes[j].ID })
	body, err := CanonicalEncode(map[string]any{"outbounds": outbounds, "route": map[string]any{"rules": rules, "final": "reject"}})
	if err != nil {
		return nil, nil, err
	}
	return routes, &RuntimeProfile{Kind: "sing_box", Config: string(body)}, nil
}

func targetMatchesService(target string, service Service) bool {
	if ValidateHTTPSURL(target) != nil {
		return false
	}
	parsed, _ := url.Parse(target)
	for _, matcher := range service.Matchers {
		if matcher.Matches(parsed.Hostname()) {
			return true
		}
	}
	return false
}

func validateDeviceViewAuthorization(view DeviceView) error {
	services, policies, err := servicePermissionValues(view)
	if err != nil {
		return err
	}
	for index, endpoint := range view.Endpoints {
		if endpoint.Validate() != nil {
			return errors.New("view endpoint is invalid")
		}
		if index > 0 {
			previous := view.Endpoints[index-1]
			if previous.ID > endpoint.ID || previous.ID == endpoint.ID && previous.Generation >= endpoint.Generation {
				return errors.New("view endpoints are not uniquely sorted")
			}
		}
	}
	for index, group := range view.BusinessProbeTargets {
		service, exists := services[group.ServiceID]
		policy, assigned := policies[group.ServiceID]
		if !exists || !assigned || policy.Action != "allow" || group.Targets == nil || index > 0 && view.BusinessProbeTargets[index-1].ServiceID >= group.ServiceID {
			return errors.New("business probe group is unauthorized or not uniquely sorted")
		}
		for targetIndex, target := range group.Targets {
			if !targetMatchesService(target, service) || targetIndex > 0 && group.Targets[targetIndex-1] >= target {
				return errors.New("business probe target is unauthorized or not uniquely sorted")
			}
			for otherID, other := range services {
				if otherID != service.ID {
					if _, chosen := policies[otherID]; chosen && targetMatchesService(target, other) {
						return errors.New("business probe target belongs to multiple Services")
					}
				}
			}
		}
	}
	for index, component := range view.ExpectedComponents {
		if component.Validate() != nil {
			return errors.New("expected component is invalid")
		}
		if index > 0 {
			previous := view.ExpectedComponents[index-1]
			if previous.ComponentID > component.ComponentID || previous.ComponentID == component.ComponentID && previous.Platform >= component.Platform {
				return errors.New("expected components are not uniquely sorted")
			}
		}
	}
	if err := validateViewResources(view); err != nil {
		return err
	}
	routes, profile, err := ProjectAccessRuntime(view)
	if err != nil {
		return err
	}
	actualRoutes, err := CanonicalEncode(view.Routes)
	if err != nil {
		return err
	}
	wantedRoutes, err := CanonicalEncode(routes)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualRoutes, wantedRoutes) {
		return errors.New("view candidates do not match its Service permissions")
	}
	if (profile == nil) != (view.RuntimeProfile == nil) || profile != nil && *profile != *view.RuntimeProfile {
		return errors.New("view runtime does not match its Service permissions")
	}
	return nil
}

// ProjectDeviceView consumes authenticated facts and independently verified
// immutable release sets. It performs no I/O; the envelope signer attaches the
// actual member proof and verified fact frontier.
func ProjectDeviceView(projection Projection, deviceID string, releases ...ReleaseSet) (DeviceView, error) {
	var authorization DeviceAuthorization
	found := false
	for _, value := range projection.DeviceAuthorizations {
		if value.ID == deviceID {
			if found {
				return DeviceView{}, errors.New("device authorization is ambiguous")
			}
			authorization, found = value, true
		}
	}
	identity, identityFound := identityFor(projection, deviceID)
	if !identityFound || found && authorization.Validate() != nil {
		return DeviceView{}, errors.New("device identity or authorization is unavailable")
	}
	view := DeviceView{DNSRecords: projectDNSRecords(projection.NetworkIntent.DNSRecords), Schema: 3, DeviceID: identity.ID, Name: identity.Name, Platform: identity.Platform, DevicePublicKey: identity.DevicePublicKey,
		Responsibilities: append([]string{}, authorization.Responsibilities...), PolicyIDs: append([]string{}, authorization.PolicyIDs...),
		Services: []Service{}, Policies: []NetworkPolicy{}, Resources: []TransportResource{}, Links: []NetworkLink{}, Endpoints: []EndpointGeneration{},
		DNSServers: append([]string{}, authorization.DNSServers...), BusinessProbeTargets: []ServiceProbeTargets{}, Routes: []RouteCandidate{}, InboundCredentials: []InboundCredential{}, ExpectedComponents: []ComponentReadback{}}
	view.PublicTrust = append([]PublicTrust(nil), projection.NetworkIntent.PublicTrust...)
	var componentErr error
	view.ExpectedComponents, componentErr = deviceExpectedComponents(projection, deviceID, releases)
	if componentErr != nil {
		return DeviceView{}, componentErr
	}
	for _, member := range projection.Config.Members {
		if member.NodeID == deviceID {
			view.Responsibilities = append(view.Responsibilities, "control")
			break
		}
	}
	sort.Strings(view.Responsibilities)
	serviceIDs := map[string]bool{}
	for _, policy := range projection.NetworkIntent.Policies {
		if !containsString(view.PolicyIDs, policy.ID) {
			continue
		}
		for _, service := range projection.NetworkIntent.Services {
			if service.ID == policy.ServiceID {
				view.Policies = append(view.Policies, policy)
				serviceIDs[service.ID] = true
				break
			}
		}
	}
	for _, service := range projection.NetworkIntent.Services {
		if serviceIDs[service.ID] {
			view.Services = append(view.Services, service)
		}
	}
	sort.Slice(view.Policies, func(i, j int) bool { return view.Policies[i].ID < view.Policies[j].ID })
	sort.Slice(view.Services, func(i, j int) bool { return view.Services[i].ID < view.Services[j].ID })
	credentials, err := projectViewResources(projection, &view)
	if err != nil {
		return DeviceView{}, err
	}
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.State != "serving" && endpoint.State != "draining" || !containsString(endpoint.Modes, "device") {
			continue
		}
		if _, member := proofMember(projection.Config, endpoint.OwnerControlID); member {
			view.Endpoints = append(view.Endpoints, endpoint)
		}
	}
	sort.Slice(view.Endpoints, func(i, j int) bool {
		return view.Endpoints[i].ID < view.Endpoints[j].ID || view.Endpoints[i].ID == view.Endpoints[j].ID && view.Endpoints[i].Generation < view.Endpoints[j].Generation
	})
	// An unrepresentable concurrent website port conflict removes only the
	// reserved website projection. The management snapshot exposes the conflict.
	view.WebEndpoints, _ = WebsiteEndpoints(projection)
	for _, service := range view.Services {
		var policy NetworkPolicy
		for _, selected := range view.Policies {
			if selected.ServiceID == service.ID && containsString(view.PolicyIDs, selected.ID) {
				policy = selected
				break
			}
		}
		if policy.Action != "allow" {
			continue
		}
		group := ServiceProbeTargets{ServiceID: service.ID, Targets: []string{}}
		for _, target := range projection.NetworkIntent.BusinessProbeTargets {
			unique := true
			for _, otherPolicy := range view.Policies {
				if !containsString(view.PolicyIDs, otherPolicy.ID) || otherPolicy.ServiceID == service.ID {
					continue
				}
				for _, otherService := range view.Services {
					if otherService.ID == otherPolicy.ServiceID && targetMatchesService(target.URL, otherService) {
						unique = false
					}
				}
			}
			if unique && targetMatchesService(target.URL, service) {
				group.Targets = append(group.Targets, target.URL)
			}
		}
		sort.Strings(group.Targets)
		unique := group.Targets[:0]
		for _, target := range group.Targets {
			if len(unique) == 0 || unique[len(unique)-1] != target {
				unique = append(unique, target)
			}
		}
		group.Targets = unique
		view.BusinessProbeTargets = append(view.BusinessProbeTargets, group)
	}
	view.Routes, view.RuntimeProfile, err = projectAccessRuntime(view, credentials)
	if err != nil {
		return DeviceView{}, err
	}
	if err := view.Validate(); err != nil {
		return DeviceView{}, err
	}
	return view, nil
}

// ServicesOverlap proves overlaps available from the certified matcher values;
// it never resolves DNS to invent a relation between a name and an IP prefix.
func ServicesOverlap(left, right Service) bool {
	for _, a := range left.Matchers {
		for _, b := range right.Matchers {
			if a.Kind == "ip_prefix" && b.Kind == "ip_prefix" {
				pa, ea := netip.ParsePrefix(a.Value)
				pb, eb := netip.ParsePrefix(b.Value)
				if ea == nil && eb == nil && (pa.Contains(pb.Addr()) || pb.Contains(pa.Addr())) {
					return true
				}
			}
			if a.Kind == "dns_exact" && b.Matches(a.Value) || b.Kind == "dns_exact" && a.Matches(b.Value) || a.Kind == "dns_suffix" && b.Kind == "dns_suffix" && (a.Matches(b.Value) || b.Matches(a.Value)) {
				return true
			}
		}
	}
	return false
}
