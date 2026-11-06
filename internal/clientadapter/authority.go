package clientadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/netx"
)

// AccessProjection is a one-way execution input. It never decodes authority,
// signs facts, persists a second view, or supplies fields missing from a view.
func AccessProjection(view control.DeviceView, selected []string) ([]clientmodel.RouteCandidate, clientmodel.RuntimeProfile, error) {
	if !slices.Contains(view.Responsibilities, "access") {
		return nil, clientmodel.RuntimeProfile{}, errors.New("view has no access runtime")
	}
	execution, err := control.ProjectDeviceExecution(view, selected)
	if err != nil {
		return nil, clientmodel.RuntimeProfile{}, err
	}
	routes, err := accessCandidates(execution)
	profile := clientmodel.RuntimeProfile{Kind: execution.RuntimeProfile.Kind, Config: execution.RuntimeProfile.Config}
	if err == nil {
		err = profile.Validate(routes)
	}
	return routes, profile, err
}

// AccessCandidates avoids serializing native configuration on each measurement
// or recommendation tick. It derives only the currently selected Policies.
func AccessCandidates(view control.DeviceView, selected []string) ([]clientmodel.RouteCandidate, error) {
	execution, err := control.ProjectDeviceCandidates(view, selected)
	if err != nil {
		return nil, err
	}
	return accessCandidates(execution)
}

// AccessRoutingInputs shares one current candidate projection and one set of
// link references between access selection and graph estimation.
func AccessRoutingInputs(view control.DeviceView, selected []string) ([]clientmodel.RouteCandidate, []clientmodel.PolicyGraph, error) {
	execution, err := control.ProjectDeviceCandidates(view, selected)
	if err != nil {
		return nil, nil, err
	}
	return AccessRoutingInputsFromExecution(execution, selected)
}

// AccessRoutingInputsFromExecution reuses the current round's authenticated
// candidate projection instead of projecting the same View a second time.
func AccessRoutingInputsFromExecution(execution control.DeviceExecution, selected []string) ([]clientmodel.RouteCandidate, []clientmodel.PolicyGraph, error) {
	view := execution.DeviceView
	graphs, err := selectedPolicyGraphs(view, selected)
	if err != nil {
		return nil, nil, err
	}
	if len(graphs) == 0 {
		return []clientmodel.RouteCandidate{}, graphs, nil
	}
	refs, err := graphLinkReferences(view, execution.Links)
	if err != nil {
		return nil, nil, err
	}
	routes, err := accessCandidatesWithLinks(execution, refs)
	for i := range graphs {
		graphs[i].Links = refs
	}
	return routes, graphs, err
}

func accessCandidates(execution control.DeviceExecution) ([]clientmodel.RouteCandidate, error) {
	if len(execution.Routes) == 0 {
		return []clientmodel.RouteCandidate{}, nil
	}
	refs, err := graphLinkReferences(execution.DeviceView, execution.Links)
	if err != nil {
		return nil, err
	}
	return accessCandidatesWithLinks(execution, refs)
}

func accessCandidatesWithLinks(execution control.DeviceExecution, refs []clientmodel.GraphLink) ([]clientmodel.RouteCandidate, error) {
	view := execution.DeviceView
	probes, err := control.CandidateFirstHopProbes(execution)
	if err != nil {
		return nil, err
	}
	linkRefs := make(map[string]clientmodel.LinkSampleRef, len(refs))
	for _, link := range refs {
		linkRefs[link.Ref.LinkID] = link.Ref
	}
	routes := make([]clientmodel.RouteCandidate, 0, len(execution.Routes))
	fixed := map[string]bool{}
	for _, policy := range view.Policies {
		fixed[policy.ID] = policy.ExitScope == nil || policy.AllowDirect != nil && !*policy.AllowDirect && policy.ExitScope.Mode == "only" && len(policy.ExitScope.NodeIDs) == 1
	}
	resources := map[string]control.TransportResource{}
	for _, value := range view.Resources {
		resources[value.ID] = value
	}
	for _, route := range execution.Routes {
		chain, linkIDs, estimateErr := control.CandidateTopologyEstimate(execution, route)
		if estimateErr != nil {
			return nil, estimateErr
		}
		candidate := clientmodel.RouteCandidate{ID: route.ID, PolicyID: route.PolicyID, FixedExit: fixed[route.PolicyID], SourceNode: view.DeviceID, EntryNodeID: route.EntryNodeID, FirstResourceID: route.FirstResourceID, FinalExit: route.FinalExit, Chain: chain, Scope: route.Scope}
		candidate.Transport = resources[route.FirstResourceID].Kind
		if route.FirstResourceID == "" {
			candidate.Transport = "direct"
			if route.FinalExit != "direct" && route.FinalExit != view.DeviceID {
				candidate.Transport = "forward"
			}
		}
		for _, id := range linkIDs {
			candidate.RelayLinks = append(candidate.RelayLinks, linkRefs[id])
		}
		if probe, found := probes[route.ID]; found {
			candidate.FirstHop = &clientmodel.ResourceSampleRef{ResourceID: probe.Resource.ID, SpecDigest: probe.SpecDigest, Target: probe.Target(), Action: probe.Action()}
		}
		routes = append(routes, candidate)
	}
	return routes, nil
}

// ManagedRuntimeConfig adds only local execution inputs. Platform capture
// adapters must complete this value before passing it to a process. It remains
// disposable and must never replace the signed RuntimeProfile.
func ManagedRuntimeConfig(view control.DeviceView, secret string, websites ...WebsiteAccess) (string, error) {
	_, config, err := AccessRuntimeProjection(view, nil, secret, websites...)
	return config, err
}

// AccessRuntimeProjection validates the certified View once for both selection
// and host execution. Its private helpers never accept unvalidated inputs.
func AccessRuntimeProjection(view control.DeviceView, selected []string, secret string, websites ...WebsiteAccess) ([]clientmodel.RouteCandidate, string, error) {
	routes, _, err := AccessProjection(view, selected)
	if err != nil {
		return nil, "", err
	}
	config, err := managedRuntimeConfig(view, secret, websites...)
	return routes, config, err
}

func managedRuntimeConfig(view control.DeviceView, secret string, websites ...WebsiteAccess) (string, error) {
	if len(websites) > 1 {
		return "", errors.New("runtime has more than one website execution input")
	}
	var website WebsiteAccess
	if len(websites) == 1 {
		website = websites[0]
		if _, err := websiteAccessFor(view, website.Addresses); err != nil || len(view.WebEndpoints) > 0 && website.Port != view.WebEndpoints[0].Port {
			return "", errors.New("website execution differs from the certified entry projection")
		}
	}
	config, err := runtimeSource(view, secret, true)
	if err != nil {
		return "", err
	}
	config, err = WithManagedDNS(config, view.DNSServers, true)
	if err != nil {
		return "", err
	}
	config, err = WithOverlayDNS(config, view.DNSRecords, true, website.Addresses...)
	if err != nil {
		return "", err
	}
	return WithWebsiteRoute(config, website)
}

// AccessRuntimeSource retains the complete certified authorization and adds
// only the local API. Capture adapters add DNS once for their own inbounds.
func AccessRuntimeSource(view control.DeviceView, secret string) (string, error) {
	if _, _, err := AccessProjection(view, nil); err != nil {
		return "", err
	}
	return runtimeSource(view, secret, true)
}

// RuntimeSource adds only local listeners and diagnostics to the one certified
// profile. A profile's presence is never interpreted as the access role.
func RuntimeSource(view control.DeviceView, secret string, access bool) (string, error) {
	if err := view.Validate(); err != nil {
		return "", err
	}
	return runtimeSource(view, secret, access)
}

func runtimeSource(view control.DeviceView, secret string, access bool) (string, error) {
	execution, err := control.ProjectDeviceExecution(view, nil)
	if err != nil {
		return "", err
	}
	if execution.RuntimeProfile == nil || secret == "" || access && !slices.Contains(view.Responsibilities, "access") {
		return "", errors.New("runtime profile, role or local API secret is missing")
	}
	if err := ValidateOverlayUnderlay(view); err != nil {
		return "", err
	}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID {
			if view.Platform != "linux" {
				return "", errors.New("this platform has no server resource executor")
			}
		}
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(execution.RuntimeProfile.Config), &document); err != nil {
		return "", err
	}
	if document["outbounds"] == nil || document["route"] == nil {
		return "", errors.New("unsupported authorization runtime facilities")
	}
	for field := range document {
		if field != "outbounds" && field != "route" && field != "endpoints" && field != "dns" {
			return "", errors.New("unsupported authorization runtime facilities")
		}
	}
	if document["dns"] == nil {
		document["dns"] = json.RawMessage(`{"servers":[{"tag":"loom-runtime-deny-dns","address":"rcode://refused"}],"rules":[],"final":"loom-runtime-deny-dns"}`)
	}
	document["inbounds"] = json.RawMessage(`[]`)
	if access {
		document["inbounds"] = json.RawMessage(`[{"type":"tun","tag":"tun-in","auto_route":true}]`)
	}
	document["experimental"], _ = json.Marshal(map[string]any{"clash_api": map[string]any{"external_controller": "127.0.0.1:61800", "secret": secret}})
	body, err := json.Marshal(document)
	return string(body), err
}

// A transport must be reachable before the overlay exists. This is an
// execution precondition; it does not reinterpret already signed resources.
func ValidateOverlayUnderlay(view control.DeviceView) error {
	for _, resource := range view.Resources {
		if strings.HasSuffix(resource.DialHost, ".loom") || resource.DialHost == "loom" {
			return errors.New("transport dial host cannot depend on overlay DNS")
		}
	}
	return nil
}

// WithManagedDNS projects the authenticated per-device resolver addresses into
// a disposable runtime. It cannot change the certified business selectors.
func WithManagedDNS(config string, addresses []string, access bool) (string, error) {
	if err := netx.ValidateDNSResolvers(addresses); err != nil {
		return "", err
	}
	if len(addresses) == 0 {
		var document map[string]json.RawMessage
		if err := json.Unmarshal([]byte(config), &document); err != nil {
			return "", err
		}
		if document["dns"] == nil {
			document["dns"] = json.RawMessage(`{"servers":[{"tag":"loom-runtime-deny-dns","address":"rcode://refused"}],"rules":[],"final":"loom-runtime-deny-dns"}`)
		}
		if access {
			var route map[string]json.RawMessage
			if err := json.Unmarshal(document["route"], &route); err != nil {
				return "", err
			}
			var rules []json.RawMessage
			if err := json.Unmarshal(route["rules"], &rules); err != nil {
				return "", err
			}
			hijack := json.RawMessage(`{"inbound":["tun-in"],"port":[53],"action":"hijack-dns"}`)
			found := false
			for _, rule := range rules {
				found = found || string(rule) == string(hijack)
			}
			if !found {
				rules = append([]json.RawMessage{hijack}, rules...)
			}
			route["rules"], _ = json.Marshal(rules)
			document["route"], _ = json.Marshal(route)
		}
		body, err := json.Marshal(document)
		return string(body), err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	{
		var outbounds []map[string]any
		if err := json.Unmarshal(document["outbounds"], &outbounds); err != nil {
			return "", err
		}
		found := false
		for _, outbound := range outbounds {
			if outbound["tag"] == "loom-underlay-dns" {
				if found || outbound["type"] != "direct" || len(outbound) != 2 {
					return "", errors.New("conflicting managed DNS outbound")
				}
				found = true
			}
		}
		if !found {
			outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "loom-underlay-dns"})
		}
		document["outbounds"], _ = json.Marshal(outbounds)
		dns := map[string]any{}
		if raw := document["dns"]; raw != nil {
			if err := json.Unmarshal(raw, &dns); err != nil {
				return "", err
			}
		}
		servers, _ := dns["servers"].([]any)
		for i, address := range addresses {
			tag := fmt.Sprintf("loom-resolver-%d", i)
			resolver, _ := netx.ParseDNSResolver(address)
			server := map[string]any{"tag": tag, "address": resolver.RuntimeAddress(), "detour": "loom-underlay-dns"}
			seen := false
			for _, raw := range servers {
				value, ok := raw.(map[string]any)
				if !ok {
					return "", errors.New("invalid DNS server")
				}
				if value["tag"] == tag {
					a, _ := json.Marshal(value)
					b, _ := json.Marshal(server)
					if seen || string(a) != string(b) {
						return "", errors.New("managed DNS conflicts with certified resolver")
					}
					seen = true
				}
			}
			if !seen {
				servers = append(servers, server)
			}
		}
		dns["servers"], dns["final"], dns["strategy"], dns["independent_cache"] = servers, "loom-resolver-0", "prefer_ipv4", true
		if len(addresses) > 1 && strings.HasPrefix(addresses[0], "https://") {
			physical := []string{}
			for _, outbound := range outbounds {
				if outbound["type"] == "direct" && outbound["detour"] == nil {
					tag, _ := outbound["tag"].(string)
					physical = append(physical, tag)
				}
			}
			rules, _ := dns["rules"].([]any)
			for _, rule := range control.ManagedResolverRules(addresses, physical) {
				encoded, _ := json.Marshal(rule)
				found := false
				for _, existing := range rules {
					body, _ := json.Marshal(existing)
					found = found || string(encoded) == string(body)
				}
				if !found {
					rules = append(rules, rule)
				}
			}
			dns["rules"] = rules
		}
		document["dns"], _ = json.Marshal(dns)
		var route map[string]json.RawMessage
		if err := json.Unmarshal(document["route"], &route); err != nil {
			return "", err
		}
		var rules []json.RawMessage
		if err := json.Unmarshal(route["rules"], &rules); err != nil {
			return "", err
		}
		if access {
			rules = append([]json.RawMessage{json.RawMessage(`{"inbound":["tun-in"],"port":[53],"action":"hijack-dns"}`)}, rules...)
		}
		route["rules"], _ = json.Marshal(rules)
		document["route"], _ = json.Marshal(route)
	}
	body, err := json.Marshal(document)
	return string(body), err
}

// PolicyGraphs derives only the caller's current calculation scopes. Policies
// share the same link reference slice; none is an authorization wire value.
func PolicyGraphs(view control.DeviceView, selected []string) ([]clientmodel.PolicyGraph, error) {
	graphs, err := selectedPolicyGraphs(view, selected)
	if err != nil || len(graphs) == 0 {
		return graphs, err
	}
	links, err := control.DerivedViewLinks(view)
	if err != nil {
		return nil, err
	}
	refs, err := graphLinkReferences(view, links)
	if err != nil {
		return nil, err
	}
	for index := range graphs {
		graphs[index].Links = refs
	}
	return graphs, nil
}

func selectedPolicyGraphs(view control.DeviceView, selected []string) ([]clientmodel.PolicyGraph, error) {
	graphs := []clientmodel.PolicyGraph{}
	if len(selected) == 0 {
		return graphs, nil
	}
	wanted := make(map[string]bool, len(selected))
	for _, id := range selected {
		if control.ValidateID(id) != nil || wanted[id] {
			return nil, errors.New("invalid or duplicated graph Policy selection")
		}
		wanted[id] = true
	}
	for _, policy := range view.Policies {
		if wanted[policy.ID] && policy.Action == "allow" {
			graphs = append(graphs, clientmodel.PolicyGraph{PolicyID: policy.ID, SourceNode: view.DeviceID, RelayScope: policy.RelayScope, MaxHops: policy.MaxHops})
		}
	}
	if len(graphs) != len(wanted) {
		return nil, errors.New("graph Policy selection is absent or denied")
	}
	return graphs, nil
}

func graphLinkReferences(view control.DeviceView, links []control.NetworkLink) ([]clientmodel.GraphLink, error) {
	specs, err := control.LinkSpecifications(view)
	if err != nil {
		return nil, err
	}
	refs := make([]clientmodel.GraphLink, 0, len(links))
	for _, link := range links {
		spec := specs[link.ID]
		refs = append(refs, clientmodel.GraphLink{From: link.FromNodeID, To: link.ToNodeID, Ref: clientmodel.LinkSampleRef{LinkID: link.ID, DeviceID: link.FromNodeID, ResourceID: link.ResourceID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, fmt.Sprint(link.ProbeTarget.Port)), Action: link.ProbeTarget.Action}})
	}
	return refs, nil
}
