package clientadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

// AccessProjection is a one-way execution input. It never decodes authority,
// signs facts, persists a second view, or supplies fields missing from a view.
func AccessProjection(view control.DeviceView) ([]clientmodel.RouteCandidate, clientmodel.RuntimeProfile, error) {
	if err := view.Validate(); err != nil {
		return nil, clientmodel.RuntimeProfile{}, err
	}
	if view.RuntimeProfile == nil || !slices.Contains(view.Responsibilities, "access") {
		return nil, clientmodel.RuntimeProfile{}, errors.New("view has no access runtime")
	}
	routes := make([]clientmodel.RouteCandidate, 0, len(view.Routes))
	for _, route := range view.Routes {
		routes = append(routes, clientmodel.RouteCandidate{ID: route.ID, FinalExit: route.FinalExit, Chain: append([]string{}, route.NodeChain...), Scope: route.Scope})
	}
	profile := clientmodel.RuntimeProfile{Kind: view.RuntimeProfile.Kind, Config: view.RuntimeProfile.Config}
	return routes, profile, profile.Validate(routes)
}

// ManagedRuntimeConfig adds only local execution inputs. Platform capture
// adapters must complete this value before passing it to a process. It remains
// disposable and must never replace the signed RuntimeProfile.
func ManagedRuntimeConfig(view control.DeviceView, secret string, websites ...WebsiteAccess) (string, error) {
	if len(websites) > 1 {
		return "", errors.New("runtime has more than one website execution input")
	}
	var website WebsiteAccess
	if len(websites) == 1 {
		website = websites[0]
		if _, err := WebsiteAccessFor(view, website.Addresses); err != nil || len(view.WebEndpoints) > 0 && website.Port != view.WebEndpoints[0].Port {
			return "", errors.New("website execution differs from the certified entry projection")
		}
	}
	config, err := AccessRuntimeSource(view, secret)
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
	if _, _, err := AccessProjection(view); err != nil {
		return "", err
	}
	return RuntimeSource(view, secret, true)
}

// RuntimeSource adds only local listeners and diagnostics to the one certified
// profile. A profile's presence is never interpreted as the access role.
func RuntimeSource(view control.DeviceView, secret string, access bool) (string, error) {
	if err := view.Validate(); err != nil {
		return "", err
	}
	if view.RuntimeProfile == nil || secret == "" || access && !slices.Contains(view.Responsibilities, "access") {
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
		} else if _, err := netip.ParseAddr(resource.DialHost); err != nil && len(view.DNSServers) == 0 {
			return "", errors.New("resource hostname execution requires an authenticated resolver configuration")
		}
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(view.RuntimeProfile.Config), &document); err != nil {
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
	if len(addresses) == 0 {
		return config, nil
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
			server := map[string]any{"tag": tag, "address": "udp://" + net.JoinHostPort(address, "53"), "detour": "loom-underlay-dns"}
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
