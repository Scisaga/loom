package clientadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	if view.RuntimeProfile == nil {
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
func ManagedRuntimeConfig(view control.DeviceView, secret string) (string, error) {
	config, err := AccessRuntimeSource(view, secret)
	if err != nil {
		return "", err
	}
	config, err = WithManagedDNS(config, view.DNSServers, true)
	if err != nil {
		return "", err
	}
	return WithOverlayDNS(config, view.DNSRecords, true)
}

// AccessRuntimeSource retains the complete certified authorization and adds
// only the local API. Capture adapters add DNS once for their own inbounds.
func AccessRuntimeSource(view control.DeviceView, secret string) (string, error) {
	if _, _, err := AccessProjection(view); err != nil {
		return "", err
	}
	if secret == "" {
		return "", errors.New("local runtime API secret is required")
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
	if len(document) != 2 || document["outbounds"] == nil || document["route"] == nil {
		return "", errors.New("unsupported authorization runtime facilities")
	}
	document["inbounds"] = json.RawMessage(`[{"type":"tun","tag":"tun-in","auto_route":true}]`)
	document["experimental"], _ = json.Marshal(map[string]any{"clash_api": map[string]any{"external_controller": "127.0.0.1:61800", "secret": secret}})
	body, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	return string(body), nil
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
		var outbounds []json.RawMessage
		if err := json.Unmarshal(document["outbounds"], &outbounds); err != nil {
			return "", err
		}
		outbounds = append(outbounds, json.RawMessage(`{"type":"direct","tag":"loom-underlay-dns"}`))
		document["outbounds"], _ = json.Marshal(outbounds)
		servers := make([]map[string]any, 0, len(addresses))
		for i, address := range addresses {
			servers = append(servers, map[string]any{"tag": fmt.Sprintf("loom-resolver-%d", i), "address": "udp://" + net.JoinHostPort(address, "53"), "detour": "loom-underlay-dns"})
		}
		document["dns"], _ = json.Marshal(map[string]any{"servers": servers, "final": "loom-resolver-0", "strategy": "prefer_ipv4", "independent_cache": true})
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
