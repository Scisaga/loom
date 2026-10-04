package clientadapter

import (
	"encoding/json"
	"errors"
	"net/netip"

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
	if _, _, err := AccessProjection(view); err != nil {
		return "", err
	}
	if secret == "" {
		return "", errors.New("local runtime API secret is required")
	}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID {
			if view.Platform != "linux" {
				return "", errors.New("this platform has no server resource executor")
			}
		} else if _, err := netip.ParseAddr(resource.DialHost); err != nil {
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
	return string(body), err
}
