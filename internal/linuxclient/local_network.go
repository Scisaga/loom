package linuxclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"

	"loom/internal/control"
)

// Read only the underlay namespace in which the client supervisor runs. The
// isolated capture process never supplies interfaces to this observation.
func collectLocalNetworks(ctx context.Context, view control.DeviceView) (*[]control.LocalNetworkPrefix, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := exec.CommandContext(ctx, "/usr/sbin/ip", "-j", "-d", "address", "show").Output()
	if err != nil {
		return nil, errors.New("local interface readback failed")
	}
	routes, err := exec.CommandContext(ctx, "/usr/sbin/ip", "-j", "-4", "route", "show", "table", "main").Output()
	if err != nil {
		return nil, errors.New("connected route readback failed")
	}
	values, err := localNetworksFromReadback(addresses, routes, view.Resources)
	if err != nil {
		return nil, err
	}
	return &values, nil
}

func localNetworksFromReadback(addressBody, routeBody []byte, resources []control.TransportResource) ([]control.LocalNetworkPrefix, error) {
	var interfaces []struct {
		Name     string   `json:"ifname"`
		Flags    []string `json:"flags"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
		Addresses []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Bits   int    `json:"prefixlen"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	var routes []struct {
		Device      string `json:"dev"`
		Destination string `json:"dst"`
		Scope       string `json:"scope"`
		Protocol    string `json:"protocol"`
		Type        string `json:"type"`
	}
	if len(addressBody) > 8<<20 || len(routeBody) > 8<<20 || json.Unmarshal(addressBody, &interfaces) != nil || interfaces == nil || json.Unmarshal(routeBody, &routes) != nil || routes == nil {
		return nil, errors.New("local network readback is incomplete")
	}
	overlay := map[netip.Addr]bool{}
	for _, resource := range resources {
		if resource.Authentication.LocalAddresses != nil {
			for _, value := range *resource.Authentication.LocalAddresses {
				prefix, err := netip.ParsePrefix(value)
				if err == nil {
					overlay[prefix.Addr()] = true
				}
			}
		}
	}
	connected := map[string]map[string]bool{}
	for _, route := range routes {
		if route.Scope != "link" || route.Protocol != "kernel" || route.Type != "" && route.Type != "unicast" {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 8 || prefix != prefix.Masked() {
			continue
		}
		if connected[route.Device] == nil {
			connected[route.Device] = map[string]bool{}
		}
		connected[route.Device][prefix.String()] = true
	}
	found := map[string]bool{}
	for _, iface := range interfaces {
		if !slices.Contains(iface.Flags, "UP") || slices.Contains(iface.Flags, "LOOPBACK") {
			continue
		}
		for _, value := range iface.Addresses {
			address, err := netip.ParseAddr(value.Local)
			if value.Family != "inet" || value.Scope != "global" || err != nil || !address.Is4() || !address.IsGlobalUnicast() || overlay[address] || value.Bits < 8 || value.Bits > 32 {
				continue
			}
			prefix := netip.PrefixFrom(address, value.Bits).Masked().String()
			lan := connected[iface.Name][prefix] && !slices.Contains(iface.Flags, "POINTOPOINT") && iface.LinkInfo.Kind != "wireguard" && iface.LinkInfo.Kind != "tun" && iface.LinkInfo.Kind != "tuntap"
			if previous, exists := found[prefix]; exists {
				lan = lan && previous
			}
			found[prefix] = lan
		}
	}
	values := make([]control.LocalNetworkPrefix, 0, len(found))
	for prefix, lan := range found {
		values = append(values, control.LocalNetworkPrefix{Prefix: prefix, LAN: lan})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Prefix < values[j].Prefix })
	return values, nil
}

func runtimeHasLocalNetwork(view control.DeviceView) bool {
	for _, service := range view.Services {
		if service.LocalNetwork != nil {
			return true
		}
	}
	return view.RuntimeProfile != nil && strings.Contains(view.RuntimeProfile.Config, `"prefix_mapping"`)
}
