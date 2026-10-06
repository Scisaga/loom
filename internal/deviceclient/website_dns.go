package deviceclient

import (
	"context"
	"errors"
	"loom/internal/control"
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// WebsiteAddresses resolves the web_endpoints from an already verified View.
// The result is local execution input; no Host, identity or fact is rewritten.
func WebsiteAddresses(ctx context.Context, endpoints []control.EndpointGeneration, dnsAddresses []string) ([]string, error) {
	addresses := map[string]bool{}
	for index, endpoint := range endpoints {
		if endpoint.Validate() != nil || endpoint.WebsiteTrustID == "" || endpoint.State != "serving" || index > 0 && endpoint.Port != endpoints[0].Port {
			return nil, errors.New("website resolution requires certified serving entries with one client port")
		}
		resolved, err := endpointDialAddresses(ctx, net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), dnsAddresses)
		if err != nil {
			return nil, err
		}
		for _, target := range resolved {
			host, _, err := net.SplitHostPort(target)
			ip, parseErr := netip.ParseAddr(host)
			if err != nil || parseErr != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
				return nil, errors.New("website resolution did not return unicast underlay addresses")
			}
			addresses[ip.Unmap().String()] = true
		}
	}
	var result []string
	for address := range addresses {
		result = append(result, address)
	}
	sort.Strings(result)
	return result, nil
}
