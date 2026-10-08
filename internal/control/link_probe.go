package control

import (
	"errors"
	"net"
	"sort"
	"strconv"
)

// LinkSpecDigest binds the two native resources and the Link, independently of
// Service business observations. No secondary proxy resource participates.
func LinkSpecDigest(view DeviceView, linkID string) (string, error) {
	resources := map[string]TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	for _, link := range view.Links {
		if link.ID != linkID {
			continue
		}
		from, to, _, err := linkResources(link, resources)
		if err != nil {
			return "", err
		}
		values := []TransportResource{from, to}
		sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
		return digestContractValue("loom-link-spec-v3\x00", map[string]any{"link": link, "resources": values})
	}
	return "", errors.New("Link observation has no current Link")
}

func verifyLinkObservation(value Observation, view DeviceView) error {
	for _, link := range view.Links {
		if link.ID != value.LinkID || link.FromNodeID != view.DeviceID {
			continue
		}
		digest, err := LinkSpecDigest(view, link.ID)
		if err == nil && value.ResourceID == link.ResourceID && value.SpecDigest == digest && value.Target == net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)) && value.Action == "wireguard_dns" {
			return nil
		}
	}
	return errors.New("Link observation is outside the source's current native probe specification")
}
