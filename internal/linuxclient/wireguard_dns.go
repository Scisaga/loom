package linuxclient

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/netx"
)

// DNS answers are temporary execution addresses. The signed resource and peer
// key remain unchanged; the kernel must never perform implicit host resolution.
func resolveWireGuardEndpoints(ctx context.Context, desired, current wireGuardExecution, servers []string, dial func(context.Context, string, string) (net.Conn, error)) (wireGuardExecution, error) {
	result := wireGuardExecution{WireGuard: append([]wireGuardExecutionLink{}, desired.WireGuard...)}
	resolved := map[string][]netip.Addr{}
	for index, link := range result.WireGuard {
		if link.Mode != "initiator" {
			continue
		}
		host, port, err := net.SplitHostPort(link.Endpoint)
		if err != nil {
			return wireGuardExecution{}, errors.New("WireGuard endpoint is invalid")
		}
		addresses, found := resolved[host]
		if !found {
			addresses, err = netx.ResolveCertifiedIPs(ctx, host, servers, dial)
			if err != nil {
				return wireGuardExecution{}, err
			}
			resolved[host] = addresses
		}
		chosen := addresses[0]
		for _, prior := range current.WireGuard {
			if prior.LinkID != link.LinkID || prior.PeerPublicKey != link.PeerPublicKey {
				continue
			}
			previousHost, previousPort, err := net.SplitHostPort(prior.Endpoint)
			previous, parseErr := netip.ParseAddr(previousHost)
			if err == nil && parseErr == nil && previousPort == port && slices.Contains(addresses, previous) {
				chosen = previous
			}
		}
		result.WireGuard[index].Endpoint = net.JoinHostPort(chosen.String(), port)
	}
	return result, nil
}

func invalidateWireGuardObservations(state LocalState, view control.DeviceView, previous, next wireGuardExecution) LocalState {
	changed := map[string]bool{}
	for _, link := range next.WireGuard {
		for _, prior := range previous.WireGuard {
			if link.LinkID == prior.LinkID && link.Endpoint != prior.Endpoint {
				changed[link.LinkID] = true
			}
		}
	}
	affectedLinks := map[string]bool{}
	for _, link := range view.Links {
		if changed[link.ResourceID] || changed[link.FromResourceID] {
			affectedLinks[link.ID] = true
		}
	}
	affectedCandidates := map[string]bool{}
	for _, candidate := range view.Routes {
		for _, link := range candidate.LinkIDs {
			if affectedLinks[link] {
				affectedCandidates[candidate.ID] = true
			}
		}
	}
	state.Observations = slices.DeleteFunc(append([]clientmodel.Observation{}, state.Observations...), func(value clientmodel.Observation) bool {
		return affectedCandidates[value.CandidateID]
	})
	return state
}
