package linuxclient

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/netx"
)

// Peer coordinates and keepalive belong to the native transport, not ownership
// of a host interface, exact address or management return route.
func sameWireGuardHostInputs(before, after wireGuardExecution) bool {
	project := func(value wireGuardExecution) []wireGuardExecutionLink {
		links := append([]wireGuardExecutionLink{}, value.WireGuard...)
		for index := range links {
			links[index].Endpoint = ""
			links[index].PersistentKeepalive = 0
			links[index].ListenPort = 0
		}
		return links
	}
	return reflect.DeepEqual(project(before), project(after))
}

// DNS answers are temporary execution addresses. The signed resource and peer
// key remain unchanged; the kernel must never perform implicit host resolution.
func resolveWireGuardEndpoints(ctx context.Context, desired, current wireGuardExecution, servers []string, dial func(context.Context, string, string) (net.Conn, error)) (wireGuardExecution, error) {
	result := wireGuardExecution{WireGuard: append([]wireGuardExecutionLink{}, desired.WireGuard...), ListenPort: desired.ListenPort}
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
	execution, err := control.ProjectDeviceCandidates(view, clientmodel.MeasurementPolicies(state.Preference))
	if err != nil {
		state.Observations = nil
		return state
	}
	changed := map[string]bool{}
	for _, link := range next.WireGuard {
		for _, prior := range previous.WireGuard {
			if link.LinkID == prior.LinkID && link.PeerPublicKey == prior.PeerPublicKey && link.Endpoint != prior.Endpoint {
				changed[link.LinkID] = true
			}
		}
	}
	affectedLinks := map[string]bool{}
	for _, link := range execution.Links {
		if changed[link.ResourceID] || changed[link.FromResourceID] {
			affectedLinks[link.ID] = true
		}
	}
	affectedCandidates := map[string]bool{}
	for _, candidate := range execution.Routes {
		if changed[candidate.FirstResourceID] {
			affectedCandidates[candidate.ID] = true
		}
		_, linkIDs, err := control.CandidateTopologyEstimate(execution, candidate)
		if err != nil {
			continue
		}
		for _, link := range linkIDs {
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
