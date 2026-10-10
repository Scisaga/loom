package linuxclient

import (
	"context"
	"loom/internal/clientadapter"
	"loom/internal/control"
	"net"
	"sort"
	"strconv"
	"time"
)

// Samples use the running native session and are never Service health.
func observeLinks(ctx context.Context, view control.DeviceView, _ wireGuardExecution, generation string, interval time.Duration, now func() time.Time) ([]control.Observation, error) {
	resources := map[string]control.TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	result := []control.Observation{}
	for _, link := range view.Links {
		if link.FromNodeID != view.DeviceID {
			continue
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		digest, err := control.LinkSpecDigest(view, link.ID)
		if err != nil {
			return nil, err
		}
		at := now()
		pending, cancel := context.WithTimeout(ctx, 3*time.Second)
		started := time.Now()
		roundTrip, probeErr := clientadapter.ProbeWireGuard(pending, view.NetworkID, resources[link.ResourceID])
		duration := time.Since(started).Milliseconds()
		cancel()
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		state := "available"
		if probeErr != nil {
			state = "unavailable"
		}
		value := control.Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID, Target: net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)), Action: link.ProbeTarget.Action, SpecDigest: digest, NetworkGeneration: generation, Result: state, ObservedAt: at.UnixMilli(), ValidUntil: at.Add(interval).UnixMilli(), DurationMS: &duration}
		if probeErr == nil {
			value.RoundTripMS = new(roundTrip.Milliseconds())
		}
		if err := value.Validate(); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ResourceID < result[j].ResourceID || result[i].ResourceID == result[j].ResourceID && result[i].LinkID < result[j].LinkID
	})
	return result, nil
}
