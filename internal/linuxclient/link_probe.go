package linuxclient

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

// Samples use the running native session and are never Service health.
func observeLinks(ctx context.Context, view control.DeviceView, _ wireGuardExecution, generation string, interval time.Duration, now func() time.Time) ([]control.Observation, error) {
	return observeLinksWithProbe(ctx, view, generation, interval, now, clientadapter.ProbeWireGuard)
}

func observeLinksWithProbe(ctx context.Context, view control.DeviceView, generation string, interval time.Duration, now func() time.Time,
	probe func(context.Context, string, control.TransportResource) (time.Duration, error)) ([]control.Observation, error) {
	resources := map[string]control.TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	links := []control.NetworkLink{}
	digests := map[string]string{}
	for _, link := range view.Links {
		if link.FromNodeID != view.DeviceID {
			continue
		}
		digest, err := control.LinkSpecDigest(view, link.ID)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
		digests[link.ID] = digest
	}
	jobs := make(chan control.NetworkLink, len(links))
	values := make(chan control.Observation, len(links))
	for _, link := range links {
		jobs <- link
	}
	close(jobs)
	var workers sync.WaitGroup
	for i := 0; i < min(4, len(links)); i++ {
		workers.Go(func() {
			for link := range jobs {
				if ctx.Err() != nil {
					return
				}
				pending, cancel := context.WithTimeout(ctx, 3*time.Second)
				started := time.Now()
				roundTrip, probeErr := probe(pending, view.NetworkID, resources[link.ResourceID])
				duration := time.Since(started).Milliseconds()
				cancel()
				if ctx.Err() != nil {
					return
				}
				value := control.Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID,
					Target: net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)),
					Action: link.ProbeTarget.Action, SpecDigest: digests[link.ID], NetworkGeneration: generation,
					Result: "unavailable", DurationMS: &duration}
				if probeErr == nil {
					value.Result = "available"
					value.RoundTripMS = new(roundTrip.Milliseconds())
				}
				values <- value
			}
		})
	}
	go func() {
		workers.Wait()
		close(values)
	}()
	result := []control.Observation{}
	var invalid error
	for value := range values {
		at := now()
		value.ObservedAt, value.ValidUntil = at.UnixMilli(), at.Add(interval).UnixMilli()
		if err := value.Validate(); err != nil {
			invalid = err
			continue
		}
		result = append(result, value)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if invalid != nil {
		return nil, invalid
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ResourceID < result[j].ResourceID || result[i].ResourceID == result[j].ResourceID && result[i].LinkID < result[j].LinkID
	})
	return result, nil
}
