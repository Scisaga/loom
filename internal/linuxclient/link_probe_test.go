package linuxclient

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

func independentLinkView(t *testing.T) control.DeviceView {
	t.Helper()
	p, _, _, _ := nativeProjectionFixture(t)
	view := control.DeviceView{DeviceID: "demo-entry", NetworkID: p.NetworkID}
	var receiver control.TransportResource
	for _, resource := range p.NetworkIntent.Resources {
		if resource.ID == "demo-entry-wg" {
			view.Resources = append(view.Resources, resource)
		}
		if resource.ID == "demo-exit-wg" {
			receiver = resource
		}
	}
	for i := 0; i < 5; i++ {
		resource := receiver
		resource.ID, resource.ListenerID = fmt.Sprintf("demo-wg-%d", i), fmt.Sprintf("demo-wg-%d", i)
		resource.OwnerNodeID = fmt.Sprintf("demo-node-%d", i)
		resource.Authentication.LocalAddresses = new([]string{fmt.Sprintf("192.0.2.%d/32", 52+i)})
		dns, err := control.WireGuardAccessAddress(resource, "")
		if err != nil {
			t.Fatal(err)
		}
		view.Resources = append(view.Resources, resource)
		view.Links = append(view.Links, control.NetworkLink{ID: fmt.Sprintf("demo-link-%d", i),
			FromNodeID: view.DeviceID, ToNodeID: resource.OwnerNodeID, FromResourceID: "demo-entry-wg",
			ResourceID: resource.ID, InitiatorNodeID: view.DeviceID, Purpose: "relay",
			ProbeTarget: control.LinkProbeTarget{ResourceID: resource.ID, Host: dns.String(), Port: 53, Action: "wireguard_dns"}})
	}
	return view
}

func TestIndependentLinkProbesAreBoundedAndTimestampCompletedResults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	view := independentLinkView(t)
	started := make(chan string, len(view.Links))
	permits := make(chan struct{})
	var active, maximum atomic.Int32
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(at.UnixMilli())
	probe := func(ctx context.Context, _ string, resource control.TransportResource) (time.Duration, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		started <- resource.ID
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-permits:
		}
		if resource.ID == "demo-wg-0" {
			return 0, errors.New("temporary packet loss")
		}
		return 0, nil
	}
	var values []control.Observation
	var err error
	done := make(chan struct{})
	go func() {
		values, err = observeLinksWithProbe(ctx, view, "demo-network", 30*time.Second,
			func() time.Time { return time.UnixMilli(clock.Load()) }, probe)
		close(done)
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("independent links waited serially")
		}
	}
	select {
	case <-started:
		t.Fatal("more than four probes started concurrently")
	default:
	}
	clock.Store(at.Add(5 * time.Second).UnixMilli())
	select {
	case permits <- struct{}{}:
	case <-ctx.Done():
		t.Fatal("first wave did not complete")
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("remaining link never received the freed slot")
	}
	close(permits)
	<-done
	if err != nil || len(values) != 5 || maximum.Load() != 4 || active.Load() != 0 {
		t.Fatal("bounded link probing failed", err)
	}
	for i, value := range values {
		if value.ResourceID != fmt.Sprintf("demo-wg-%d", i) || value.ObservedAt != clock.Load() ||
			value.ValidUntil != clock.Load()+30000 || value.SpecDigest == "" {
			t.Fatal("unordered result or lifetime started before completion", value)
		}
		if i == 0 {
			if value.Result != "unavailable" || value.RoundTripMS != nil {
				t.Fatal("failed link borrowed another link's success", value)
			}
		} else if value.Result != "available" || value.RoundTripMS == nil || *value.RoundTripMS != 0 {
			t.Fatal("independent successful link was lost", value)
		}
	}
}

func TestCanceledLinkProbesExitWithoutInventingFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	view := independentLinkView(t)
	started := make(chan struct{}, len(view.Links))
	var active atomic.Int32
	probe := func(ctx context.Context, _ string, _ control.TransportResource) (time.Duration, error) {
		active.Add(1)
		defer active.Add(-1)
		started <- struct{}{}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		values, err := observeLinksWithProbe(ctx, view, "demo-network", 30*time.Second, time.Now, probe)
		if len(values) != 0 {
			err = errors.New("cancellation invented link failure observations")
		}
		done <- err
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-deadline.C:
			t.Fatal("independent probes did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || active.Load() != 0 {
			t.Fatal("cancellation failed to await probe cleanup", err)
		}
	case <-deadline.C:
		t.Fatal("canceled probes did not exit")
	}
}
