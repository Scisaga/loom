package linuxclient

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
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
		seed := sha256.Sum256([]byte(resource.OwnerNodeID))
		private, err := ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		resource.Authentication.PublicKey = new(base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()))
		view.Resources = append(view.Resources, resource)
		device := p.DeviceAuthorizations[2]
		device.ID, device.Name = resource.OwnerNodeID, resource.OwnerNodeID
		device.DevicePublicKey, device.RuntimeKey = *resource.Authentication.PublicKey, *resource.Authentication.PublicKey
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, device)
	}
	p.NetworkIntent.Resources = view.Resources
	current, err := control.ProjectDeviceView(p, view.DeviceID)
	if err != nil || len(current.Links) != 5 {
		t.Fatal("independent automatic links were not projected", err)
	}
	return current
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

func TestLinkProbeRefreshOverlapPreservesFreshnessBound(t *testing.T) {
	view := independentLinkView(t)
	options := Options{}
	options.defaults()
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	observe := func(at time.Time, interval time.Duration) []control.Observation {
		t.Helper()
		values, err := observeLinksWithProbe(context.Background(), view, "demo-network", interval,
			func() time.Time { return at }, func(context.Context, string, control.TransportResource) (time.Duration, error) { return 0, nil })
		if err != nil || len(values) != len(view.Links) {
			t.Fatal("link refresh did not complete", err)
		}
		return values
	}
	first := observe(at, options.RefreshPoll)
	original, err := control.CanonicalEncode(first)
	if err != nil {
		t.Fatal(err)
	}
	second := observe(at.Add(options.RefreshPoll), options.RefreshPoll)
	// Twelve seconds represent ordinary upload plus member-copy delay. The
	// next independently measured round must arrive before the old one expires.
	arrived := at.Add(options.RefreshPoll + 12*time.Second).UnixMilli()
	for i := range first {
		if first[i].ValidUntil != at.Add(30*time.Second).UnixMilli() || arrived >= first[i].ValidUntil ||
			second[i].ObservedAt != at.Add(options.RefreshPoll).UnixMilli() || second[i].ValidUntil <= first[i].ValidUntil {
			t.Fatal("normal report delivery has no overlap within the original freshness bound")
		}
	}
	unchanged, err := control.CanonicalEncode(first)
	if err != nil || string(unchanged) != string(original) {
		t.Fatal("a later round changed the original samples", err)
	}
	// A custom slow diagnostic poll cannot create observations outside the
	// existing receiving contract either.
	for _, sample := range observe(at, time.Hour) {
		if sample.ValidUntil != at.Add(30*time.Second).UnixMilli() {
			t.Fatal("a slow refresh extended the maximum sample lifetime")
		}
	}
}
