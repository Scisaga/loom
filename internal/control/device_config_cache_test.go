package control

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeviceConfigBuildCoalescesCancelledWaitersAndDoesNotCacheFailures(t *testing.T) {
	var cache deviceConfigCache
	key := deviceConfigKey{device: "demo-device"}
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	value := &deviceConfigValue{body: []byte("demo-output")}
	build := func() (*deviceConfigValue, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return value, nil
	}
	first, cancel := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() { _, err := cache.get(first, key, build); firstResult <- err }()
	<-started
	cancel()
	if err := <-firstResult; !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled caller remained attached to the shared build", err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			if got, err := cache.get(ctx, key, build); err != nil || got != value {
				t.Error("another waiter lost the shared result", err)
			}
		}()
	}
	close(release)
	group.Wait()
	if calls.Load() != 1 {
		t.Fatal("cancellation or concurrent reads started another build", calls.Load())
	}
	failureKey := deviceConfigKey{device: "demo-failed"}
	for range 2 {
		if _, err := cache.get(ctx, failureKey, func() (*deviceConfigValue, error) {
			calls.Add(1)
			return nil, errors.New("demo build failure")
		}); err == nil {
			t.Fatal("failed build became a success")
		}
	}
	if calls.Load() != 3 {
		t.Fatal("failed build was cached")
	}
}

func TestDeviceConfigCacheBoundsTypedAndEncodedOutputs(t *testing.T) {
	var cache deviceConfigCache
	for i := 0; i < 24; i++ {
		key := deviceConfigKey{device: "demo-" + strconv.Itoa(i)}
		if _, err := cache.get(context.Background(), key, func() (*deviceConfigValue, error) {
			return &deviceConfigValue{body: make([]byte, 128<<10)}, nil
		}); err != nil {
			t.Fatal(err)
		}
		if cache.bytes > deviceConfigCacheBytes {
			t.Fatal("configuration cache exceeded its complete budget", cache.bytes)
		}
	}
	if len(cache.items) >= 24 || cache.lru.Len() != len(cache.items) {
		t.Fatal("old outputs were not evicted together")
	}
	var builds int
	oversized := deviceConfigKey{device: "demo-oversized"}
	for range 2 {
		if _, err := cache.get(context.Background(), oversized, func() (*deviceConfigValue, error) {
			builds++
			return &deviceConfigValue{body: make([]byte, deviceConfigCacheBytes)}, nil
		}); err != nil {
			t.Fatal("large valid result was rejected instead of bypassing storage", err)
		}
	}
	if builds != 2 || cache.items[oversized] != nil || cache.bytes > deviceConfigCacheBytes {
		t.Fatal("oversized output entered the cache")
	}
}

func TestDeviceConfigurationReusesCanonicalOutputAndAdvancesUnchangedView(t *testing.T) {
	server, invite, _, claim, _, policyDependencies := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("join failed", response.Code)
	}
	read := func() *deviceConfigValue {
		t.Helper()
		request, err := server.newDeviceConfigRequest()
		if err != nil {
			t.Fatal(err)
		}
		value, err := request.get(context.Background(), invite.DeviceID)
		if err != nil || request.finish() != nil {
			t.Fatal("configuration unavailable", err)
		}
		return value
	}
	first := read()
	if next := read(); next != first || !bytes.Equal(next.body, first.body) {
		t.Fatal("unchanged authenticated inputs rebuilt the configuration")
	}
	canonical, err := CanonicalEncode(first.envelope)
	if err != nil || !bytes.Equal(canonical, first.body) {
		t.Fatal("stored wire differs from the ordinary canonical encoder", err)
	}
	envelope, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	envelope.View.Name = "Demo caller mutation"
	if len(envelope.View.Routes) == 0 {
		t.Fatal("fixture has no route slice to exercise output ownership")
	}
	routeID := envelope.View.Routes[0].ID
	envelope.View.Routes[0].ID = "demo-caller-route-mutation"
	if read().envelope.View.Name == envelope.View.Name || read().envelope.View.Routes[0].ID != routeID {
		t.Fatal("public envelope caller mutated the shared value")
	}
	prior, err := server.newDeviceConfigRequest()
	if err != nil {
		t.Fatal(err)
	}
	p := server.Runtime.Authority.Snapshot()
	authorization, found := authorizationFor(p, invite.DeviceID)
	if !found {
		t.Fatal("authorization missing")
	}
	target, _ := p.CurrentTarget("device", invite.DeviceID)
	put := DevicePut{ID: authorization.ID, Name: authorization.Name, Responsibilities: authorization.Responsibilities,
		PolicyIDs: authorization.PolicyIDs, DistributionURLs: authorization.DistributionURLs, DNSServers: authorization.DNSServers}
	dependencies := sortedUniqueDependencies(append(append([]string{}, target.MaterialIDs...), policyDependencies...))
	_, _, err = server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-same-device-inputs", Operation: "device.put", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: dependencies, Payload: put})
	if err != nil {
		t.Fatal("same execution inputs could not advance authentication", err)
	}
	if _, err := prior.get(context.Background(), invite.DeviceID); !errors.Is(err, errDeviceConfigChanged) {
		t.Fatal("an older captured input returned after authentication advanced", err)
	}
	next := read()
	if next == first || next.envelope.ViewDigest != first.envelope.ViewDigest || reflect.DeepEqual(next.envelope.FactFrontier, first.envelope.FactFrontier) || bytes.Equal(next.body, first.body) {
		t.Fatal("unchanged execution View hid authentication progress")
	}
	a := server.Runtime.Authority
	a.mu.Lock()
	a.blocked = errors.New("demo blocked authority")
	a.mu.Unlock()
	if _, err := server.newDeviceConfigRequest(); err == nil {
		t.Fatal("blocked authority served a warm configuration")
	}
	a.mu.Lock()
	a.blocked = nil
	a.mu.Unlock()
	target, _ = a.Snapshot().CurrentTarget("device", invite.DeviceID)
	_, _, err = server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-revoke-cached-device", Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: target.MaterialIDs, Payload: DeleteTarget{ID: invite.DeviceID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.deviceEnvelope(invite.DeviceID); err == nil {
		t.Fatal("revocation returned an older cached configuration")
	}
}
