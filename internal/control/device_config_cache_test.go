package control

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	go func() { _, err := cache.get(first, key, true, build, nil); firstResult <- err }()
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
			if got, err := cache.get(ctx, key, true, build, nil); err != nil || got != value {
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
		if _, err := cache.get(ctx, failureKey, true, func() (*deviceConfigValue, error) {
			calls.Add(1)
			return nil, errors.New("demo build failure")
		}, nil); err == nil {
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
		if _, err := cache.get(context.Background(), key, true, func() (*deviceConfigValue, error) {
			return &deviceConfigValue{body: make([]byte, 128<<10)}, nil
		}, nil); err != nil {
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
		if _, err := cache.get(context.Background(), oversized, true, func() (*deviceConfigValue, error) {
			builds++
			return &deviceConfigValue{body: make([]byte, deviceConfigCacheBytes)}, nil
		}, nil); err != nil {
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
	conditional := func(digest string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/device/config", nil)
		r.Header.Set(DeviceConfigDigestHeader, digest)
		r = r.WithContext(context.WithValue(r.Context(), tunnelIdentityKey{}, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}))
		w := httptest.NewRecorder()
		server.DeviceHandler().ServeHTTP(w, r)
		return w
	}
	confirmed := conditional(first.configDigest)
	if confirmed.Code != http.StatusNoContent || confirmed.Body.Len() != 0 || confirmed.Header().Get(DeviceConfigDigestHeader) != first.configDigest || confirmed.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("unchanged certified configuration was not confirmed", confirmed.Code)
	}
	if conditional(ReleaseDigest([]byte("demo-other-config"))).Code != http.StatusOK {
		t.Fatal("different configuration did not return its complete signed envelope")
	}
	if next := read(); next != first || !bytes.Equal(next.body, first.body) {
		t.Fatal("unchanged authenticated inputs rebuilt the configuration")
	}
	firstEnvelope := decodedDeviceConfig(t, first)
	canonical, err := CanonicalEncode(firstEnvelope)
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
	if current := decodedDeviceConfig(t, read()); current.View.Name == envelope.View.Name || current.View.Routes[0].ID != routeID {
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
	nextEnvelope := decodedDeviceConfig(t, next)
	if next == first || nextEnvelope.ViewDigest != firstEnvelope.ViewDigest || reflect.DeepEqual(nextEnvelope.FactFrontier, firstEnvelope.FactFrontier) || bytes.Equal(next.body, first.body) {
		t.Fatal("unchanged execution View hid authentication progress")
	}
	if response := conditional(first.configDigest); response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), next.body) || first.configDigest == next.configDigest {
		t.Fatal("unchanged View suppressed a new signed authentication frontier", response.Code)
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
	if response := conditional(next.configDigest); response.Code == http.StatusNoContent || response.Code == http.StatusOK {
		t.Fatal("revoked device received an unchanged-configuration success")
	}
}

func decodedDeviceConfig(t *testing.T, value *deviceConfigValue) DeviceViewEnvelope {
	t.Helper()
	var envelope DeviceViewEnvelope
	if err := DecodeCanonical(value.body, &envelope, ContractDecodeLimits{MaxBytes: 4 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestDeviceConfigViewDoesNotWaitForSharedResponseSigning(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(strconv.FormatBool(oversized), func(t *testing.T) {
			var cache deviceConfigCache
			key := deviceConfigKey{device: "demo-device"}
			var projects, signatures atomic.Int32
			started, release := make(chan struct{}), make(chan struct{})
			view := &deviceConfigValue{digest: "demo-digest", canonicalView: []byte("demo-strict-view")}
			if oversized {
				view.canonicalView = make([]byte, deviceConfigCacheBytes)
			}
			project := func() (*deviceConfigValue, error) { projects.Add(1); return view, nil }
			sign := func(value *deviceConfigValue) (*deviceConfigValue, error) {
				signatures.Add(1)
				close(started)
				<-release
				return &deviceConfigValue{view: value.view, digest: value.digest, body: []byte("demo-signed-response")}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			first, stopFirst := context.WithCancel(ctx)
			fullDone := make(chan error, 1)
			go func() { _, err := cache.get(first, key, true, project, sign); fullDone <- err }()
			<-started
			stopFirst()
			if err := <-fullDone; !errors.Is(err, context.Canceled) {
				t.Fatal("cancelled response waiter remained attached", err)
			}
			// The full flight still holds a build slot. An uncached, oversized
			// View must also be readable from that flight without another build.
			actual, err := cache.get(ctx, key, false, project, sign)
			if err != nil || actual != view || actual.body != nil {
				t.Fatal("read-only caller waited for or received a partial signed response", err)
			}
			close(release)
			complete, err := cache.get(ctx, key, true, project, sign)
			if err != nil || complete.body == nil || complete.canonicalView != nil || view.body != nil || projects.Load() != 1 || signatures.Load() != 1 {
				t.Fatal("shared response was rebuilt or modified an already published View", err, projects.Load(), signatures.Load())
			}
			if cache.bytes > deviceConfigCacheBytes {
				t.Fatal("both outputs exceeded the original shared budget")
			}
		})
	}
}

func TestDeviceConfigSigningFailureRetainsOnlySuccessfulView(t *testing.T) {
	var cache deviceConfigCache
	key := deviceConfigKey{device: "demo-device"}
	var projects, signatures int
	project := func() (*deviceConfigValue, error) {
		projects++
		return &deviceConfigValue{canonicalView: []byte("demo-strict-view")}, nil
	}
	sign := func(value *deviceConfigValue) (*deviceConfigValue, error) {
		signatures++
		if signatures == 1 {
			return nil, errors.New("demo signing rejected")
		}
		return &deviceConfigValue{view: value.view, digest: value.digest, body: []byte("demo-response")}, nil
	}
	ctx := context.Background()
	view, err := cache.get(ctx, key, false, project, sign)
	if err != nil || signatures != 0 {
		t.Fatal("read-only construction signed a configuration", err)
	}
	if _, err := cache.get(ctx, key, true, project, sign); err == nil {
		t.Fatal("signing error became a successful response")
	}
	if actual, err := cache.get(ctx, key, false, project, sign); err != nil || actual != view || actual.body != nil {
		t.Fatal("failed response destroyed the independently successful View", err)
	}
	if full, err := cache.get(ctx, key, true, project, sign); err != nil || full.body == nil || projects != 1 || signatures != 2 {
		t.Fatal("failed signature was cached or retry repeated projection", err, projects, signatures)
	}
}

func TestDeviceConfigRequestJoinsPendingReadOnlyProjection(t *testing.T) {
	var cache deviceConfigCache
	key := deviceConfigKey{device: "demo-device"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	projectStarted, projectRelease := make(chan struct{}), make(chan struct{})
	signStarted, signRelease := make(chan struct{}), make(chan struct{})
	var projects atomic.Int32
	project := func() (*deviceConfigValue, error) {
		projects.Add(1)
		close(projectStarted)
		<-projectRelease
		return &deviceConfigValue{canonicalView: []byte("demo-strict-view")}, nil
	}
	sign := func(value *deviceConfigValue) (*deviceConfigValue, error) {
		close(signStarted)
		<-signRelease
		return &deviceConfigValue{view: value.view, digest: value.digest, body: []byte("demo-response")}, nil
	}
	readOnly, complete := make(chan error, 1), make(chan error, 1)
	go func() { _, err := cache.get(ctx, key, false, project, sign); readOnly <- err }()
	<-projectStarted
	go func() { _, err := cache.get(ctx, key, true, project, sign); complete <- err }()
	for {
		cache.mu.Lock()
		joined := cache.flights[key].full
		cache.mu.Unlock()
		if joined {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("configuration did not join the outstanding View computation")
		}
		time.Sleep(time.Millisecond)
	}
	close(projectRelease)
	<-signStarted
	if err := <-readOnly; err != nil {
		t.Fatal("read-only consumer waited for subsequent signing", err)
	}
	close(signRelease)
	if err := <-complete; err != nil || projects.Load() != 1 {
		t.Fatal("configuration repeated an in-flight strict View computation", err, projects.Load())
	}
}

func TestDeviceConfigFullFlightsDoNotConsumeAnotherViewBuildSlot(t *testing.T) {
	var cache deviceConfigCache
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started, release := make(chan struct{}, 2), make(chan struct{})
	results := make(chan error, 2)
	project := func() (*deviceConfigValue, error) { return &deviceConfigValue{canonicalView: []byte("demo-view")}, nil }
	sign := func(*deviceConfigValue) (*deviceConfigValue, error) {
		started <- struct{}{}
		<-release
		return &deviceConfigValue{body: []byte("demo-response")}, nil
	}
	for _, id := range []string{"demo-a", "demo-b"} {
		go func() { _, err := cache.get(ctx, deviceConfigKey{device: id}, true, project, sign); results <- err }()
	}
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("full callers occupied both slots waiting for another View build")
		}
	}
	for _, id := range []string{"demo-a", "demo-b"} {
		if value, err := cache.get(ctx, deviceConfigKey{device: id}, false, project, sign); err != nil || value.body != nil {
			t.Fatal("View access required another occupied build slot", err)
		}
	}
	third, stopThird := context.WithCancel(ctx)
	stopThird()
	if _, err := cache.get(third, deviceConfigKey{device: "demo-c"}, false, project, sign); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled third build was queued outside the fixed slots", err)
	}
	cache.mu.Lock()
	count := len(cache.flights)
	cache.mu.Unlock()
	if count != deviceConfigBuilds {
		t.Fatal("distinct build count escaped its original bound", count)
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}
