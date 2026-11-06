package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

func TestSnapshotConfigReusePreservesBlockedAndUnsignedReadability(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("join failed")
	}
	request, err := server.newDeviceConfigRequest()
	if err != nil {
		t.Fatal(err)
	}
	value, err := request.get(context.Background(), invite.DeviceID)
	if err != nil || request.finish() != nil {
		t.Fatal("warm fixture", err)
	}
	read := func() WebSnapshot {
		t.Helper()
		value, err := server.snapshotValue(httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
		if err != nil {
			t.Fatal("readable projection failed", err)
		}
		if len(value.Paths) != 0 {
			t.Fatal("snapshot invented a current Policy without a device report")
		}
		return value
	}
	first := read()
	read()
	again, err := request.get(context.Background(), invite.DeviceID)
	if err != nil || again != value {
		t.Fatal("snapshot replaced an unchanged shared config", err)
	}
	// A local signing failure cannot prevent a pure read of accepted authority.
	saved := server.Runtime.Config.SigningKeyFile
	server.Runtime.Config.SigningKeyFile = filepath.Join(t.TempDir(), "demo-unavailable-signing-key")
	if fallback := read(); len(fallback.Paths) != len(first.Paths) {
		t.Fatal("unavailable signing identity removed readable paths")
	}
	server.Runtime.Config.SigningKeyFile = saved
	authority := server.Runtime.Authority
	authority.mu.Lock()
	authority.blocked = errors.New("demo blocked accepted-input refresh")
	authority.mu.Unlock()
	if blocked := read(); blocked.UIState.LocalWritable || len(blocked.Paths) != len(first.Paths) {
		t.Fatal("blocked read-only projection changed")
	}
	authority.mu.Lock()
	authority.blocked = nil
	authority.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.snapshotValue(httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil).WithContext(ctx)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read returned a fallback snapshot", err)
	}
}

type snapshotEnteredContext struct {
	context.Context
	once    sync.Once
	entered chan struct{}
}

func (ctx *snapshotEnteredContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.entered) })
	return nil
}

func TestSnapshotConfigReuseRejectsAnInputChangeWhileWaiting(t *testing.T) {
	server, invite, _, claim, private, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("join failed")
	}
	request, err := server.newDeviceConfigRequest()
	if err != nil {
		t.Fatal(err)
	}
	value, err := request.get(context.Background(), invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: value.view.NetworkID, DeviceID: invite.DeviceID, ReportSequence: 1, ViewDigest: value.digest, NetworkGeneration: "demo-network", ReportedAt: server.now().UnixMilli(), PolicyID: value.view.PolicyIDs[0], Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped"}, Components: []ComponentReadback{}}, private)
	if err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, server.Runtime.Reports, []DeviceReport{report}, value.view.DevicePublicKey)
	cache := &request.authority.deviceConfigs
	cache.mu.Lock()
	cache.items = nil
	cache.bytes = 0
	cache.lru.Init()
	cache.mu.Unlock()
	key := deviceConfigKey{request.input.revision, invite.DeviceID, request.member.PublicKey, request.local, request.releases}
	buildStarted, release := make(chan struct{}), make(chan struct{})
	buildDone := make(chan error, 1)
	go func() {
		_, err := cache.get(context.Background(), key, true, func() (*deviceConfigValue, error) { close(buildStarted); <-release; return value, nil }, nil)
		buildDone <- err
	}()
	<-buildStarted
	ctx := &snapshotEnteredContext{Context: context.Background(), entered: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := server.snapshotValue(httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil).WithContext(ctx))
		result <- err
	}()
	<-ctx.entered
	projection := request.authority.Snapshot()
	policy := projection.NetworkIntent.Policies[0]
	policy.AllowDirect = new(false)
	policy.EntryScope = PolicyScope{Mode: "none", NodeIDs: []string{}}
	target, _ := projection.CurrentTarget("policy", policy.ID)
	service, _ := projection.CurrentTarget("service", policy.ServiceID)
	dependencies := sortedUniqueDependencies(append(append([]string{}, target.MaterialIDs...), service.MaterialIDs...))
	_, _, err = server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-change-during-snapshot", Operation: "policy.put", TargetKind: "policy", TargetID: policy.ID, Dependencies: dependencies, Payload: policy})
	close(release)
	if buildErr := <-buildDone; buildErr != nil {
		t.Fatal(buildErr)
	}
	if err != nil {
		t.Fatal("fixture authority change failed", err)
	}
	if err := <-result; !errors.Is(err, errDeviceConfigChanged) {
		t.Fatal("changed inputs returned a stale pure fallback", err)
	}
}

func TestDeviceConfigOuterFinishRejectsUnavailableReleaseMetadata(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("join failed")
	}
	source, expected := expectedReleaseFixture()
	server.Releases = source
	if _, _, err := server.HandleOperation(context.Background(), expectedOperation(server.Runtime.Authority.Snapshot(), expected, "demo-current-release")); err != nil {
		t.Fatal(err)
	}
	request, err := server.newDeviceConfigRequest()
	if err != nil {
		t.Fatal(err)
	}
	value, err := request.get(context.Background(), invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	source.unavailable = true
	if !errors.Is(request.finish(), errDeviceConfigChanged) {
		t.Fatal("outer finish accepted unavailable original release metadata")
	}
	if response := enrollmentHTTP(t, server, "/device/config", map[string]any{"schema": 3}, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code == http.StatusOK {
		t.Fatal("formal config endpoint returned a cached missing release")
	}
	source.unavailable = false
	next, err := server.newDeviceConfigRequest()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := next.get(context.Background(), invite.DeviceID)
	if err != nil || restored != value || next.finish() != nil {
		t.Fatal("restored exact metadata did not permit immutable output reuse", err)
	}
}
