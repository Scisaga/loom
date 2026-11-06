package control

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

// A warm response has no outstanding build. Done is first consulted when the
// handler begins waiting, allowing a mutation without sleeping or racing it.
type configWaitingContext struct {
	context.Context
	ready chan struct{}
	once  sync.Once
}

func (ctx *configWaitingContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.ready) })
	return ctx.Context.Done()
}

func TestDeviceConfigurationWaitRechecksAuthorityAndKeepsAuthenticationProgress(t *testing.T) {
	for _, action := range []string{"same-view", "revoke", "blocked", "cancel", "timeout"} {
		t.Run(action, func(t *testing.T) {
			server, invite, _, claim, _, policyDependencies := enrollmentAuthorityFixture(t)
			if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
				t.Fatal("join failed", response.Code)
			}
			request, err := server.newDeviceConfigRequest()
			if err != nil {
				t.Fatal(err)
			}
			first, err := request.get(context.Background(), invite.DeviceID)
			if err != nil {
				t.Fatal(err)
			}
			before := decodedDeviceConfig(t, first)
			parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx := &configWaitingContext{Context: context.WithValue(parent, tunnelIdentityKey{}, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}), ready: make(chan struct{})}
			r := httptest.NewRequest(http.MethodPost, "/device/config", nil).WithContext(ctx)
			r.Header.Set(DeviceConfigDigestHeader, first.configDigest)
			r.Header.Set(DeviceConfigWaitHeader, "20")
			if action == "timeout" {
				r.Header.Set(DeviceConfigWaitHeader, "1")
			}
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); server.DeviceHandler().ServeHTTP(w, r) }()
			select {
			case <-ctx.ready:
			case <-parent.Done():
				t.Fatal("handler did not wait for a configuration change")
			}
			select {
			case <-done:
				t.Fatal("unchanged configuration was returned without waiting")
			default:
			}
			switch action {
			case "cancel":
				cancel()
			case "blocked":
				a := server.Runtime.Authority
				if err := os.WriteFile(filepath.Join(a.root, "state.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
				a.mu.Lock()
				err := a.reloadLocked()
				a.mu.Unlock()
				if err == nil {
					t.Fatal("invalid protected authority did not fail closed")
				}
			case "same-view", "revoke":
				p := server.Runtime.Authority.Snapshot()
				authorization, _ := authorizationFor(p, invite.DeviceID)
				target, _ := p.CurrentTarget("device", invite.DeviceID)
				op := Operation{Schema: 3, RequestID: "demo-wait-" + action, Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: target.MaterialIDs, Payload: DeleteTarget{ID: invite.DeviceID}}
				if action == "same-view" {
					op.Operation = "device.put"
					op.Dependencies = sortedUniqueDependencies(append(append([]string{}, target.MaterialIDs...), policyDependencies...))
					op.Payload = DevicePut{ID: authorization.ID, Name: authorization.Name, Responsibilities: authorization.Responsibilities, PolicyIDs: authorization.PolicyIDs, DistributionURLs: authorization.DistributionURLs, DNSServers: authorization.DNSServers}
				}
				if _, _, err := server.HandleOperation(parent, op); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("configuration wait was not released by its event")
			}
			switch action {
			case "same-view":
				if w.Code != http.StatusOK || bytes.Equal(w.Body.Bytes(), first.body) {
					t.Fatal("authentication advance was suppressed", w.Code)
				}
				var after DeviceViewEnvelope
				if err := DecodeCanonical(w.Body.Bytes(), &after, ContractDecodeLimits{MaxBytes: 4 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
					t.Fatal(err)
				}
				if after.ViewDigest != before.ViewDigest || reflect.DeepEqual(after.FactFrontier, before.FactFrontier) || w.Header().Get(DeviceConfigDigestHeader) == first.configDigest {
					t.Fatal("unchanged View lost its new signed frontier")
				}
			case "revoke", "blocked":
				if w.Code == http.StatusOK || w.Code == http.StatusNoContent {
					t.Fatal("revoked identity received an old success")
				}
			case "cancel":
				if w.Body.Len() != 0 || w.Header().Get(DeviceConfigDigestHeader) != "" {
					t.Fatal("cancelled wait manufactured an acknowledgment")
				}
			case "timeout":
				if w.Code != http.StatusNoContent || w.Body.Len() != 0 || w.Header().Get(DeviceConfigDigestHeader) != first.configDigest || w.Header().Get(DeviceConfigWaitHeader) != "1" {
					t.Fatal("unchanged deadline did not confirm the accepted configuration", w.Code)
				}
			}
		})
	}
}

func TestDeviceConfigurationWaitRejectsAmbiguousAndUnboundedRequests(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("join failed", response.Code)
	}
	for _, values := range [][]string{{"0"}, {"21"}, {"01"}, {"+1"}, {"1", "1"}, {""}} {
		r := httptest.NewRequest(http.MethodPost, "/device/config", nil)
		r.Header.Set(DeviceConfigDigestHeader, ReleaseDigest([]byte("demo-known-config")))
		for _, value := range values {
			r.Header.Add(DeviceConfigWaitHeader, value)
		}
		r = r.WithContext(context.WithValue(r.Context(), tunnelIdentityKey{}, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}))
		w := httptest.NewRecorder()
		server.DeviceHandler().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatal("noncanonical or unbounded configuration wait accepted", values, w.Code)
		}
	}
}
