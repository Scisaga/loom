package deviceclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"loom/internal/control"
)

func TestAwaitConfigurationDoesNotLetUnchangedMemberCancelFreshEnvelope(t *testing.T) {
	unchanged := make(chan struct{})
	var next control.DeviceViewEnvelope
	fixture := newDeviceRequestFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(control.DeviceConfigWaitHeader) == "" {
			t.Error("configuration follow did not request bounded waiting")
		}
		w.Header().Set(control.DeviceConfigDigestHeader, r.Header.Get(control.DeviceConfigDigestHeader))
		w.Header().Set(control.DeviceConfigWaitHeader, r.Header.Get(control.DeviceConfigWaitHeader))
		w.WriteHeader(http.StatusNoContent)
		close(unchanged)
	}, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-unchanged:
			writeDeviceResponse(t, w, next)
		case <-r.Context().Done():
		}
	})
	next = fixture.view(8)
	before, _ := os.ReadFile(fixture.store.path)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result, err := AwaitConfiguration(fixture.context(ctx), fixture.store, 0)
	if err != nil || result.FactFrontier[0].Sequence != 8 {
		t.Fatal("unchanged member hid the validated new configuration", err)
	}
	after, _ := os.ReadFile(fixture.store.path)
	if !bytes.Equal(before, after) {
		t.Fatal("read-only follow overwrote identity or authentication progress")
	}
}

func TestAwaitConfigurationConfirmsOnlyAuthenticatedEmptyAcknowledgment(t *testing.T) {
	for _, acknowledged := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-wait-ack", true: "unchanged"}[acknowledged], func(t *testing.T) {
			fixture := newDeviceRequestFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(control.DeviceConfigDigestHeader, r.Header.Get(control.DeviceConfigDigestHeader))
				if acknowledged {
					w.Header().Set(control.DeviceConfigWaitHeader, r.Header.Get(control.DeviceConfigWaitHeader))
				}
				w.WriteHeader(http.StatusNoContent)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			value, err := AwaitConfiguration(fixture.context(ctx), fixture.store, 0)
			if acknowledged {
				if err != nil || value.Signature != fixture.store.LKG().Signature {
					t.Fatal("verified unchanged response was lost", err)
				}
			} else if err == nil {
				t.Fatal("nonwaiting response became a successful configuration follow")
			}
		})
	}
}

func TestAwaitConfigurationCancelsAndJoinsPrivateRequests(t *testing.T) {
	started, stopped := make(chan struct{}, 2), make(chan struct{}, 2)
	handler := func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		// This framed-tunnel fixture dispatches ReadRequest directly rather
		// than using http.Server; observe the actual TLS socket closing.
		_, _ = io.Copy(io.Discard, w.(*deviceTunnelResponse).connection)
		stopped <- struct{}{}
	}
	fixture := newDeviceRequestFixture(t, handler, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := AwaitConfiguration(fixture.context(ctx), fixture.store, 0); done <- err }()
	for range 2 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("private waiting requests did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation became a configuration result", err)
		}
	case <-time.After(time.Second):
		t.Fatal("configuration follow left a client request running")
	}
	for range 2 {
		select {
		case <-stopped:
		case <-time.After(time.Second):
			t.Fatal("cancellation did not close an authenticated tunnel")
		}
	}
}
