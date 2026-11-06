package deviceclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"

	"loom/internal/control"
)

func measurementFetchScope(t *testing.T, fixture deviceRequestFixture) control.DeviceLinkObservations {
	t.Helper()
	_, makeView := schema3Fixture(t, "linux")
	endpoints := fixture.store.LKG().View.Endpoints
	view := makeView(fixture.store.PublicKey(), 8, func(view *control.DeviceView) {
		view.Endpoints = endpoints
		view.Services[0].ProbeURLs = []string{"https://demo-a.example/health", "https://demo-b.example/health"}
		view.Nodes = append(view.Nodes, control.ViewNode{ID: "demo-exit", Responsibilities: []string{"internet_egress"}, PolicyIDs: []string{}})
		sort.Slice(view.Nodes, func(i, j int) bool { return view.Nodes[i].ID < view.Nodes[j].ID })
	})
	if err := fixture.store.SaveLKG(view); err != nil {
		t.Fatal(err)
	}
	// The old sample is deliberately expired. It still belongs to this exact
	// base until the server removes it; the client cannot trim it on read.
	at := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	sample := control.Observation{Level: "egress", Target: view.View.Services[0].ProbeURLs[0], Action: "https_request", SpecDigest: control.ReleaseDigest([]byte("demo-spec")), NetworkGeneration: "demo-exit-network", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli()}
	base := control.DeviceLinkObservations{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.View.DeviceID, ViewDigest: view.ViewDigest, Cursor: "demo-base", Reset: true, Removed: []string{}, Observations: []control.DeviceLinkObservation{{DeviceID: "demo-exit", ReportSequence: 1, ReportDigest: control.ReleaseDigest([]byte("demo-report")), CurrentUntil: sample.ValidUntil, Observation: sample}}}
	if err := base.ValidateForView(view.View); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestFetchMeasurementsCapturesTheExactRequestBase(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var base control.DeviceLinkObservations
	var removed string
	fixture := newDeviceRequestFixture(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		var request control.DeviceLinkObservationRequest
		if err != nil || control.DecodeCanonical(raw, &request, control.ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 8, MaxItems: 32}) != nil || request.Cursor != "demo-base" {
			t.Error("request did not capture its original cursor")
		}
		close(started)
		<-release
		delta := base
		delta.Reset, delta.Cursor, delta.Removed, delta.Observations = false, "demo-next", []string{removed}, []control.DeviceLinkObservation{}
		writeDeviceResponse(t, w, delta)
	})
	base = measurementFetchScope(t, fixture)
	removed, _ = control.MeasurementItemID(base.Observations[0])
	previous := base
	previous.Observations = append([]control.DeviceLinkObservation(nil), base.Observations...)
	identityBefore, _ := os.ReadFile(fixture.store.path)
	type outcome struct {
		value control.DeviceLinkObservations
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		value, err := FetchLinkObservations(fixture.context(context.Background()), fixture.store, &previous)
		done <- outcome{value, err}
	}()
	<-started
	// The caller now owns a different, individually valid full cache. It is
	// not the base whose cursor was sent by the in-flight request.
	previous.Cursor = "demo-other"
	previous.Observations[0].Observation.Target = "https://demo-b.example/health"
	if err := previous.ValidateForView(fixture.store.LKG().View); err != nil {
		t.Fatal(err)
	}
	callerBytes, _ := control.CanonicalEncode(previous)
	close(release)
	result := <-done
	if result.err != nil || result.value.Cursor != "demo-next" || len(result.value.Observations) != 0 {
		t.Fatal("response was merged with another caller cache", result.err)
	}
	after, _ := control.CanonicalEncode(previous)
	identityAfter, _ := os.ReadFile(fixture.store.path)
	if !bytes.Equal(callerBytes, after) || !bytes.Equal(identityBefore, identityAfter) {
		t.Fatal("read-only measurement fetch changed caller base or protected identity")
	}
}

func TestFetchMeasurementsRejectedCancelledAndChangedViewKeepBase(t *testing.T) {
	for _, scenario := range []string{"invalid-delta", "cancelled", "changed-view"} {
		t.Run(scenario, func(t *testing.T) {
			var fixture deviceRequestFixture
			var base control.DeviceLinkObservations
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture = newDeviceRequestFixture(t, func(w http.ResponseWriter, r *http.Request) {
				delta := base
				delta.Reset, delta.Cursor, delta.Observations = false, "demo-next", []control.DeviceLinkObservation{}
				switch scenario {
				case "invalid-delta":
					delta.Removed = []string{control.ReleaseDigest([]byte("demo-unknown-item"))}
				case "cancelled":
					cancel()
				case "changed-view":
					_, makeView := schema3Fixture(t, "linux")
					previous := fixture.store.LKG()
					next := makeView(fixture.store.PublicKey(), 9, func(view *control.DeviceView) { *view = previous.View; view.Name = "Demo changed view" })
					if err := fixture.store.SaveLKG(next); err != nil {
						t.Error(err)
					}
				}
				writeDeviceResponse(t, w, delta)
			})
			base = measurementFetchScope(t, fixture)
			before, _ := control.CanonicalEncode(base)
			_, err := FetchLinkObservations(fixture.context(ctx), fixture.store, &base)
			if err == nil || scenario == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("rejected result became a new snapshot", err)
			}
			after, _ := control.CanonicalEncode(base)
			if !bytes.Equal(before, after) {
				t.Fatal("failed request changed exact base or cursor")
			}
			if scenario == "changed-view" && fixture.store.LKG().View.Name != "Demo changed view" {
				t.Fatal("stale measurement response restored a superseded accepted View")
			}
		})
	}
}

func TestFetchMeasurementsOwnsTheRequestedSampleMetrics(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var base control.DeviceLinkObservations
	fixture := newDeviceRequestFixture(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		delta := base
		delta.Reset, delta.Cursor, delta.Observations = false, "demo-next", []control.DeviceLinkObservation{}
		writeDeviceResponse(t, w, delta)
	})
	base = measurementFetchScope(t, fixture)
	duration := int64(5)
	base.Observations[0].Observation.DurationMS = &duration
	type outcome struct {
		value control.DeviceLinkObservations
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		value, err := FetchLinkObservations(fixture.context(context.Background()), fixture.store, &base)
		done <- outcome{value, err}
	}()
	<-started
	duration = 50
	close(release)
	result := <-done
	if result.err != nil || len(result.value.Observations) != 1 || result.value.Observations[0].Observation.DurationMS == nil || *result.value.Observations[0].Observation.DurationMS != 5 {
		t.Fatal("response adopted a sample metric changed after the request began", result.err)
	}
	if duration != 50 {
		t.Fatal("measurement read changed the caller's sample metric")
	}
}

func TestMeasurementSnapshotClonesEveryMutableSampleField(t *testing.T) {
	duration, rtt := int64(5), int64(3)
	value := control.DeviceLinkObservations{
		Removed: []string{"demo-removed"},
		Observations: []control.DeviceLinkObservation{{Observation: control.Observation{
			Target: "demo.example:443", DurationMS: &duration, RoundTripMS: &rtt,
			HY2Transfer: &control.HY2Transfer{DurationNS: 1000, RXBytes: 1, TXBytes: 1},
		}}},
	}
	want, _ := control.CanonicalEncode(value)
	copy := cloneMeasurementSnapshot(value)
	value.Removed[0] = "demo-other"
	value.Observations[0].Observation.Target = "demo-other.example:443"
	duration, rtt = 50, 30
	value.Observations[0].Observation.HY2Transfer.RXBytes = 2
	got, _ := control.CanonicalEncode(copy)
	if !bytes.Equal(got, want) {
		t.Fatal("request snapshot retained mutable caller fields")
	}
	missing := cloneMeasurementSnapshot(control.DeviceLinkObservations{})
	if missing.Removed != nil || missing.Observations != nil {
		t.Fatal("cloning repaired invalid absent cache arrays")
	}
}
