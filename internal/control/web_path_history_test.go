package control

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestWebPathPreservesSameExitRouteIdentity(t *testing.T) {
	projection := relayProjectionFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	paths := projectWebPaths(projection)
	seen := 0
	for _, path := range paths {
		if path.Device != view.DeviceID {
			continue
		}
		for _, route := range view.Routes {
			if route.ID != path.CandidateID {
				continue
			}
			seen++
			if path.ServiceID != route.ServiceID || path.SpecDigest != route.SpecDigest || path.FirstResourceID != route.FirstResourceID || path.FirstTransport != "hysteria2" || !reflect.DeepEqual(path.LinkIDs, route.LinkIDs) || !reflect.DeepEqual(path.Chain, route.NodeChain) || path.FinalExit != route.FinalExit {
				t.Fatal("same-exit routes lost the first resource, transport, ordered link scope or specification")
			}
		}
	}
	if seen != 2 {
		t.Fatal("one-hop and relay routes were collapsed")
	}
}

func TestWebPathHistoryUsesOriginalScopedSignedSamples(t *testing.T) {
	fixture, _, projection := deviceContractFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil || len(view.Routes) != 1 {
		t.Fatal("Direct fixture unavailable", err)
	}
	route := view.Routes[0]
	digest, _ := DeviceViewDigest(view)
	now := time.Date(2026, 1, 2, 12, 30, 0, 0, time.UTC)
	hour := now.Truncate(time.Hour)
	zero := int64(0)
	base := Observation{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, Target: "https://demo.example/", Action: "https_request", SpecDigest: route.SpecDigest, NetworkGeneration: "demo-network-generation", Result: "available", DurationMS: &zero}
	reports := []DeviceReport{}
	appendSample := func(hoursAgo int, change func(*Observation)) {
		t.Helper()
		observation := base
		observation.ObservedAt = hour.Add(-time.Duration(hoursAgo)*time.Hour + time.Minute).UnixMilli()
		observation.ValidUntil = observation.ObservedAt + time.Minute.Milliseconds()
		if change != nil {
			change(&observation)
		}
		value := DeviceReport{Schema: 3, NetworkID: projection.NetworkID, DeviceID: view.DeviceID, ReportSequence: U64(len(reports) + 1), ViewDigest: digest, NetworkGeneration: base.NetworkGeneration,
			ReportedAt: now.Add(time.Hour).UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{observation}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
		value, err = SignDeviceReport(value, fixture.keys[0])
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, value)
	}
	appendSample(0, nil)
	appendSample(0, nil) // Repeated original sample, not another measurement.
	appendSample(1, func(v *Observation) { v.Result, v.DurationMS = "unavailable", nil })
	appendSample(2, nil) // Expired now, still an original historical success.
	appendSample(3, func(v *Observation) { v.SpecDigest = "sha256:" + strings.Repeat("f", 64) })
	appendSample(3, func(v *Observation) { v.Target = "https://other.example/" })
	appendSample(4, nil)
	appendSample(4, func(v *Observation) { v.Result, v.DurationMS = "unavailable", nil })
	appendSample(5, nil)
	fork := reports[len(reports)-1]
	fork.Observations = append([]Observation{}, fork.Observations...)
	fork.Observations[0].Result = "unavailable"
	fork, err = SignDeviceReport(fork, fixture.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	reports = append(reports, fork)
	appendSample(6, nil)
	// Canonical but signed by another identity: restarting the file is not authentication.
	reports[len(reports)-1], err = SignDeviceReport(reports[len(reports)-1], fixture.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	appendSample(-1, nil) // Future sample cannot populate the current hour.
	appendSample(24, nil)
	appendSample(7, nil)
	// ReportedAt and ObservedAt are separate device wall-clock readings. A
	// backward clock adjustment does not invalidate an original signed sample.
	last := &reports[len(reports)-1]
	last.ReportedAt = last.Observations[0].ObservedAt - time.Minute.Milliseconds()
	*last, err = SignDeviceReport(*last, fixture.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(reports, func(i, j int) bool {
		left, _ := CanonicalEncode(reports[i])
		right, _ := CanonicalEncode(reports[j])
		return reportBefore(reports[i], left, reports[j], right)
	})
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, reports)
	body := testObservationBytes(t, root)
	for attempt := 0; attempt < 2; attempt++ {
		store, err := OpenObservationStore(root)
		if err != nil {
			t.Fatal(err)
		}
		result, err := store.pathHistory(context.Background(), projection.NetworkID, projection.DeviceAuthorizations[0], route, base.Target, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Buckets) != 24 || result.Buckets[23].Observation == nil || result.Buckets[23].Observation.DurationMS == nil || *result.Buckets[23].Observation.DurationMS != 0 || result.Buckets[22].Observation == nil || result.Buckets[22].Observation.Result != "unavailable" || result.Buckets[22].Observation.DurationMS != nil || result.Buckets[21].Observation == nil {
			t.Fatal("original success, failure, zero duration or expired history lost")
		}
		if !result.Buckets[19].Ambiguous || result.Buckets[19].Observation != nil {
			t.Fatal("same-time conflicting measurements acquired a winner")
		}
		if sample := result.Buckets[16].Observation; sample == nil || sample.ObservedAt != hour.Add(-7*time.Hour+time.Minute).UnixMilli() {
			t.Fatal("report clock adjustment discarded or rewrote an original historical sample")
		}
		for _, index := range []int{20, 18, 17, 0} {
			if result.Buckets[index].Observation != nil {
				t.Fatal("old scope, target, generation, signature, fork or out-of-window sample entered history", index)
			}
		}
		readback := testObservationBytes(t, root)
		if !bytes.Equal(body, readback) {
			t.Fatal("history query or restart changed signed reports")
		}
	}
}
