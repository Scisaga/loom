package control

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWebRuntimeHistoryReadsOriginalHourlySamples(t *testing.T) {
	fixture, _, projection := deviceContractFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := DeviceViewDigest(view)
	now := time.Date(2026, 1, 2, 12, 30, 0, 0, time.UTC)
	hour := now.Truncate(time.Hour)
	reports := []DeviceReport{}
	add := func(at time.Time, state string) {
		t.Helper()
		report := DeviceReport{Schema: 3, NetworkID: projection.NetworkID, DeviceID: view.DeviceID, ReportSequence: U64(len(reports) + 1), ViewDigest: digest,
			NetworkGeneration: "demo-network", ReportedAt: at.UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{},
			Runtime: RuntimeReadback{State: state, AppliedViewDigest: digest}, Components: []ComponentReadback{}}
		report, err = SignDeviceReport(report, fixture.keys[0])
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	resignLast := func() {
		t.Helper()
		reports[len(reports)-1], err = SignDeviceReport(reports[len(reports)-1], fixture.keys[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	add(now, "running")
	add(hour.Add(-time.Hour), "error")
	add(hour.Add(-time.Hour+time.Minute), "stopped")
	add(hour.Add(-2*time.Hour), "unknown")
	add(hour.Add(-3*time.Hour+time.Minute), "running")
	add(hour.Add(-3*time.Hour), "error") // Clock rollback: sequence does not rewrite the hour's latest time.
	add(hour.Add(-4*time.Hour), "stopped")
	add(hour.Add(-4*time.Hour), "error") // Equal timestamp: the later signed report wins.
	add(hour.Add(-5*time.Hour), "running")
	fork := reports[len(reports)-1]
	fork.Runtime.State = "error"
	fork, err = SignDeviceReport(fork, fixture.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	reports = append(reports, fork)
	add(hour.Add(-6*time.Hour), "running")
	reports[len(reports)-1], err = SignDeviceReport(reports[len(reports)-1], fixture.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	add(hour.Add(-7*time.Hour), "running")
	oldView := "sha256:" + strings.Repeat("e", 64)
	reports[len(reports)-1].ViewDigest = oldView
	reports[len(reports)-1].Runtime.AppliedViewDigest = oldView
	resignLast()
	add(hour.Add(-23*time.Hour), "stopped") // Exact inclusive start.
	add(hour.Add(-24*time.Hour), "running")
	add(now.Add(time.Millisecond), "error") // No future grace for historical samples.
	add(hour.Add(-8*time.Hour), "running")
	reports[len(reports)-1].NetworkID = "demo-other-network"
	resignLast()
	add(hour.Add(-9*time.Hour), "running")
	reports[len(reports)-1].DeviceID = "demo-other-device"
	resignLast()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, reports)
	original := testObservationBytes(t, root)
	var previous WebRuntimeHistory
	for attempt := 0; attempt < 2; attempt++ {
		store, err := testOpenObservationStore(t, root)
		if err != nil {
			t.Fatal(err)
		}
		result, err := store.runtimeHistory(context.Background(), projection.NetworkID, view.DeviceID, projection.DeviceAuthorizations[0].DevicePublicKey, now)
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			store.cache.clear()
			cold, err := store.runtimeHistory(context.Background(), projection.NetworkID, view.DeviceID, projection.DeviceAuthorizations[0].DevicePublicKey, now)
			if err != nil || !reflect.DeepEqual(cold, result) {
				t.Fatal("discarding the report index changed historical samples", err)
			}
		}
		if len(result.Buckets) != 24 || result.From != hour.Add(-23*time.Hour).UnixMilli() || result.Until != now.UnixMilli() {
			t.Fatal("history did not preserve the requested UTC window")
		}
		for index, state := range map[int]string{23: "running", 22: "stopped", 21: "unknown", 20: "running", 19: "error", 16: "running", 0: "stopped"} {
			sample := result.Buckets[index].Sample
			if sample == nil || sample.State != state {
				t.Fatal("wrong original runtime sample", index, sample)
			}
			matched := false
			for _, report := range reports {
				encoded, _ := CanonicalEncode(report)
				if ReleaseDigest(encoded) == sample.ReportID {
					matched = sample.ReportSequence == report.ReportSequence && sample.ReportedAt == report.ReportedAt && sample.ViewDigest == report.ViewDigest && sample.AppliedViewDigest == report.Runtime.AppliedViewDigest && sample.ErrorCode == report.Runtime.ErrorCode
				}
			}
			if !matched {
				t.Fatal("hour sample did not match original signed bytes")
			}
		}
		if result.Buckets[16].Sample.ViewDigest != oldView || result.Buckets[19].Sample.ReportSequence != reports[7].ReportSequence {
			t.Fatal("historical View or equal-time sequence ordering was lost")
		}
		for _, index := range []int{18, 17, 15, 14, 1} {
			if result.Buckets[index].Sample != nil {
				t.Fatal("fork, invalid signature, other identity or missing sample acquired a runtime state", index)
			}
		}
		if attempt > 0 && !reflect.DeepEqual(previous, result) || !bytes.Equal(original, testObservationBytes(t, store)) {
			t.Fatal("reopen changed original reports or their historical projection")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		previous = result
	}
}
