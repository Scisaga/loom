package loomcore

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"loom/internal/control"
)

func TestAndroidPolicyVisibilityUsesExistingSharedBatchAndOriginalDeadline(t *testing.T) {
	var exitView control.DeviceView
	_, stateBody := androidFixture(t, 7, false, func(p *control.Projection) {
		p.NetworkIntent.Policies[0].AllowDirect = new(false)
		owner := p.DeviceAuthorizations[0]
		owner.ID, owner.Name, owner.Responsibilities, owner.PolicyIDs = "demo-exit", "Demo exit", []string{"internet_egress"}, []string{}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, owner)
		var err error
		exitView, err = control.ProjectDeviceView(*p, owner.ID)
		if err != nil {
			t.Fatal(err)
		}
	})
	probes, err := control.EgressProbes(exitView)
	if err != nil || len(probes) != 1 {
		t.Fatal("fixture has no current exit request", err)
	}
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	sample := control.Observation{Level: "egress", Target: probes[0].Target, Action: "https_request", SpecDigest: probes[0].SpecDigest, NetworkGeneration: "demo-exit-network", Result: "unavailable", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(30 * time.Second).UnixMilli(), DurationMS: new(int64(1))}
	shared := []control.DeviceLinkObservation{{DeviceID: exitView.DeviceID, ReportSequence: 1, ReportDigest: control.ReleaseDigest([]byte("demo-report")), CurrentUntil: sample.ValidUntil, Observation: sample}}
	batch, _ := json.Marshal(shared)
	body, err := HiddenAndroidInternetPolicies(stateBody, batch, at.Add(time.Second).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	var hidden map[string]int64
	if json.Unmarshal(body, &hidden) != nil || hidden["demo-policy"] != sample.ValidUntil {
		t.Fatal("existing batch was not projected with its original expiry")
	}
	// The bridge accepts ordinary strict JSON, not canonical signed bytes.
	// Whitespace keeps one fully valid sample while exercising its byte bound.
	padded := append(bytes.Repeat([]byte(" "), 5<<20), batch...)
	if len(padded) <= 4<<20 || len(padded) >= androidMeasurementSnapshotLimit {
		t.Fatal("fixture does not exercise the received response range")
	}
	if _, err := HiddenAndroidInternetPolicies(stateBody, padded, at.Add(time.Second).UnixMilli()); err != nil {
		t.Fatal("legal received batch was narrowed by the visibility bridge", err)
	}
	runtime, _, err := decodeAndroidRoutingSamples(nil, nil, nil, padded, nil, "demo-network")
	if err != nil || len(runtime.LinkObservations) != 1 || runtime.LinkObservations[0].Validate() != nil {
		t.Fatal("runtime and visibility rejected different shared input sizes", err)
	}
	for _, input := range []struct {
		batch []byte
		now   int64
	}{{[]byte(`[]`), at.UnixMilli()}, {batch, sample.ValidUntil}} {
		body, err = HiddenAndroidInternetPolicies(stateBody, input.batch, input.now)
		hidden = nil
		if err != nil || json.Unmarshal(body, &hidden) != nil || len(hidden) != 0 {
			t.Fatal("unknown or expired evidence stayed hidden", err)
		}
	}
}
