package loomcore

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestAndroidReportFiltersAllCandidatesAtFixedMillisecondTime(t *testing.T) {
	_, body := androidFixture(t, 7, false, func(p *control.Projection) {
		p.DeviceAuthorizations[0].Responsibilities = []string{"access", "internet_egress"}
		p.NetworkIntent.Policies[0].LocalEgressDevices = new([]string{p.DeviceAuthorizations[0].ID})
		p.NetworkIntent.Services[0].ProbeURLs = append(p.NetworkIntent.Services[0].ProbeURLs, "https://demo.example:8443/other")
	})
	reserved, err := ReserveAndroidReportSequence(body)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeState(reserved)
	if err != nil || len(testDeviceExecution(state.LKG.View).Routes) != 2 {
		t.Fatal("fixture needs two candidates", err)
	}
	at := time.Date(2030, 1, 1, 0, 1, 0, 120_000_000, time.UTC)
	values := []androidObservation{}
	for _, row := range []struct {
		route           int
		target, result  string
		observed, until time.Time
	}{
		{0, "https://demo.example:8443/health", "available", at.Add(-time.Second), at.Add(time.Minute)},
		{1, "https://demo.example:8443/health", "unknown", at.Add(-time.Second), at.Add(time.Minute)},
		{0, "https://demo.example:8443/other", "unavailable", at.Add(-time.Minute), at.Truncate(time.Second)},
		{1, "https://demo.example:8443/other", "available", at.Add(time.Second), at.Add(time.Minute)},
	} {
		route := testDeviceExecution(state.LKG.View).Routes[row.route]
		values = append(values, androidObservation{CandidateID: route.ID, Scope: control.AccessSelectorScope, Target: row.target, Action: "https_request", NetworkGeneration: "demo-underlay", Result: row.result,
			ObservedAt: row.observed.Format(time.RFC3339), ValidUntil: row.until.Format(time.RFC3339)})
	}
	observations, _ := json.Marshal(values)
	selections, _ := json.Marshal([]androidSelection{{Scope: control.AccessSelectorScope, CandidateID: testDeviceExecution(state.LKG.View).Routes[0].ID}})
	runtime, _ := json.Marshal(control.RuntimeReadback{State: "running", AppliedViewDigest: state.LKG.ViewDigest})
	report, err := androidReport(state, nil, nil, observations, selections, runtime, []byte("[]"), nil, "demo-underlay", at.Format(androidReportTimeLayout))
	if err != nil || len(report.Observations) != 2 || report.ReportedAt != at.UnixMilli() || report.Verify(state.PublicKey) != nil {
		t.Fatal("Android report lost current candidate observations or millisecond time", err)
	}
	byID := map[string]string{}
	for _, value := range report.Observations {
		byID[value.CandidateID] = value.Result
	}
	if byID[testDeviceExecution(state.LKG.View).Routes[0].ID] != "available" || byID[testDeviceExecution(state.LKG.View).Routes[1].ID] != "unknown" {
		t.Fatal("nonselected result was omitted")
	}
	after, _ := json.Marshal(values)
	if !reflect.DeepEqual(after, observations) {
		t.Fatal("report changed local candidate evidence")
	}
	expired := values[2]
	for _, invalid := range [][]androidObservation{{expired, expired}, func() []androidObservation {
		value := expired
		value.Result = "invalid"
		return []androidObservation{value}
	}()} {
		input, _ := json.Marshal(invalid)
		if _, err := androidReport(state, nil, nil, input, selections, runtime, []byte("[]"), nil, "demo-underlay", at.Format(androidReportTimeLayout)); err == nil {
			t.Fatal("expired malformed or duplicate input was silently removed")
		}
	}
	for _, value := range []string{"2030-01-01T00:01:00Z", "2030-01-01T00:01:00.12Z", "2030-01-01T00:01:00.1200Z", "2030-01-01T00:01:00.120+00:00"} {
		if _, err := androidReport(state, nil, nil, []byte("[]"), []byte("[]"), runtime, []byte("[]"), nil, "demo-underlay", value); err == nil {
			t.Fatal("noncanonical internal bridge time accepted", value)
		}
	}
	for _, value := range []string{"2030-01-01T00:01:00.000Z", "2030-01-01T00:01:00.120Z", "2030-01-01T00:01:00.123Z"} {
		report, err := androidReport(state, nil, nil, []byte("[]"), []byte("[]"), runtime, []byte("[]"), nil, "demo-underlay", value)
		timestamp, _ := time.Parse(androidReportTimeLayout, value)
		if err != nil || report.ReportedAt != timestamp.UnixMilli() {
			t.Fatal("fixed bridge milliseconds were lost", value, err)
		}
	}
}

func TestAndroidPartialResourcesReportOnlyIndependentMeasurements(t *testing.T) {
	_, body := androidFixture(t, 7, false, func(p *control.Projection) {
		owner := p.DeviceAuthorizations[0]
		owner.ID, owner.Platform, owner.Responsibilities, owner.PolicyIDs = "demo-exit", "linux", []string{"internet_egress"}, []string{}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, owner)
		for i := range p.DeviceAuthorizations {
			public, err := control.DerivedWireGuardPublicKey(p.NetworkID, p.DeviceAuthorizations[i])
			if err != nil {
				t.Fatal(err)
			}
			p.DeviceAuthorizations[i].WireGuardPublicKey = public
		}
		public := p.DeviceAuthorizations[1].WireGuardPublicKey
		addresses := []string{"192.0.2.10/32"}
		p.NetworkIntent.Resources = []control.TransportResource{{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: "demo-exit", ListenerID: "demo-wg", DialHost: "192.0.2.10", DialPort: 51820, AccessEnabled: true, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: &addresses}}}
	})
	reserved, err := ReserveAndroidReportSequence(body)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeState(reserved)
	if err != nil {
		t.Fatal(err)
	}
	probes, err := control.FirstHopProbes(testDeviceExecution(state.LKG.View))
	if err != nil || len(probes) == 0 {
		t.Fatal("fixture needs a qualified resource", err)
	}
	at := time.Date(2030, 1, 1, 0, 1, 0, 120_000_000, time.UTC)
	probe := probes[0]
	sample := control.Observation{Level: "resource", ResourceID: probe.Resource.ID, Target: probe.Target(), Action: probe.Action(), SpecDigest: probe.SpecDigest, NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: at.Add(-time.Second).UnixMilli(), ValidUntil: at.Add(time.Minute).UnixMilli(), RoundTripMS: new(int64(2)), DurationMS: new(int64(4))}
	cache, err := clientadapter.EncodeResourceObservations(*state.LKG, []control.Observation{sample}, testPolicyIDs(state.LKG.View))
	if err != nil {
		t.Fatal(err)
	}
	runtime := control.RuntimeReadback{State: "unknown", PermissionViewDigest: state.LKG.ViewDigest}
	runtimeBody, _ := json.Marshal(runtime)
	report, err := androidReport(state, nil, cache, []byte(`[]`), []byte(`[]`), runtimeBody, []byte(`[]`), nil, "demo-underlay", at.Format(androidReportTimeLayout))
	if err != nil || report.Verify(state.PublicKey) != nil || len(report.Observations) != 1 || report.Observations[0].ObservedAt != sample.ObservedAt || report.Observations[0].ValidUntil != sample.ValidUntil || report.Runtime.AppliedViewDigest != "" || report.Runtime.Resources != nil || len(report.Selections) != 0 {
		t.Fatal("partial execution lost independent original measurement or claimed full application", err)
	}
	runtime.PermissionViewDigest = ""
	unknown, _ := json.Marshal(runtime)
	if _, err := androidReport(state, nil, cache, []byte(`[]`), []byte(`[]`), unknown, []byte(`[]`), nil, "demo-underlay", at.Format(androidReportTimeLayout)); err == nil {
		t.Fatal("unconfirmed permissions published independent samples")
	}
	route := testDeviceExecution(state.LKG.View).Routes[0]
	selections, _ := json.Marshal([]androidSelection{{Scope: control.AccessSelectorScope, CandidateID: route.ID}})
	partial, err := androidReport(state, nil, cache, []byte(`[]`), selections, runtimeBody, []byte(`[]`), nil, "demo-underlay", at.Format(androidReportTimeLayout))
	if err != nil || len(partial.Selections) != 1 || partial.Selections[0].CandidateID != route.ID || partial.Runtime.State != "unknown" || partial.Runtime.AppliedViewDigest != "" || len(partial.Observations) != 1 || partial.Verify(state.PublicKey) != nil {
		t.Fatal("independent measurements or host-confirmed scope were lost while another scope was pending", err)
	}
	business, _ := json.Marshal([]androidObservation{{CandidateID: route.ID, Scope: control.AccessSelectorScope, Target: "https://demo.example:8443/health", Action: "https_request", NetworkGeneration: "demo-underlay", Result: "available",
		ObservedAt: at.Add(-time.Second).Format(time.RFC3339), ValidUntil: at.Add(time.Minute).Format(time.RFC3339)}})
	if _, err := androidReport(state, nil, cache, business, selections, runtimeBody, []byte(`[]`), nil, "demo-underlay", at.Format(androidReportTimeLayout)); err == nil {
		t.Fatal("a partial scope report claimed fully applied business samples")
	}
}
