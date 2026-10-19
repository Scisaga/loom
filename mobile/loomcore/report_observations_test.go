package loomcore

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"loom/internal/control"
)

func TestAndroidReportFiltersAllCandidatesAtFixedMillisecondTime(t *testing.T) {
	_, body := androidFixture(t, 7, false, func(p *control.Projection) {
		p.DeviceAuthorizations[0].Responsibilities = []string{"access", "internet_egress"}
		p.NetworkIntent.Policies[0].LocalEgressDevices = new([]string{p.DeviceAuthorizations[0].ID})
		p.NetworkIntent.BusinessProbeTargets = append(p.NetworkIntent.BusinessProbeTargets, control.BusinessProbeTarget{ID: "demo-other-probe", URL: "https://demo.example:8443/other"})
	})
	reserved, err := ReserveAndroidReportSequence(body)
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeState(reserved)
	if err != nil || len(state.LKG.View.Routes) != 2 {
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
		route := state.LKG.View.Routes[row.route]
		values = append(values, androidObservation{CandidateID: route.ID, Scope: route.Scope, Target: row.target, Action: "https_request", NetworkGeneration: "demo-underlay", Result: row.result,
			ObservedAt: row.observed.Format(time.RFC3339), ValidUntil: row.until.Format(time.RFC3339)})
	}
	observations, _ := json.Marshal(values)
	selections, _ := json.Marshal([]androidSelection{{Scope: state.LKG.View.Routes[0].Scope, CandidateID: state.LKG.View.Routes[0].ID}})
	runtime, _ := json.Marshal(control.RuntimeReadback{State: "running", AppliedViewDigest: state.LKG.ViewDigest})
	report, err := androidReport(state, nil, nil, observations, selections, runtime, []byte("[]"), nil, "demo-underlay", at.Format(androidReportTimeLayout))
	if err != nil || len(report.Observations) != 2 || report.ReportedAt != at.UnixMilli() || report.Verify(state.PublicKey) != nil {
		t.Fatal("Android report lost current candidate observations or millisecond time", err)
	}
	byID := map[string]string{}
	for _, value := range report.Observations {
		byID[value.CandidateID] = value.Result
	}
	if byID[state.LKG.View.Routes[0].ID] != "available" || byID[state.LKG.View.Routes[1].ID] != "unknown" {
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
