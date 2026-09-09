package loomcore

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAndroidRoutingInputsUseActualOutboundDetours(t *testing.T) {
	planBody, preparedBody := androidRouteFixture(t)
	var plan androidRoutePlan
	if err := json.Unmarshal(planBody, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Declarations = []androidRouteDeclaration{{
		ID: "auto", Selector: "decl:auto", Objective: "latency", Targets: []string{"https://target.example/"},
		TuningPeriod: "1m", SwitchThreshold: 0.2, Window: "1h", MinSamples: 2, StaleAfter: "10m",
		Candidates: plan.Selectors[0].Candidates,
	}}
	planBody, err := marshalCanonical(&plan)
	if err != nil {
		t.Fatal(err)
	}
	var prepared preparedAndroidRuntime
	if err := json.Unmarshal(preparedBody, &prepared); err != nil {
		t.Fatal(err)
	}
	body, err := AndroidRoutingInputs([]byte(prepared.SingBoxConfig), planBody)
	if err != nil {
		t.Fatal(err)
	}
	var inputs androidRoutingInputs
	if err := json.Unmarshal(body, &inputs); err != nil {
		t.Fatal(err)
	}
	if inputs.Schema != 1 || len(inputs.Entries) != 1 || inputs.Entries[0].Node != "relay-a" ||
		inputs.Entries[0].Address != "relay.example" {
		t.Fatalf("routing inputs=%+v", inputs)
	}
	if got := inputs.HopCarriers["opaque-a-via"]; len(got) != 1 || got[0] != "neighbor" {
		t.Fatalf("opaque-a-via carriers=%v", got)
	}
}

func TestRunAndroidRouteTickUsesEntryAndMarksBusinessUnmeasured(t *testing.T) {
	planBody, preparedBody := androidRouteFixture(t)
	var plan androidRoutePlan
	if err := json.Unmarshal(planBody, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Declarations = []androidRouteDeclaration{{
		ID: "auto", Selector: "decl:auto", Objective: "latency", Targets: []string{"https://target.example/"},
		TuningPeriod: "1m", SwitchThreshold: 0.2, Window: "1h", MinSamples: 2, StaleAfter: "10m",
		Candidates: plan.Selectors[0].Candidates,
	}}
	planBody, err := marshalCanonical(&plan)
	if err != nil {
		t.Fatal(err)
	}
	var prepared preparedAndroidRuntime
	if err := json.Unmarshal(preparedBody, &prepared); err != nil {
		t.Fatal(err)
	}
	inputs, err := AndroidRoutingInputs([]byte(prepared.SingBoxConfig), planBody)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	actual := []byte(`{"schema":1,"plan_scope":"PLACEHOLDER","selections":[{"selector":"decl:auto","candidate":"opaque-a-via"},{"selector":"svc:web","candidate":"opaque-b-via"}]}`)
	application, err := EvaluateAndroidRoute(planBody, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var selected androidRouteApplication
	if err := json.Unmarshal(application, &selected); err != nil {
		t.Fatal(err)
	}
	actual = []byte(strings.Replace(string(actual), "PLACEHOLDER", selected.PlanScope, 1))
	entries := []byte(`{"schema":1,"source":"wlan0","measurements":[{"node":"relay-a","address":"relay.example","ts":"2026-09-08T12:00:00Z","rtt_ms":31}]}`)

	resultBody, err := RunAndroidRouteTick(planBody, nil, nil, inputs, actual, entries, nil, []byte(`[{"node":"outside"}]`), nil, now.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	var result androidRouteTick
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatal(err)
	}
	if result.Schema != 2 || result.Changed || len(result.Decisions) != 1 ||
		!strings.Contains(result.Decisions[0].Reason, "单次 ping 31 ms") ||
		!strings.Contains(result.Decisions[0].Reason, "未测整条业务路径") || result.ObservationError == "" {
		t.Fatalf("route tick=%+v", result)
	}
	measurements := result.Decisions[0].Measurements
	if len(measurements) != 3 || measurements[0].Kind != "entry" || measurements[0].DelayMS == nil ||
		*measurements[0].DelayMS != 31 || measurements[1].Kind != "neighbor" || measurements[1].DelayMS != nil ||
		measurements[2].Kind != "target" || measurements[2].DelayMS != nil {
		t.Fatalf("structured path measurements=%+v", measurements)
	}
	var state androidScheduleState
	if err := json.Unmarshal([]byte(result.State), &state); err != nil || state.Schema != 2 || len(state.Observations) != 0 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestRunAndroidRouteTickDirectNeverRequiresEntryEvidence(t *testing.T) {
	planBody, preparedBody := androidRouteFixture(t)
	var prepared preparedAndroidRuntime
	if err := json.Unmarshal(preparedBody, &prepared); err != nil {
		t.Fatal(err)
	}
	inputs, err := AndroidRoutingInputs([]byte(prepared.SingBoxConfig), planBody)
	if err != nil {
		t.Fatal(err)
	}
	applicationBody, err := EvaluateAndroidRoute(planBody, []byte(`{"schema":1,"mode":"direct"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	var application androidRouteApplication
	if err := json.Unmarshal(applicationBody, &application); err != nil {
		t.Fatal(err)
	}
	actual, err := marshalCanonical(&androidSavedSelections{
		Schema: 1, PlanScope: application.PlanScope,
		Selections: []androidSavedSelection{{Selector: "decl:auto", Candidate: "opaque-a-direct"}, {Selector: "svc:web", Candidate: "opaque-b-direct"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resultBody, err := RunAndroidRouteTick(planBody, []byte(`{"schema":1,"mode":"direct"}`), nil,
		inputs, actual, []byte(`{"schema":1}`), []byte(`{"schema":1,"plan_scope":"legacy","measurements":[]}`), nil, nil,
		time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	var result androidRouteTick
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Application.Mode != androidRouteModeDirect {
		t.Fatalf("direct tick=%+v", result)
	}
}

func TestAndroidEntryMeasurementsRejectUnknownTarget(t *testing.T) {
	inputs := androidRoutingInputs{Schema: 1, Entries: []androidRouteEntry{{Node: "entry-a", Address: "entry.example"}}, HopCarriers: map[string][]string{}}
	_, err := loadAndroidEntryMeasurements(
		[]byte(`{"schema":1,"measurements":[{"node":"entry-b","address":"other.example","ts":"2026-09-08T12:00:00Z","rtt_ms":1}]}`),
		inputs,
		time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
	)
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("unknown entry error=%v", err)
	}
}
