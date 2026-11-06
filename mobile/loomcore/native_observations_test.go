package loomcore

import (
	"encoding/json"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

func TestAndroidRecoveryCompletionUsesOriginalPendingAndBinding(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	currentID, alternative := control.ReleaseDigest([]byte("demo-current")), control.ReleaseDigest([]byte("demo-alternative"))
	actual := clientmodel.Selection{Scope: "access", PolicyID: "demo-policy", CandidateID: currentID, Revision: "demo-revision", Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{currentID: {EntryNodeID: "demo-entry", FirstResourceID: "demo-resource", FinalExit: "demo-exit"}}}
	memory := clientmodel.SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-network", NativeBinding: &clientmodel.NativeBinding{Revision: actual.Revision, NetworkGeneration: "demo-network", ExecutionSpec: "demo-spec"}, Decisions: map[string]clientmodel.SelectionDecision{"": {Current: currentID}, "tcp://web.example:443": {Current: currentID, Pending: alternative, CalibrateTCP: true, Confirmations: 2}}}
	sample := clientmodel.Observation{CandidateID: alternative, Scope: "access", Target: "web.example:443", Action: "tcp_calibration", NetworkGeneration: "demo-network", Result: "available", ObservedAt: at.Format(time.RFC3339Nano), ValidUntil: at.Add(time.Minute).Format(time.RFC3339Nano), MetricMillis: 1}
	batch, _ := json.Marshal([]clientmodel.Observation{sample})
	for _, scenario := range []string{"current request", "different pending", "superseded revision"} {
		t.Run(scenario, func(t *testing.T) {
			current := actual
			copyMemory := memory
			if scenario == "different pending" {
				copyMemory.Decisions = map[string]clientmodel.SelectionDecision{"": {Current: currentID}}
			}
			if scenario == "superseded revision" {
				current.Revision = "demo-new-revision"
			}
			currentBody, _ := json.Marshal(map[string]clientmodel.Selection{"access": current})
			memoryBody, _ := json.Marshal(map[string]clientmodel.SelectionMemory{"access": copyMemory})
			body, err := MergeAndroidTCPRecoveryObservations(currentBody, memoryBody, []byte(`[]`), batch, "demo-network", at.Add(time.Second).UnixMilli())
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Observations []clientmodel.Observation              `json:"native_observations"`
				Memory       map[string]clientmodel.SelectionMemory `json:"memory"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
			if scenario == "current request" {
				if len(result.Observations) != 1 || result.Observations[0] != sample || result.Memory["access"].NativeHealthUntil != at.Add(time.Minute).UnixMilli() {
					t.Fatal("original allowed calibration was lost or renewed")
				}
			} else if len(result.Observations) != 0 {
				t.Fatal("a superseded request supplied current target health")
			}
		})
	}
}

func TestAndroidNativeBindingQuickConsumptionAndSamePathNetworkChange(t *testing.T) {
	_, identity := androidFixture(t, 7, false)
	chosen, err := ChooseAndroidPolicy(identity, "demo-policy")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	body, err := EvaluateAndroidRoutes(chosen, nil, nil, "demo-network", at.UnixMilli(), nil, nil, nil, 1000, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var application runtimeApplication
	if err := json.Unmarshal(body, &application); err != nil {
		t.Fatal(err)
	}
	if len(application.Selections) != 1 || !application.Selections[0].ForceCAS {
		t.Fatal("startup did not require a confirmed binding")
	}
	selected := application.Selections[0]
	actual := clientmodel.Selection{Scope: selected.Selector, PolicyID: selected.PolicyID, CandidateID: selected.Candidate, Choices: selected.Choices, Targets: selected.Targets, Revision: "demo-revision"}
	actualBody, _ := json.Marshal(actual)
	memory, _ := json.Marshal(application.Memory)
	confirmed, err := ConfirmAndroidSelectionMemory(memory, actualBody, 1000)
	if err != nil {
		t.Fatal(err)
	}
	currentBody, _ := json.Marshal(map[string]clientmodel.Selection{actual.Scope: actual})
	events, _ := json.Marshal(map[string]any{"observations": []any{map[string]any{"revision": actual.Revision, "policy_id": actual.PolicyID, "candidate_id": actual.CandidateID, "target": "demo.example:443", "result": "available", "started_at": at.UnixMilli() + 100, "observed_at": at.UnixMilli() + 200}}})
	quick, err := RefreshAndroidNativeObservations(currentBody, confirmed, []byte(`[]`), events, "demo-network", at.UnixMilli()+1000)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Observations []clientmodel.Observation `json:"native_observations"`
		NeedsRouting bool                      `json:"needs_routing"`
		Bound        bool                      `json:"binding_current"`
	}
	if err := json.Unmarshal(quick, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Bound || !result.NeedsRouting || len(result.Observations) != 1 || result.Observations[0].Action != "tcp_connect" {
		t.Fatal("quick path did not consume the original pinned result")
	}
	nativeBody, _ := json.Marshal(result.Observations)
	quick, err = RefreshAndroidNativeObservations(currentBody, confirmed, nativeBody, events, "demo-network", at.UnixMilli()+2000)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(quick, &result) != nil || result.NeedsRouting {
		t.Fatal("unchanged local result reran routing")
	}
	body, err = EvaluateAndroidRoutes(chosen, nil, currentBody, "demo-network", at.UnixMilli()+2000, nil, nil, confirmed, 3000, nativeBody, events)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(body, &application) != nil || application.Selections[0].ForceCAS {
		t.Fatal("confirmed unchanged binding was treated as a new execution")
	}
	body, err = EvaluateAndroidRoutes(chosen, nil, currentBody, "demo-other-network", at.UnixMilli()+3000, nil, nil, confirmed, 4000, nativeBody, events)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(body, &application) != nil || !application.Selections[0].ForceCAS || len(application.NativeObservations) != 0 {
		t.Fatal("same-path network change reused old native events")
	}
}
