package loomcore

import (
	"encoding/json"
	"loom/internal/control"
	"testing"
)

func TestAndroidMeasurementHintsRequireNetworkScopedTargetKeys(t *testing.T) {
	state, _ := androidFixture(t, 7, false)
	execution := testDeviceExecution(state.LKG.View)
	if len(execution.Routes) == 0 {
		t.Fatal("fixture has no selected route")
	}
	route := execution.Routes[0]
	for _, target := range []string{"tcp://demo.example:443", "udp://demo.example:443", "demo.example:443"} {
		body, _ := json.Marshal([]androidSelection{{Scope: control.AccessSelectorScope, CandidateID: route.ID, Targets: map[string]string{target: route.ID}}})
		_, err := androidSelectedCandidates(execution, body, nil, "demo-network")
		if (target == "demo.example:443") != (err != nil) {
			t.Fatal("runtime measurement hint target lost its network boundary", target, err)
		}
	}
}
