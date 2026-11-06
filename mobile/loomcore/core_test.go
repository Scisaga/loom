package loomcore

import (
	"bytes"
	"encoding/json"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"testing"
	"time"
)

func TestRouteInputDiagnosticsDistinguishEmptyAndOversizedProjection(t *testing.T) {
	for _, sample := range []struct {
		body []byte
		want string
	}{
		{nil, "Android route projection: JSON input is empty (0 bytes)"},
		{make([]byte, (1<<20)+1), "Android route projection: JSON input is 1048577 bytes; limit is 1048576 bytes"},
	} {
		_, err := evaluateTestRoutes(sample.body, nil, nil, nil, "demo-generation", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli(), nil, nil, nil, nil, nil, 0, nil)
		if err == nil || err.Error() != sample.want {
			t.Fatal("lost input origin or actual size", err)
		}
	}
}

func testPolicyPreference() ([]byte, error) {
	return control.CanonicalEncode(clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"})
}
func TestAndroidSelectedPolicyKeepsLocalExitIdentity(t *testing.T) {
	routes := []byte(`[{"id":"demo-local","policy_id":"demo-policy","final_exit":"demo-hybrid","chain":[],"scope":"service:demo-service"}]`)
	preference, _ := testPolicyPreference()
	body, err := evaluateTestRoutes(routes, nil, preference, nil, "demo-generation", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli(), nil, nil, nil, []byte(`["access"]`), nil, 0, nil)
	var application runtimeApplication
	if err != nil || json.Unmarshal(body, &application) != nil || len(application.Selections) != 1 || application.Selections[0].FinalExit != "demo-hybrid" || len(application.Selections[0].Chain) != 0 {
		t.Fatal("local exit identity was lost", string(body), err)
	}
}
func TestAndroidOneSelectedPolicyDeterminesServiceAndNeverBorrowsAnotherPolicy(t *testing.T) {
	routes := []byte(`[{"id":"demo-a","policy_id":"demo-policy","final_exit":"direct","chain":[],"scope":"service:demo-a"},{"id":"demo-b","policy_id":"demo-other-policy","final_exit":"demo-exit","chain":["demo-exit"],"scope":"service:demo-b"}]`)
	preference, _ := testPolicyPreference()
	body, err := evaluateTestRoutes(routes, nil, preference, nil, "demo-network", time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC).UnixMilli(), nil, nil, nil, []byte(`["access"]`), nil, 0, nil)
	var application runtimeApplication
	if err != nil || json.Unmarshal(body, &application) != nil || len(application.Selections) != 1 || application.Selections[0].Candidate != "demo-a" || application.PolicyID != "demo-policy" || application.ServiceID != "demo-a" || len(application.BlockedScopes) != 0 {
		t.Fatal("one current Policy did not determine Service", string(body), err)
	}
	for _, bad := range [][]byte{[]byte(`{"mode":"auto","schema":3}`), []byte(`{"schema":3,"services":null}`), []byte(`{"schema":3,"services":[{"policy_id":"","service_id":"demo-a"}]}`)} {
		if _, err := evaluateTestRoutes(routes, nil, bad, nil, "demo-network", time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC).UnixMilli(), nil, nil, nil, []byte(`["access"]`), nil, 0, nil); err == nil {
			t.Fatal("old preference entered current routing")
		}
	}
	if bytes.Contains(body, []byte(`"policy_choices"`)) {
		t.Fatal("old concurrent Service choices were projected")
	}
	pending, _ := control.CanonicalEncode(clientmodel.EmptyPreference())
	body, err = evaluateTestRoutes(routes, nil, pending, nil, "demo-network", time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC).UnixMilli(), nil, nil, nil, []byte(`["access"]`), nil, 0, nil)
	if err != nil || json.Unmarshal(body, &application) != nil || len(application.BlockedScopes) != 1 || len(application.Selections) != 0 {
		t.Fatal("pending selection granted Internet", string(body), err)
	}
}
