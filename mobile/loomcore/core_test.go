package loomcore

import (
	"bytes"
	"encoding/json"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"testing"
)

func TestRouteInputDiagnosticsDistinguishEmptyAndOversizedProjection(t *testing.T) {
	for _, sample := range []struct {
		body []byte
		want string
	}{
		{nil, "Android route projection: JSON input is empty (0 bytes)"},
		{make([]byte, (1<<20)+1), "Android route projection: JSON input is 1048577 bytes; limit is 1048576 bytes"},
	} {
		_, err := EvaluateAndroidRoutes(sample.body, nil, nil, nil, "demo-generation", "2030-01-01T00:00:00Z", nil, nil, nil, nil)
		if err == nil || err.Error() != sample.want {
			t.Fatal("lost input origin or actual size", err)
		}
	}
}

func testPolicyPreference() ([]byte, error) {
	return control.CanonicalEncode(clientmodel.Preference{Schema: 3, Services: []clientmodel.ServicePreference{{ServiceID: "demo-a", PolicyID: "demo-policy"}, {ServiceID: "demo-b", PolicyID: "demo-policy"}, {ServiceID: "demo-lan", PolicyID: "demo-policy"}, {ServiceID: "demo-service", PolicyID: "demo-policy"}}})
}
func TestAndroidSelectedPolicyKeepsLocalExitIdentity(t *testing.T) {
	routes := []byte(`[{"id":"demo-local","policy_id":"demo-policy","final_exit":"demo-hybrid","chain":[],"scope":"service:demo-service"}]`)
	preference, _ := testPolicyPreference()
	body, err := EvaluateAndroidRoutes(routes, nil, preference, nil, "demo-generation", "2030-01-01T00:00:00Z", nil, nil, nil, []byte(`["service:demo-service"]`))
	var application runtimeApplication
	if err != nil || json.Unmarshal(body, &application) != nil || len(application.Selections) != 1 || application.Selections[0].FinalExit != "demo-hybrid" || len(application.Selections[0].Chain) != 0 {
		t.Fatal("local exit identity was lost", string(body), err)
	}
}
func TestAndroidPolicyChoiceAndServiceFailureStayIndependent(t *testing.T) {
	routes := []byte(`[{"id":"demo-a","policy_id":"demo-policy","final_exit":"direct","chain":[],"scope":"service:demo-a"},{"id":"demo-b","policy_id":"demo-policy","final_exit":"demo-exit","chain":["demo-exit"],"scope":"service:demo-b"},{"id":"demo-other-policy","policy_id":"demo-other-policy","final_exit":"direct","chain":[],"scope":"service:demo-b"}]`)
	samples := []byte(`[{"candidate_id":"demo-b","network_generation":"demo-network","scope":"service:demo-b","result":"unavailable","action":"https_request","target":"https://demo-b.example/","observed_at":"2030-01-01T00:00:00Z","valid_until":"2030-01-01T00:00:30Z"}]`)
	preference, _ := testPolicyPreference()
	scopes := []byte(`["service:demo-a","service:demo-b","service:demo-pending"]`)
	targets := []byte(`[{"service_id":"demo-b","targets":["https://demo-b.example/"]}]`)
	body, err := EvaluateAndroidRoutes(routes, samples, preference, nil, "demo-network", "2030-01-01T00:00:01Z", targets, nil, nil, scopes)
	var application runtimeApplication
	if err != nil || json.Unmarshal(body, &application) != nil || len(application.Selections) != 1 || application.Selections[0].Candidate != "demo-a" || len(application.BlockedScopes) != 2 {
		t.Fatal("failed/pending Service borrowed a different policy", string(body), err)
	}
	for _, bad := range [][]byte{[]byte(`{"mode":"auto","schema":3}`), []byte(`{"schema":3,"services":null}`), []byte(`{"schema":3,"services":[{"policy_id":"","service_id":"demo-a"}]}`)} {
		if _, err := EvaluateAndroidRoutes(routes, nil, bad, nil, "demo-network", "2030-01-01T00:00:01Z", nil, nil, nil, scopes); err == nil {
			t.Fatal("noncanonical or old preference accepted")
		}
	}
	if !bytes.Contains(body, []byte(`"policy_choices"`)) {
		t.Fatal("local choices were not projected")
	}
}
