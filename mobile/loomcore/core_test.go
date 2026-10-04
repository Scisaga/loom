package loomcore

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAndroidLocalExitKeepsItsIdentityAndDoesNotOfferDirect(t *testing.T) {
	routes := []byte(`[{"id":"demo-local","final_exit":"demo-hybrid","chain":[],"scope":"service:demo-service"}]`)
	for _, mode := range []string{"auto", "fixed_exit", "direct"} {
		exit := ""
		if mode == "fixed_exit" {
			exit = "demo-hybrid"
		}
		preference, err := NewAndroidPreference(mode, exit)
		if err != nil {
			t.Fatal(err)
		}
		body, err := EvaluateAndroidRoutes(routes, nil, preference, nil, "demo-generation", "2030-01-01T00:00:00Z")
		if mode == "direct" {
			if err == nil {
				t.Fatal("Direct selected a local exit")
			}
			continue
		}
		var application runtimeApplication
		if err != nil || json.Unmarshal(body, &application) != nil || application.DirectAvailable || len(application.Exits) != 1 || application.Exits[0] != "demo-hybrid" || len(application.Selections) != 1 || application.Selections[0].FinalExit != "demo-hybrid" || len(application.Selections[0].Chain) != 0 {
			t.Fatalf("local exit presentation for %s: %s, %v", mode, body, err)
		}
	}
}

func TestEvaluateAndroidRoutesUsesOneSharedModel(t *testing.T) {
	routes := []byte(`[{"id":"direct","final_exit":"direct","chain":[],"scope":"default"},{"id":"exit-a-direct","final_exit":"exit-a","chain":["exit-a"],"scope":"default"},{"id":"exit-a-relay","final_exit":"exit-a","chain":["relay-a","exit-a"],"scope":"default"}]`)
	preference, err := NewAndroidPreference("fixed_exit", "exit-a")
	if err != nil {
		t.Fatal(err)
	}
	observations := []byte(`[{"candidate_id":"exit-a-direct","network_generation":"net-a","scope":"default","result":"unavailable","action":"dns_https","observed_at":"2030-01-01T00:00:00Z","valid_until":"2030-01-01T00:10:00Z"},{"candidate_id":"exit-a-relay","network_generation":"net-a","scope":"default","result":"available","action":"dns_https","observed_at":"2030-01-01T00:00:00Z","valid_until":"2030-01-01T00:10:00Z","metric_millis":5}]`)
	result, err := EvaluateAndroidRoutes(routes, observations, preference, nil, "net-a", "2030-01-01T00:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(result, []byte(`"candidate":"exit-a-relay"`)) {
		t.Fatalf("unexpected result %s", result)
	}
}

func TestAndroidDenyOnlySelectionAndCanonicalPreference(t *testing.T) {
	preference, err := NewAndroidPreference("auto", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := EvaluateAndroidRoutes([]byte("[]"), []byte("[]"), preference, nil, "demo-network-generation", "2030-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(result, []byte(`"selections":[]`)) {
		t.Fatal("deny-only configuration did not return an empty actual selection set")
	}
	for _, bad := range [][]byte{[]byte(`{"mode":"auto","schema":1}`), []byte(`{"schema":3,"mode":"auto"}`)} {
		if _, err := EvaluateAndroidRoutes([]byte("[]"), []byte("[]"), bad, nil, "demo-network-generation", "2030-01-01T00:00:00Z"); err == nil {
			t.Fatal("old or noncanonical preference accepted")
		}
	}
}
