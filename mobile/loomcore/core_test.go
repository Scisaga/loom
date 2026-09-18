package loomcore

import (
	"bytes"
	"testing"
)

func TestEvaluateAndroidRoutesUsesOneSharedModel(t *testing.T) {
	routes := []byte(`[{"id":"direct","final_exit":"direct","chain":[],"scope":"default"},{"id":"exit-a-direct","final_exit":"exit-a","chain":["exit-a"],"scope":"default"},{"id":"exit-a-relay","final_exit":"exit-a","chain":["relay-a","exit-a"],"scope":"default"}]`)
	preference := []byte(`{"schema":1,"mode":"fixed_exit","exit":"exit-a"}`)
	observations := []byte(`[{"candidate_id":"exit-a-direct","network_generation":"net-a","scope":"default","result":"unavailable","action":"dns_https","observed_at":"2030-01-01T00:00:00Z","valid_until":"2030-01-01T00:10:00Z"},{"candidate_id":"exit-a-relay","network_generation":"net-a","scope":"default","result":"available","action":"dns_https","observed_at":"2030-01-01T00:00:00Z","valid_until":"2030-01-01T00:10:00Z","metric_millis":5}]`)
	result, err := EvaluateAndroidRoutes(routes, observations, preference, nil, "net-a", "2030-01-01T00:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(result, []byte(`"candidate":"exit-a-relay"`)) {
		t.Fatalf("unexpected result %s", result)
	}
}
