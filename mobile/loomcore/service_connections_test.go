package loomcore

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestServiceConnectionBridgeKeepsPinnedServiceAndScope(t *testing.T) {
	snapshot := []byte(`{"connections":[{"id":"00000000-0000-0000-0000-000000000002","chains":["demo-shared-exit","access"],"metadata":{"serviceID":"demo-service","policyID":"demo-new"}},{"id":"00000000-0000-0000-0000-000000000001","chains":["demo-shared-exit","access"],"metadata":{"serviceID":"demo-service","policyID":"demo-old"}},{"id":"00000000-0000-0000-0000-000000000003","chains":["demo-shared-exit","access"],"metadata":{"serviceID":"demo-other"}},{"id":"00000000-0000-0000-0000-000000000004","chains":["demo-shared-exit","local_network:demo-lan"],"metadata":{"serviceID":"demo-lan"}}]}`)
	original := bytes.Clone(snapshot)
	for _, tc := range []struct {
		service, scope string
		want           []string
	}{
		{"demo-service", "access", []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"}},
		{"demo-other", "access", []string{"00000000-0000-0000-0000-000000000003"}},
		{"demo-lan", "local_network:demo-lan", []string{"00000000-0000-0000-0000-000000000004"}},
	} {
		body, err := ServiceConnectionIDs(snapshot, tc.service, tc.scope)
		var actual []string
		if err != nil || json.Unmarshal(body, &actual) != nil || !reflect.DeepEqual(actual, tc.want) {
			t.Fatal("bridge lost pinned Service/scope ownership", actual, err)
		}
	}
	if !bytes.Equal(snapshot, original) {
		t.Fatal("pure bridge changed the native snapshot")
	}
	body, err := ServiceConnectionIDs([]byte(`{"connections":[]}`), "demo-service", "access")
	if err != nil || string(body) != "[]" {
		t.Fatal("empty actual snapshot did not return an empty list", string(body), err)
	}
}

func TestServiceConnectionBridgeDoesNotGuessMissingOwnership(t *testing.T) {
	for _, snapshot := range []string{
		`{"connections":[{"id":"00000000-0000-0000-0000-000000000001","chains":["access"]}]}`,
		`{"connections":[{"id":"../","chains":["access"],"metadata":{"serviceID":"demo-service"}}]}`,
	} {
		if body, err := ServiceConnectionIDs([]byte(snapshot), "demo-service", "access"); err == nil || body != nil {
			t.Fatal("bridge returned deletable IDs without valid native ownership")
		}
	}
}
