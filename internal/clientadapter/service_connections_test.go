package clientadapter

import (
	"reflect"
	"testing"
)

func TestServiceConnectionsRequirePinnedServiceAndActualScope(t *testing.T) {
	body := []byte(`{"connections":[{"id":"00000000-0000-0000-0000-000000000001","chains":["demo-shared-exit","access"],"metadata":{"serviceID":"demo-old"}},{"id":"00000000-0000-0000-0000-000000000002","chains":["demo-shared-exit","access"],"metadata":{"serviceID":"demo-current"}},{"id":"00000000-0000-0000-0000-000000000003","chains":["demo-shared-exit","local_network:demo-lan"],"metadata":{"serviceID":"demo-lan"}}]}`)
	for _, tc := range []struct{ service, scope, id string }{
		{"demo-current", "access", "00000000-0000-0000-0000-000000000002"},
		{"demo-old", "access", "00000000-0000-0000-0000-000000000001"},
		{"demo-lan", "local_network:demo-lan", "00000000-0000-0000-0000-000000000003"},
	} {
		ids, err := ServiceConnectionIDs(body, tc.service, tc.scope)
		if err != nil || !reflect.DeepEqual(ids, []string{tc.id}) {
			t.Fatal("shared source or exit was mistaken for Service ownership", ids, err)
		}
	}
}

func TestServiceConnectionsIncludeBothPoliciesOfTheSameService(t *testing.T) {
	body := []byte(`{"connections":[{"id":"00000000-0000-0000-0000-000000000002","chains":["demo-new-resource","access"],"metadata":{"serviceID":"demo-service","policyID":"demo-b"}},{"id":"00000000-0000-0000-0000-000000000001","chains":["demo-old-resource","access"],"metadata":{"serviceID":"demo-service","policyID":"demo-a"}}]}`)
	ids, err := ServiceConnectionIDs(body, "demo-service", "access")
	if err != nil || !reflect.DeepEqual(ids, []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"}) {
		t.Fatal("older Policy connections of the same Service were omitted", ids, err)
	}
}

func TestServiceConnectionsRejectUnclassifiedOrUnsafeMatches(t *testing.T) {
	for _, bad := range []string{
		`{}`, `{"connections":{}}`,
		`{"connections":[{"id":"00000000-0000-0000-0000-000000000001","chains":["access"]}]}`,
		`{"connections":[{"id":"../","chains":["access"],"metadata":{"serviceID":"demo-service"}}]}`,
		`{"connections":[{"id":"00000000-0000-0000-0000-000000000001","chains":["access"],"metadata":{"serviceID":"demo-service"}},{"id":"00000000-0000-0000-0000-000000000001","chains":["access"],"metadata":{"serviceID":"demo-service"}}]}`,
	} {
		if _, err := ServiceConnectionIDs([]byte(bad), "demo-service", "access"); err == nil {
			t.Fatal("invalid connection evidence was accepted")
		}
	}
	if _, err := ServiceConnectionIDs([]byte(`{"connections":[]}`), "demo-service", "local_network:demo-other"); err == nil {
		t.Fatal("scope for a different Service was accepted")
	}
}
