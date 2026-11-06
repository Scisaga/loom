package protocol

import (
	"reflect"
	"testing"
)

func TestSyntheticRegistrationPreservesBindingAndNeverBecomesADNSName(t *testing.T) {
	value := TargetRegistration{Principal: "demo-principal", Connection: Connection{PolicyID: "demo-policy", Path: PathContext{OriginID: "demo-access", FinalExitID: "demo-exit", Visited: []string{"demo-entry"}}}, Host: "api.example", Port: 443}
	key, err := value.Marshal(3)
	if err != nil {
		t.Fatal(err)
	}
	if CanonicalHost(key) {
		t.Fatal("registration can be inserted by an ordinary DNS query")
	}
	actual, err := UnmarshalRegistration(key, 3)
	if err != nil || !reflect.DeepEqual(actual, value) {
		t.Fatal(actual, err)
	}
	if _, err := UnmarshalRegistration(key, 0); err == nil {
		t.Fatal("registration ignored the receiver graph bound")
	}
	if _, err := UnmarshalRegistration("api.example", 3); err == nil {
		t.Fatal("ordinary fake DNS target became execution permission")
	}
	if _, err := UnmarshalRegistration(key+"=", 3); err == nil {
		t.Fatal("ambiguous cache key accepted")
	}
	changed := value
	changed.Connection.PolicyID = "demo-other"
	other, _ := changed.Marshal(3)
	if other == key {
		t.Fatal("registration was reused across Policies")
	}
}
