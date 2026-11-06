package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

func TestContextCanonicalRoundTripAndInvalidPathRejection(t *testing.T) {
	for _, value := range []PathContext{{"demo-access", "direct", []string{}}, {"demo-access", "demo-exit", []string{}}, {"demo-access", "demo-exit", []string{"demo-entry", "demo-relay"}}, {"demo-access", "demo-exit", []string{"demo-entry", "demo-exit"}}} {
		body, err := value.Marshal(8)
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnmarshalContext(body, 8)
		if err != nil || !reflect.DeepEqual(got, value) {
			t.Fatal("context lost execution meaning", got, err)
		}
		again, err := got.Marshal(8)
		if err != nil || !bytes.Equal(again, body) {
			t.Fatal("context has two wire representations", err)
		}
		for _, invalid := range [][]byte{append(append([]byte{}, body...), 0), body[:len(body)-1], append([]byte{4}, body[1:]...)} {
			if _, err := UnmarshalContext(invalid, 8); err == nil {
				t.Fatal("noncurrent or incomplete context accepted")
			}
		}
	}
	for _, value := range []PathContext{{"demo-access", "demo-exit", nil}, {"demo-access", "demo-exit", []string{"demo-entry", "demo-entry"}}, {"demo-access", "demo-exit", []string{"demo-exit", "demo-entry"}}, {"demo-access", "demo-exit", []string{"demo-a", "demo-b"}}} {
		if _, err := value.Marshal(1); err == nil {
			t.Fatal("invalid path became execution input", value)
		}
	}
	body, _ := (PathContext{"demo-access", "demo-exit", []string{}}).Marshal(1)
	// The same small length using an overlong varint is not another wire value.
	invalid := append([]byte{Schema, 0x8b, 0}, body[2:]...)
	if _, err := UnmarshalContext(invalid, 1); err == nil {
		t.Fatal("overlong execution length was accepted")
	}
}
