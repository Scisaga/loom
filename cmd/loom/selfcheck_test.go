package main

import "testing"

func TestSelfcheckDoesNotAdvertiseRetiredReleaseActivation(t *testing.T) {
	if err := requireSelfcheckCapability(""); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []string{"signed-current-v1", "future-capability"} {
		if err := requireSelfcheckCapability(capability); err == nil {
			t.Fatalf("unsupported release activation capability accepted: %s", capability)
		}
	}
}
