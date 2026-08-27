package main

import "testing"

func TestSelfcheckSignedCurrentCapability(t *testing.T) {
	if err := requireSelfcheckCapability(signedCurrentCapability); err != nil {
		t.Fatal(err)
	}
	if err := requireSelfcheckCapability("future-capability"); err == nil {
		t.Fatal("未知 capability 被 selfcheck 接受")
	}
}
