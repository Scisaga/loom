//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/clientsecret"
	"loom/internal/wire"
)

func TestCleanWindowsClientWaitsForQRBeforeLoadingPackagedTrust(t *testing.T) {
	if _, err := ensureWindowsJoined(context.Background(), t.TempDir(), clientsecret.UserProtector{}, ""); !errors.Is(err, errWindowsJoinInputRequired) {
		t.Fatal(err)
	}
}

func TestWindowsJoinRejectsOldCarrierAndPreservesExistingIdentity(t *testing.T) {
	root := t.TempDir()
	original := []byte("demo-preserved-identity")
	path := filepath.Join(root, "join", "identity.json.dpapi")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"loom://enroll#ZGVtby1vbGQ", `{"schema":1,"endpoint":"https://control.example/loom-client/enroll","token":"demo-old"}`} {
		if _, err := ensureWindowsJoined(context.Background(), root, clientsecret.UserProtector{}, source); err == nil {
			t.Fatal("old carrier was accepted")
		}
		if after, err := os.ReadFile(path); err != nil || string(after) != string(original) {
			t.Fatal("old input changed existing identity", err)
		}
	}
}

func TestWindowsEarlyRuntimeProofUsesSamePinnedPlatformTrust(t *testing.T) {
	key := make([]byte, 32)
	bundle := &wire.InviteProofBundleV2{RuntimeActivationBundle: &wire.RuntimeActivationBundleV1{
		Proof: wire.RuntimeActivationProofV1{Statement: wire.RuntimeActivationStatementV1{V1PlatformKeyID: "demo-platform"}},
	}}
	trust := windowsInviteProofTrust(bundle, key)
	if trust.V1PlatformKeyID != "demo-platform" || len(trust.V1PlatformKey) != 32 {
		t.Fatal("missing migration trust")
	}
}
