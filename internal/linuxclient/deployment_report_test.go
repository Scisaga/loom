package linuxclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/releasefloor"
	"loom/internal/rollout"
)

func TestLinuxDeploymentReadbackRequiresMatchingVerifiedLocalFacts(t *testing.T) {
	root := t.TempDir()
	options := Options{ReleaseFloor: filepath.Join(root, "release-floor.json"),
		AppliedSnapshot: filepath.Join(root, "applied"), RolloutState: filepath.Join(root, "rollout.json")}
	floor := releasefloor.Record{Schema: releasefloor.CurrentSchema, Generation: 7,
		PayloadSHA256: strings.Repeat("a", 64), SelectedSnapshot: "123456abcdef"}
	if err := releasefloor.Advance(options.ReleaseFloor, floor); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.AppliedSnapshot, []byte(floor.SelectedSnapshot+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	record := rollout.Begin(nil, floor.SelectedSnapshot, "", time.Unix(100, 0))
	record.Enter(rollout.Verified, time.Unix(101, 0))
	if err := record.Write(options.RolloutState); err != nil {
		t.Fatal(err)
	}
	readback, err := linuxDeploymentReadback(options)
	if err != nil || readback == nil || !readback.RolloutVerified || readback.Generation != floor.Generation ||
		readback.PayloadSHA256 != floor.PayloadSHA256 || readback.SelectedSnapshot != floor.SelectedSnapshot ||
		readback.AppliedSnapshot != floor.SelectedSnapshot || readback.Version == "" {
		t.Fatalf("readback=%+v err=%v", readback, err)
	}
	if err := os.WriteFile(options.AppliedSnapshot, []byte("abcdef123456\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	readback, err = linuxDeploymentReadback(options)
	if err != nil || readback == nil || readback.RolloutVerified {
		t.Fatalf("mismatched applied snapshot was marked verified: readback=%+v err=%v", readback, err)
	}
}
