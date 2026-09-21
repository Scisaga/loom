package linuxclient

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
)

func TestLocalStateRoundTripAndNetworkChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	state, err := LoadLocalState(path, "network-a")
	if err != nil {
		t.Fatal(err)
	}
	state.Preference = clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	state.Observations = []clientmodel.Observation{{CandidateID: "relay", NetworkGeneration: "network-a", Scope: "service",
		Result: "available", Action: "tcp_udp_dns", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}}
	if err := SaveLocalState(path, state); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadLocalState(path, "network-a")
	if err != nil || len(reloaded.Observations) != 1 || reloaded.Preference.Exit != "demo-exit" {
		t.Fatalf("reload = %+v, %v", reloaded, err)
	}
	changed, err := LoadLocalState(path, "network-b")
	if err != nil || len(changed.Observations) != 0 || changed.Preference.Exit != "demo-exit" {
		t.Fatalf("network change = %+v, %v", changed, err)
	}
}

func TestServerOnlyStatusAllowsNoSelections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	status := Status{Schema: 1, DeviceID: "demo-server", Head: "sha256:" + strings.Repeat("1", 64), Floor: 2,
		Preference: clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-generation",
		Selections: []SelectionStatus{}, Observations: []clientmodel.Observation{}, Runtime: "running", Reported: false}
	if err := WriteStatus(path, status); err != nil {
		t.Fatal(err)
	}
	read, err := ReadStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if read.DeviceID != status.DeviceID || len(read.Selections) != 0 || read.Reported {
		t.Fatalf("server-only status changed: %+v", read)
	}
}
