package linuxclient

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestLocalStateRejectsNoncanonicalBytesWithoutRepairingThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	if _, err := LoadLocalState(path, "demo-network"); err != nil {
		t.Fatal(err)
	}
	canonical, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{
		append(append([]byte{}, canonical...), '\n'),
		bytes.Replace(canonical, []byte(`"schema":3`), []byte(`"schema":3,"schema":3`), 1),
		bytes.Replace(canonical, []byte(`"observations":[]`), []byte(`"observations":null`), 1),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadLocalState(path, "demo-network"); err == nil {
			t.Fatal("noncanonical state became runtime authority")
		}
		readback, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(readback, body) {
			t.Fatal("rejected persistent input was silently repaired")
		}
	}
}

func TestLocalStateRoundTripAndNetworkChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	state, err := LoadLocalState(path, "network-a")
	if err != nil {
		t.Fatal(err)
	}
	state.Preference = clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
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
	status := Status{Schema: 3, DeviceID: "demo-server", ViewDigest: "sha256:" + strings.Repeat("1", 64), FactFrontier: []control.FactFrontier{},
		Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-generation",
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

func TestObservationCacheRequiresTheSameCertifiedView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	digest := "sha256:" + strings.Repeat("1", 64)
	state, err := loadLocalState(path, "demo-network", digest)
	if err != nil {
		t.Fatal(err)
	}
	state.Preference = clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	state.Observations = []clientmodel.Observation{{CandidateID: "demo-route", NetworkGeneration: "demo-network", Scope: "demo-service",
		Result: "available", Action: "tcp_udp_dns", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}}
	if err := SaveLocalState(path, state); err != nil {
		t.Fatal(err)
	}
	restarted, err := loadLocalState(path, "demo-network", digest)
	if err != nil || len(restarted.Observations) != 1 {
		t.Fatalf("same view lost reusable evidence: %+v, %v", restarted, err)
	}
	changed, err := loadLocalState(path, "demo-network", "sha256:"+strings.Repeat("2", 64))
	if err != nil || len(changed.Observations) != 0 || changed.Preference != state.Preference {
		t.Fatalf("new view inherited old evidence or lost preference: %+v, %v", changed, err)
	}
	if _, err := SaveObservations(path, restarted); err == nil {
		t.Fatal("an old generation restored observations across a view change")
	}
}

func TestFailedApplicationStatusIsReadableWithoutOldSelections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	status := Status{Schema: 3, DeviceID: "demo-device", ViewDigest: "sha256:" + strings.Repeat("1", 64), FactFrontier: []control.FactFrontier{},
		Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-generation",
		Runtime: "error", Selections: []SelectionStatus{}, Observations: []clientmodel.Observation{}}
	if err := WriteStatus(path, status); err != nil {
		t.Fatal(err)
	}
	read, err := ReadStatus(path)
	if err != nil || read.Runtime != "error" || read.ViewDigest != status.ViewDigest || len(read.Selections) != 0 {
		t.Fatalf("failed runtime readback = %+v, %v", read, err)
	}
	status.Selections = []SelectionStatus{{Scope: "demo-service", CandidateID: "demo-old"}}
	if err := WriteStatus(path, status); err == nil {
		t.Fatal("failed application reused a previous generation's selection")
	}
}
