package linuxclient

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
)

func TestTargetSamplesRoundTripWithoutReinterpretingOldCache(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	state := defaultState("demo-network")
	state.ObservationViewDigest = "sha256:" + strings.Repeat("a", 64)
	state.Preference = clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-exit"}
	for i, target := range []string{"", "https://demo.example/a", "https://demo.example/b"} {
		result := "available"
		if i == 2 {
			result = "unavailable"
		}
		state.Observations = append(state.Observations, clientmodel.Observation{CandidateID: "demo-route", Scope: "service:demo-service", Target: target, NetworkGeneration: state.NetworkGeneration, Action: "https_request", Result: result, ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)})
	}
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := SaveLocalState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadLocalState(path, state.NetworkGeneration, state.ObservationViewDigest)
	if err != nil || !reflect.DeepEqual(loaded, state) {
		t.Fatal("canonical cache restart changed samples or preference", err)
	}
	health, err := clientmodel.ObservationState(loaded.Observations, "demo-route", "service:demo-service", state.NetworkGeneration, []string{"https://demo.example/a", "https://demo.example/b"}, now)
	if err != nil || health != "unknown" {
		t.Fatal("old targetless success hid an actual target failure", health, err)
	}
}
