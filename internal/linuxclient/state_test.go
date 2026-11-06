package linuxclient

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestNativeBusinessFactsAndBindingNeverEnterProbePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	digest := control.ReleaseDigest([]byte("demo-view"))
	state, err := loadLocalState(path, "demo-network", digest)
	if err != nil {
		t.Fatal(err)
	}
	state.NativeExecutionSpec = "demo-native-spec"
	state.NativeObservations = []clientmodel.Observation{{CandidateID: "demo-candidate", Target: "demo.example:443", Action: "tcp_connect"}}
	state.SelectionMemory = map[string]clientmodel.SelectionMemory{"access": {NativeBinding: &clientmodel.NativeBinding{Revision: "demo-revision", NetworkGeneration: "demo-network", ExecutionSpec: state.NativeExecutionSpec}}}
	saved, err := SaveObservations(path, state)
	if err != nil || len(saved.NativeObservations) != 1 || saved.SelectionMemory["access"].NativeBinding == nil {
		t.Fatal("live RAM facts lost while saving independent probes", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"tcp_connect", "native", "demo.example", "revision"} {
		if bytes.Contains(body, []byte(field)) {
			t.Fatal("ordinary business data entered the persistent probe cache")
		}
	}
	restarted, err := loadLocalState(path, "demo-network", digest)
	if err != nil || len(restarted.NativeObservations) != 0 || restarted.NativeExecutionSpec != "" || restarted.SelectionMemory != nil {
		t.Fatal("restart resurrected business bindings", err)
	}
}

func TestResourceCacheRestartPreservesOriginalFailureWithoutOwningPreference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	digest := "sha256:" + strings.Repeat("1", 64)
	state, err := loadLocalState(path, "demo-underlay", digest)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if bytes.Contains(before, []byte("resource_observations")) {
		t.Fatal("absent optional cache changed old file shape")
	}
	state.ResourceObservations = []control.Observation{{Level: "resource", ResourceID: "demo-resource", Target: "demo.example:443", Action: "hysteria2_tls",
		SpecDigest: digest, NetworkGeneration: state.NetworkGeneration, Result: "unavailable", ObservedAt: 1000, ValidUntil: 31000}}
	// Internet and independent LAN policies may require different admission
	// proofs on the same resource. The cache must preserve both originals.
	second := state.ResourceObservations[0]
	second.SpecDigest, second.Result = "sha256:"+strings.Repeat("2", 64), "available"
	state.ResourceObservations = append(state.ResourceObservations, second)
	preference := clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}
	state.Preference = preference
	saved, err := SaveObservations(path, state)
	if err != nil || !saved.Preference.Equal(preference) {
		t.Fatal("resource sample overwrote the CLI preference", err)
	}
	stored, _ := os.ReadFile(path)
	if bytes.Contains(stored, []byte(`"preference"`)) {
		t.Fatal("runtime cache became a second preference authority")
	}
	restarted, err := loadLocalState(path, state.NetworkGeneration, digest)
	if err != nil || !reflect.DeepEqual(restarted.ResourceObservations, state.ResourceObservations) || restarted.Preference.PolicyID != "" {
		t.Fatal("restart replaced original failure or its validity", err)
	}
	changed, err := loadLocalState(path, "demo-new-underlay", digest)
	if err != nil || changed.ResourceObservations != nil || changed.Preference.PolicyID != "" {
		t.Fatal("network change retained stale authentication", err)
	}
}

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
	state.Preference = clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	state.Observations = []clientmodel.Observation{{CandidateID: "relay", NetworkGeneration: "network-a", Scope: "service:demo-service",
		Result: "available", Action: "tcp_udp_dns", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}}
	if err := SaveLocalState(path, state); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadLocalState(path, "network-a")
	if err != nil || len(reloaded.Observations) != 1 || reloaded.Preference.PolicyID != "" {
		t.Fatalf("reload = %+v, %v", reloaded, err)
	}
	changed, err := LoadLocalState(path, "network-b")
	if err != nil || len(changed.Observations) != 0 || changed.Preference.PolicyID != "" {
		t.Fatalf("network change = %+v, %v", changed, err)
	}
}

func TestServerOnlyStatusAllowsNoSelections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	status := Status{Schema: 3, DeviceID: "demo-server", ViewDigest: "sha256:" + strings.Repeat("1", 64), FactFrontier: []control.FactFrontier{},
		Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-generation",
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
	state.Preference = clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	state.Observations = []clientmodel.Observation{{CandidateID: "demo-route", NetworkGeneration: "demo-network", Scope: "service:demo-service",
		Result: "available", Action: "tcp_udp_dns", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}}
	if err := SaveLocalState(path, state); err != nil {
		t.Fatal(err)
	}
	restarted, err := loadLocalState(path, "demo-network", digest)
	if err != nil || len(restarted.Observations) != 1 {
		t.Fatalf("same view lost reusable evidence: %+v, %v", restarted, err)
	}
	changed, err := loadLocalState(path, "demo-network", "sha256:"+strings.Repeat("2", 64))
	if err != nil || len(changed.Observations) != 0 || changed.Preference.PolicyID != "" {
		t.Fatalf("new view inherited old evidence or lost preference: %+v, %v", changed, err)
	}
	if _, err := SaveObservations(path, restarted); err == nil {
		t.Fatal("an old generation restored observations across a view change")
	}
}

func TestFailedApplicationStatusIsReadableWithoutOldSelections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	status := Status{Schema: 3, DeviceID: "demo-device", ViewDigest: "sha256:" + strings.Repeat("1", 64), FactFrontier: []control.FactFrontier{},
		Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-generation",
		Runtime: "error", Selections: []SelectionStatus{}, Observations: []clientmodel.Observation{}}
	if err := WriteStatus(path, status); err != nil {
		t.Fatal(err)
	}
	read, err := ReadStatus(path)
	if err != nil || read.Runtime != "error" || read.ViewDigest != status.ViewDigest || len(read.Selections) != 0 {
		t.Fatalf("failed runtime readback = %+v, %v", read, err)
	}
	status.Selections = []SelectionStatus{{Scope: "service:demo-service", CandidateID: "demo-old"}}
	if err := WriteStatus(path, status); err == nil {
		t.Fatal("failed application reused a previous generation's selection")
	}
}
