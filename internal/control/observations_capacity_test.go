package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcceptedObservationHistoryRestartsBeyondIndividualItemBudget(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ViewDigest: digest,
		NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{
			{ServiceID: "demo-a", CandidateID: digest}, {ServiceID: "demo-b", CandidateID: digest},
			{ServiceID: "demo-c", CandidateID: digest}, {ServiceID: "demo-d", CandidateID: digest}},
		Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
	history := observationState{Schema: 3, Reports: make([]DeviceReport, 40000)}
	for i := range history.Reports {
		report.ReportSequence = U64(i + 1)
		var err error
		history.Reports[i], err = SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
	}
	body, err := CanonicalEncode(history)
	if err != nil || len(body) >= maxObservationStateBytes {
		t.Fatal("history fixture exceeds the existing protected file capacity", err)
	}
	var legacyRead observationState
	if err := DecodeCanonical(body, &legacyRead, ContractDecodeLimits{MaxBytes: maxObservationStateBytes, MaxDepth: 128, MaxItems: 1 << 20}); err == nil {
		t.Fatal("fixture does not exceed the old aggregate item budget")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observations.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal("accepted canonical history prevented restart", err)
	}
	if latest := store.All(); len(latest) != 1 || latest[0].ReportSequence != U64(len(history.Reports)) {
		t.Fatal("restart lost the durable report high-water mark")
	}
	if err := store.Put(history.Reports[0], public); err != nil {
		t.Fatal("existing exact signed report lost idempotence", err)
	}
	report.ReportSequence = 2
	report.NetworkGeneration = "demo-another-underlay"
	replayed, err := SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(replayed, public); !errors.Is(err, ErrReportEquivocation) {
		t.Fatal("older signed fork was not preserved and rejected", err)
	}
	if latest := store.All(); len(latest) != 1 || latest[0].ReportSequence != U64(len(history.Reports)) {
		t.Fatal("older fork replaced the durable high-water report")
	}
	afterFork, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved observationState
	if err := DecodeCanonical(afterFork, &saved, ContractDecodeLimits{MaxBytes: maxObservationStateBytes, MaxDepth: 128, MaxItems: len(afterFork)}); err != nil || len(saved.Reports) != len(history.Reports)+1 {
		t.Fatal("older fork or original history was lost", err)
	}
	originals := map[string]bool{}
	for _, report := range saved.Reports {
		body, _ := CanonicalEncode(report)
		originals[ReleaseDigest(body)] = true
	}
	for _, report := range history.Reports {
		body, _ := CanonicalEncode(report)
		if !originals[ReleaseDigest(body)] {
			t.Fatal("preserving an older fork changed original signed bytes")
		}
	}
	if err := writeObservationState(path, make([]byte, maxObservationStateBytes+1)); err == nil {
		t.Fatal("write committed bytes that cannot be read after restart")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, afterFork) {
		t.Fatal("capacity rejection changed accepted signed history", err)
	}
}
