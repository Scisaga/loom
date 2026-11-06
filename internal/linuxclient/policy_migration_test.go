package linuxclient

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestPolicyPreferenceMigrationKeepsOriginalAndLaterChoiceOnRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	evidence := filepath.Join(t.TempDir(), "original.runtime")
	original := []byte(`{"network_generation":"demo-old","observations":[],"preference":{"mode":"auto","schema":3},"schema":3}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	pref := clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}
	next, err := PreparePolicyMigration(original, pref, "demo-current", "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitPolicyMigration(path, path, original, next); err == nil {
		t.Fatal("migration evidence could overwrite the current preference")
	}
	if err := CommitPolicyMigration(path, evidence, original, next); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(evidence)
	if !bytes.Equal(original, saved) {
		t.Fatal("historical preference bytes changed")
	}
	next.Observations = []clientmodel.Observation{{CandidateID: "demo-later-sample", Scope: "access", NetworkGeneration: next.NetworkGeneration,
		Result: "available", Action: "https_request", Target: "https://demo.example/", ObservedAt: "2030-01-01T00:00:00Z", ValidUntil: "2030-01-01T00:01:00Z"}}
	if err := SaveLocalState(path, next); err != nil {
		t.Fatal(err)
	}
	reviewed, err := PreparePolicyMigration(original, pref, "demo-current", next.ObservationViewDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitPolicyMigration(path, evidence, original, reviewed); err != nil {
		t.Fatal(err)
	}
	var current LocalState
	if err := readStrict(path, 1<<20, &current.observationCache); err != nil || len(current.Observations) != 1 || current.Observations[0].CandidateID != "demo-later-sample" {
		t.Fatal("retry replaced a later cache update", err)
	}
	if err := CommitPolicyMigration(path, evidence, []byte("different original"), reviewed); err == nil {
		t.Fatal("retry accepted unrelated evidence")
	}
}

func TestPolicyPreferenceMigrationRejectsConcurrentOrNoncanonicalOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	original := []byte(`{"network_generation":"demo-old","observations":[],"preference":{"mode":"auto","schema":3},"schema":3}`)
	preference := clientmodel.EmptyPreference()
	next, err := PreparePolicyMigration(original, preference, "demo-new", control.ReleaseDigest([]byte("demo-view")))
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(original, []byte("auto"), []byte("direct"), 1)
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CommitPolicyMigration(path, filepath.Join(t.TempDir(), "evidence"), original, next); err == nil {
		t.Fatal("migration overwrote a concurrently changed preference")
	}
	invalid := bytes.Replace(original, []byte(`"network_generation"`), []byte(`"schema":3,"network_generation"`), 1)
	if _, err := PreparePolicyMigration(invalid, preference, "demo-new", next.ObservationViewDigest); err == nil {
		t.Fatal("duplicate historical field entered current state")
	}
}
