package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func migrationOriginals(t *testing.T, root string, reports []DeviceReport) []byte {
	t.Helper()
	sort.Slice(reports, func(i, j int) bool {
		a, _ := CanonicalEncode(reports[i])
		b, _ := CanonicalEncode(reports[j])
		return reportBefore(reports[i], a, reports[j], b)
	})
	body, err := CanonicalEncode(observationState{Schema: 3, Reports: reports})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "observations.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestReportMigrationPreservesAcceptedIdentityHistoryAndRestart(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if _, err := server.Runtime.Authority.CompleteEnrollment(context.Background(), claim, false, enrollmentTunnel(invite), server.now(), server.Runtime.Config); err != nil {
		t.Fatal(err)
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	base := DeviceReport{Schema: 3, NetworkID: claim.NetworkID, DeviceID: invite.DeviceID, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped"}, Components: []ComponentReadback{}}
	sign := func(sequence U64) DeviceReport {
		t.Helper()
		base.ReportSequence = sequence
		r, err := SignDeviceReport(base, key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	first, latest := sign(1), sign(3)
	base.NetworkGeneration = "demo-another-underlay"
	fork := sign(1)
	root := server.Runtime.Authority.root
	if err := os.Remove(filepath.Join(root, "observations.db")); err != nil {
		t.Fatal(err)
	}
	original := migrationOriginals(t, root, []DeviceReport{first, latest, fork})
	evidenceRoot := t.TempDir()
	if err := os.Chmod(evidenceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(evidenceRoot, "original.json")
	socket := filepath.Join(root, "admin.sock")
	lock, err := lockProtectedControlPath(context.Background(), socket+".listen.lock")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	_, err = MigrateObservationHistory(ctx, root, socket, evidence)
	cancel()
	lock.Close()
	if err == nil {
		t.Fatal("migration proceeded while the formal control listener owned its lock")
	}
	if _, err := OpenObservationStore(root); err == nil {
		t.Fatal("daemon silently consumed the JSON container")
	}
	result, err := MigrateObservationHistory(context.Background(), root, socket, evidence)
	if err != nil || !result.Migrated || result.Reports != 3 || result.OriginalDigest != ReleaseDigest(original) {
		t.Fatal("verified migration failed", result, err)
	}
	retained, err := os.ReadFile(evidence)
	if err != nil || !bytes.Equal(retained, original) {
		t.Fatal("original container evidence changed", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "observations.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old runtime reader input remains")
	}
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testObservationBytes(t, root), original) {
		t.Fatal("migration changed an original signed value or fork")
	}
	if err := store.Put(sign(2), claim.DevicePublicKey); !errors.Is(err, ErrReportReplay) {
		t.Fatal("migration lowered report high-water", err)
	}
	if err := store.Put(fork, claim.DevicePublicKey); !errors.Is(err, ErrReportEquivocation) {
		t.Fatal("migration forgot a known historical fork", err)
	}
	if err := store.Put(sign(4), claim.DevicePublicKey); err != nil {
		t.Fatal("normal report could not continue after migration", err)
	}
	reopened, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.All(); len(got) != 1 || got[0].ReportSequence != 4 || len(reopened.History()) != 4 {
		t.Fatal("restart lost migrated history or new report")
	}
}

func TestReportMigrationInterruptedPublicationAndRefusals(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	sign := func(sequence U64) DeviceReport {
		t.Helper()
		r, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: sequence, ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped"}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, scenario := range []string{"identical-published", "extra-original", "wrong-signature", "noncanonical"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			original := migrationOriginals(t, root, []DeviceReport{sign(1), sign(3)})
			evidence := filepath.Join(t.TempDir(), "original.json")
			keys := map[reportOwner]string{{"demo-network", "demo-device"}: public}
			if scenario == "wrong-signature" {
				keys[reportOwner{"demo-network", "demo-device"}] = base64.RawURLEncoding.EncodeToString(testKey(t).Public().(ed25519.PublicKey))
			}
			if scenario == "noncanonical" {
				original = append(original, '\n')
				if err := os.WriteFile(filepath.Join(root, "observations.json"), original, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "identical-published" || scenario == "extra-original" {
				reports := []DeviceReport{sign(1), sign(3)}
				if scenario == "extra-original" {
					reports = append(reports, sign(4))
				}
				testSetObservationReports(t, root, reports)
				if _, err := OpenObservationStore(root); err == nil {
					t.Fatal("dual containers entered the daemon")
				}
			}
			_, err := migrateReportContainer(context.Background(), root, evidence, keys)
			if scenario == "identical-published" {
				if err != nil || !bytes.Equal(testObservationBytes(t, root), original) {
					t.Fatal("identical interrupted publication did not resume", err)
				}
			} else {
				if err == nil {
					t.Fatal("invalid or divergent migration was accepted")
				}
				got, readErr := os.ReadFile(filepath.Join(root, "observations.json"))
				if readErr != nil || !bytes.Equal(got, original) {
					t.Fatal("rejected migration changed its source")
				}
				if scenario == "extra-original" {
					count := 0
					err := withReportDatabase(context.Background(), filepath.Join(root, "observations.db"), false, func(tx *bolt.Tx) error { count = tx.Bucket(observationBucket).Stats().KeyN; return nil })
					if err != nil || count != 3 {
						t.Fatal("rejected migration overwrote existing originals", err)
					}
				}
			}
		})
	}
}
