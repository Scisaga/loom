package releasefloor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func record(generation uint64, digest, snapshot string) Record {
	return Record{
		Schema:           CurrentSchema,
		Generation:       generation,
		PayloadSHA256:    digest,
		SelectedSnapshot: snapshot,
	}
}

func TestCheckMatrix(t *testing.T) {
	floor := record(7, digestA, "0123456789ab")
	tests := []struct {
		name       string
		generation uint64
		digest     string
		want       error
	}{
		{name: "lower generation", generation: 6, digest: digestA, want: ErrStaleGeneration},
		{name: "same generation same digest", generation: 7, digest: digestA},
		{name: "same generation different digest", generation: 7, digest: digestB, want: ErrGenerationConflict},
		{name: "higher generation same digest", generation: 8, digest: digestA},
		{name: "higher generation different digest", generation: 8, digest: digestB},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := floor.Check(tc.generation, tc.digest)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Check() error = %v, want errors.Is(_, %v)", err, tc.want)
			}
		})
	}

	var empty *Record
	if err := empty.Check(1, digestA); err != nil {
		t.Fatalf("empty floor rejected first valid generation: %v", err)
	}
	if err := empty.Check(0, digestA); err == nil {
		t.Fatal("empty floor accepted generation zero")
	}
	if err := empty.Check(0, "A"+digestA[1:]); err == nil {
		t.Fatal("empty floor accepted malformed digest")
	}
}

func TestReadMissingAndStrictValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "floor.json")
	got, err := Read(path)
	if err != nil || got != nil {
		t.Fatalf("missing floor = %+v, %v; want nil, nil", got, err)
	}

	valid := `{"schema":1,"generation":2,"payload_sha256":"` + digestA + `","selected_snapshot":"0123456789ab"}`
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown field", body: strings.TrimSuffix(valid, "}") + `,"extra":true}`},
		{name: "wrong schema", body: strings.Replace(valid, `"schema":1`, `"schema":2`, 1)},
		{name: "zero generation", body: strings.Replace(valid, `"generation":2`, `"generation":0`, 1)},
		{name: "duplicate generation", body: strings.Replace(valid, `"generation":2`, `"generation":1,"generation":2`, 1)},
		{name: "empty digest", body: strings.Replace(valid, digestA, "", 1)},
		{name: "short digest", body: strings.Replace(valid, digestA, digestA[:63], 1)},
		{name: "uppercase digest", body: strings.Replace(valid, digestA, "A"+digestA[1:], 1)},
		{name: "nonhex digest", body: strings.Replace(valid, digestA, "g"+digestA[1:], 1)},
		{name: "empty snapshot", body: strings.Replace(valid, "0123456789ab", "", 1)},
		{name: "short snapshot", body: strings.Replace(valid, "0123456789ab", "0123456789a", 1)},
		{name: "uppercase snapshot", body: strings.Replace(valid, "0123456789ab", "0123456789AB", 1)},
		{name: "nonhex snapshot", body: strings.Replace(valid, "0123456789ab", "0123456789ag", 1)},
		{name: "second value", body: valid + ` {}`},
		{name: "trailing junk", body: valid + ` x`},
		{name: "null", body: `null`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := Read(path); err == nil || got != nil {
				t.Fatalf("Read() = %+v, %v; want nil and fail closed", got, err)
			}
		})
	}

	if err := os.WriteFile(path, []byte(valid+"\n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = Read(path)
	if err != nil || got == nil || got.Generation != 2 {
		t.Fatalf("valid floor with trailing whitespace = %+v, %v", got, err)
	}
}

func TestAdvancePersistsAtomicallyWithPrivatePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested")
	path := filepath.Join(dir, "floor.json")
	want := record(3, digestA, "0123456789ab")
	if err := Advance(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil || got == nil || *got != want {
		t.Fatalf("persisted floor = %+v, %v; want %+v", got, err, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("floor permissions = %#o, want 0600", gotMode)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("temporary file leaked after atomic write: %v", entries)
	}
	if err := Advance(path, want); err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
}

func TestAdvanceDoesNotReplaceNewerOrCorruptFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "floor.json")
	newer := record(9, digestB, "bbbbbbbbbbbb")
	if err := Advance(path, newer); err != nil {
		t.Fatal(err)
	}
	if err := Advance(path, record(8, digestA, "aaaaaaaaaaaa")); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("older advance error = %v, want stale generation", err)
	}
	got, err := Read(path)
	if err != nil || got == nil || *got != newer {
		t.Fatalf("older advance changed floor to %+v, %v", got, err)
	}

	if err := os.WriteFile(path, []byte(`{"schema":1,"generation":99`), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Advance(path, record(10, digestA, "aaaaaaaaaaaa")); err == nil {
		t.Fatal("corrupt existing floor was silently replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("failed-closed advance mutated corrupt floor: before=%q after=%q", before, after)
	}
}

func TestAdvanceSerializedConcurrentOrderCannotRegress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "floor.json")
	var releaseLock sync.Mutex
	highDone := make(chan struct{})
	errs := make(chan error, 2)

	go func() {
		releaseLock.Lock()
		err := Advance(path, record(12, digestB, "bbbbbbbbbbbb"))
		releaseLock.Unlock()
		errs <- err
		close(highDone)
	}()
	go func() {
		<-highDone
		releaseLock.Lock()
		err := Advance(path, record(11, digestA, "aaaaaaaaaaaa"))
		releaseLock.Unlock()
		errs <- err
	}()

	var sawSuccess, sawStale bool
	for range 2 {
		err := <-errs
		sawSuccess = sawSuccess || err == nil
		sawStale = sawStale || errors.Is(err, ErrStaleGeneration)
	}
	if !sawSuccess || !sawStale {
		t.Fatalf("ordered concurrent advances: success=%v stale=%v", sawSuccess, sawStale)
	}
	got, err := Read(path)
	if err != nil || got == nil || got.Generation != 12 || got.PayloadSHA256 != digestB {
		t.Fatalf("floor regressed after ordered concurrent calls: %+v, %v", got, err)
	}
}

func TestAdvanceRejectsSameGenerationSnapshotMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "floor.json")
	if err := Advance(path, record(4, digestA, "aaaaaaaaaaaa")); err != nil {
		t.Fatal(err)
	}
	if err := Advance(path, record(4, digestA, "bbbbbbbbbbbb")); err == nil {
		t.Fatal("same generation and payload changed selected snapshot")
	}
	got, err := Read(path)
	if err != nil || got == nil || got.SelectedSnapshot != "aaaaaaaaaaaa" {
		t.Fatalf("snapshot mismatch changed floor: %+v, %v", got, err)
	}
}
