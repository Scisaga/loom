package traffic

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQueryNodeAndLinkDeltasWithoutDoubleCounting(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := testStore(t)
	appendFrame(t, store, start, []Counter{
		counter("a", "b", "wg-b", "boot-a", start, 100, 200),
		counter("b", "a", "wg-a", "boot-b", start, 200, 100),
	})
	appendFrame(t, store, start.Add(time.Minute), []Counter{
		counter("a", "b", "wg-b", "boot-a", start.Add(time.Minute), 160, 240),
		counter("b", "a", "wg-a", "boot-b", start.Add(time.Minute), 240, 160),
	})

	buckets, err := store.Query(start, start.Add(5*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := buckets[0].Nodes["a"]; got.RXBytes != 60 || got.TXBytes != 40 || got.Bytes != 100 || got.Samples != 1 {
		t.Fatalf("node a totals = %+v", got)
	}
	if got := buckets[0].Nodes["b"]; got.RXBytes != 40 || got.TXBytes != 60 || got.Bytes != 100 {
		t.Fatalf("node b totals = %+v", got)
	}
	// Link bytes use a.TX + b.TX = 40 + 60. Summing both endpoints'
	// RX+TX would incorrectly produce 200.
	if got := buckets[0].Links["a↔b"]; got.Bytes != 100 || got.ReportingEndpoints != 2 || got.From != "a" || got.To != "b" {
		t.Fatalf("link totals = %+v", got)
	}
}

func TestQuerySaturatesAggregatesInsteadOfWrappingNegative(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := testStore(t)
	appendFrame(t, store, start, []Counter{
		counter("a", "b", "wg-b", "boot", start, 0, 0),
		counter("a", "c", "wg-c", "boot", start, 0, 0),
	})
	appendFrame(t, store, start.Add(time.Minute), []Counter{
		counter("a", "b", "wg-b", "boot", start.Add(time.Minute), math.MaxInt64, math.MaxInt64),
		counter("a", "c", "wg-c", "boot", start.Add(time.Minute), math.MaxInt64, math.MaxInt64),
	})
	buckets, err := store.Query(start, start.Add(5*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := buckets[0].Nodes["a"]; got.RXBytes != math.MaxInt64 ||
		got.TXBytes != math.MaxInt64 || got.Bytes != math.MaxInt64 {
		t.Fatalf("overflowing node aggregate wrapped instead of saturating: %+v", got)
	}
}

func TestQueryRejectsResetAndLongGap(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := testStore(t)
	appendFrame(t, store, start, []Counter{counter("a", "b", "wg-b", "boot-1", start, 100, 100)})
	appendFrame(t, store, start.Add(time.Minute), []Counter{counter("a", "b", "wg-b", "boot-1", start.Add(time.Minute), 20, 30)})
	appendFrame(t, store, start.Add(10*time.Minute), []Counter{counter("a", "b", "wg-b", "boot-1", start.Add(10*time.Minute), 50, 60)})
	appendFrame(t, store, start.Add(11*time.Minute), []Counter{counter("a", "b", "wg-b", "boot-2", start.Add(11*time.Minute), 70, 80)})

	buckets, err := store.Query(start, start.Add(15*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if buckets[0].Resets != 1 || buckets[2].Gaps != 1 || buckets[2].Resets != 1 {
		t.Fatalf("reset/gap buckets = %+v", buckets)
	}
	for _, bucket := range buckets {
		if got := bucket.Nodes["a"].Bytes; got != 0 {
			t.Fatalf("rejected transitions produced %d bytes", got)
		}
	}
	if got := buckets[0].Nodes["a"].Resets; got != 1 {
		t.Fatalf("node reset count = %d, want 1", got)
	}
	if got := buckets[2].Nodes["a"]; got.Gaps != 1 || got.Resets != 1 {
		t.Fatalf("node quality = %+v", got)
	}
	if got := buckets[0].Links["a↔b"]; got.Resets != 1 || got.Samples != 0 || got.ReportingEndpoints != 0 {
		t.Fatalf("link reset attribution = %+v", got)
	}
	if got := buckets[2].Links["a↔b"]; got.Gaps != 1 || got.Resets != 1 || got.Samples != 0 {
		t.Fatalf("link gap/reset attribution = %+v", got)
	}
}

func TestPeerKeyChangeIsResetWithoutChangingLogicalLink(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := testStore(t)
	first := counter("a", "b", "wg-b", "boot/7", start, 100, 100)
	first.PeerPublicKey = "peer-key-v1"
	second := counter("a", "b", "wg-b", "boot/7", start.Add(time.Minute), 150, 160)
	second.PeerPublicKey = "peer-key-v2"
	appendFrame(t, store, start, []Counter{first})
	appendFrame(t, store, start.Add(time.Minute), []Counter{second})
	buckets, err := store.Query(start, start.Add(5*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := buckets[0].Nodes["a"]; got.Bytes != 0 || got.Resets != 1 {
		t.Fatalf("peer-key rotation was counted as traffic: %+v", got)
	}
	if got := buckets[0].Links["a↔b"]; got.From != "a" || got.To != "b" || got.Resets != 1 || got.Bytes != 0 {
		t.Fatalf("logical link did not stay stable through key rotation: %+v", got)
	}
}

func TestCompactRetentionAndAtomicPermissions(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	store := testStore(t)
	appendFrame(t, store, start, []Counter{counter("a", "b", "wg-b", "boot", start, 1, 1)})
	appendFrame(t, store, start.Add(48*time.Hour), []Counter{counter("a", "b", "wg-b", "boot", start.Add(48*time.Hour), 2, 2)})
	if err := store.Compact(start.Add(49 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	frames, err := loadFrames(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].CollectedAt != start.Add(48*time.Hour).Format(time.RFC3339) {
		t.Fatalf("retained frames = %+v", frames)
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("store mode = %04o", info.Mode().Perm())
	}
}

func TestAppendRejectsDuplicateAndInvalidCounters(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := testStore(t)
	c := counter("a", "b", "wg-b", "boot", now, 1, 1)
	if err := store.Append(Frame{CollectedAt: now.Format(time.RFC3339), Counters: []Counter{c, c}}); err == nil {
		t.Fatal("duplicate counter accepted")
	}
	c.RXBytes = -1
	if err := store.Append(Frame{CollectedAt: now.Format(time.RFC3339), Counters: []Counter{c}}); err == nil {
		t.Fatal("negative counter accepted")
	}
}

func TestAppendRejectsSymlinkAndBroadExistingFile(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	c := counter("a", "b", "wg-b", "boot", now, 1, 1)
	frame := Frame{CollectedAt: now.Format(time.RFC3339), Counters: []Counter{c}}

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkStore, err := NewStore(filepath.Join(dir, "link"), time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, symlinkStore.path); err != nil {
		t.Fatal(err)
	}
	if err := symlinkStore.Append(frame); err == nil {
		t.Fatal("symlink traffic store accepted")
	}

	broadPath := filepath.Join(dir, "broad.jsonl")
	if err := os.WriteFile(broadPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	broadStore, err := NewStore(broadPath, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := broadStore.Append(frame); err == nil {
		t.Fatal("broad traffic store permissions accepted")
	}
}

func TestQueryCacheSeesFramesAppendedAfterInitialEmptyLoad(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := testStore(t)
	if _, err := store.Query(start, start.Add(5*time.Minute), 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	appendFrame(t, store, start, []Counter{counter("a", "b", "wg-b", "boot", start, 10, 20)})
	appendFrame(t, store, start.Add(time.Minute), []Counter{counter("a", "b", "wg-b", "boot", start.Add(time.Minute), 20, 40)})
	buckets, err := store.Query(start, start.Add(5*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := buckets[0].Nodes["a"].Bytes; got != 30 {
		t.Fatalf("cached query bytes = %d, want 30", got)
	}
}

func TestQueryUsesOnlyNewestPreWindowSampleAsPredecessor(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := testStore(t)
	appendFrame(t, store, start.Add(-time.Hour), []Counter{
		counter("a", "b", "wg-b", "boot", start.Add(-time.Hour), 10, 20),
	})
	appendFrame(t, store, start.Add(-time.Minute), []Counter{
		counter("a", "b", "wg-b", "boot", start.Add(-time.Minute), 100, 200),
	})
	appendFrame(t, store, start.Add(time.Minute), []Counter{
		counter("a", "b", "wg-b", "boot", start.Add(time.Minute), 130, 240),
	})
	buckets, err := store.Query(start, start.Add(5*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := buckets[0].Nodes["a"]; got.RXBytes != 30 || got.TXBytes != 40 || got.Samples != 1 {
		t.Fatalf("window predecessor delta = %+v", got)
	}
}

func TestLoadIgnoresOnlyUnterminatedCrashTail(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := testStore(t)
	appendFrame(t, store, start, []Counter{counter("a", "b", "wg-b", "boot", start, 1, 1)})
	f, err := os.OpenFile(store.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"collected_at":"crash`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	frames, err := loadFrames(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames after crash tail = %d", len(frames))
	}
}

func TestCompactTruncatesCrashTailBeforeNextAppend(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := testStore(t)
	appendFrame(t, store, start, []Counter{counter("a", "b", "wg-b", "boot", start, 1, 1)})
	f, err := os.OpenFile(store.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"collected_at":"crash`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Model a restart: the new Store must load and canonicalize the file before
	// accepting another append.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(store.path, 24*time.Hour, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Compact(start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	appendFrame(t, restarted, start.Add(time.Minute), []Counter{
		counter("a", "b", "wg-b", "boot", start.Add(time.Minute), 2, 3),
	})
	frames, err := loadFrames(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames after crash-tail repair = %d, want 2", len(frames))
	}
}

func TestStoredGapPolicyDoesNotChangeAcrossRestart(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "traffic.jsonl")
	store, err := NewStore(path, 24*time.Hour, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	appendFrame(t, store, start, []Counter{counter("a", "b", "wg-b", "boot", start, 10, 20)})
	appendFrame(t, store, start.Add(time.Minute), []Counter{
		counter("a", "b", "wg-b", "boot", start.Add(time.Minute), 20, 40),
	})
	before, err := store.Query(start, start.Add(5*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(path, 24*time.Hour, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	after, err := restarted.Query(start, start.Add(5*time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if before[0].Nodes["a"].Bytes != 30 || after[0].Nodes["a"].Bytes != 30 || after[0].Gaps != 0 {
		t.Fatalf("stored sampling policy drifted across restart: before=%+v after=%+v", before[0], after[0])
	}
}

func TestStoreRejectsSecondProcessOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.jsonl")
	first, err := NewStore(path, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := NewStore(path, time.Hour, time.Minute); err == nil {
		_ = second.Close()
		t.Fatal("second Store acquired the same process lock")
	}
}

func TestLoadRejectsOversizedCommittedFrame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.jsonl")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", (1<<20)+1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFrames(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized frame error = %v", err)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "traffic.jsonl"), 24*time.Hour, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func counter(node, peer, iface, epoch string, at time.Time, rx, tx int64) Counter {
	return Counter{Node: node, Peer: peer, Interface: iface, Epoch: epoch,
		TS: at.UTC().Format(time.RFC3339), RXBytes: rx, TXBytes: tx}
}

func appendFrame(t *testing.T, store *Store, at time.Time, counters []Counter) {
	t.Helper()
	if err := store.Append(Frame{CollectedAt: at.UTC().Format(time.RFC3339), Counters: counters}); err != nil {
		t.Fatal(err)
	}
}
