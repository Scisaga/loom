package clientrelease

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

type packageCacheWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (ctx *packageCacheWaitContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}

type capturedOpenResult struct {
	reader io.ReadCloser
	err    error
}

func awaitCapturedOpen(t *testing.T, result <-chan capturedOpenResult) capturedOpenResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("captured package operation did not finish")
		return capturedOpenResult{}
	}
}

func awaitPackageCacheWait(t *testing.T, waiting <-chan struct{}) {
	t.Helper()
	select {
	case <-waiting:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach the occupied package cache lock")
	}
}

// The full archive validator is independently exercised with signed originals.
// These inputs isolate the new mutex boundary after each real capture/hash.
func capturedOpenFixture(t *testing.T) (*Store, control.ReleasePackage, func() *capturedArtifact) {
	t.Helper()
	root := transferTestDiskRoot(t)
	store, err := New(root, make(ed25519.PublicKey, ed25519.PublicKeySize))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("demo package body\n"), 10000)
	entry := demoBootstrapEntries()[0]
	entry.Artifact.Digest, entry.Artifact.Size = control.ReleaseDigest(body), control.U64(len(body))
	writeProjectionFile(t, root, digestPath("bin", entry.Artifact.Digest, ""), body)
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	pkg := control.ReleasePackage{Entry: entry, ManifestBody: []byte("demo original manifest"), Signature: bytes.Repeat([]byte{1}, ed25519.SignatureSize)}
	return store, pkg, func() *capturedArtifact {
		input, err := store.captureArtifact(context.Background(), opened, entry.Artifact)
		if err != nil {
			t.Fatal(err)
		}
		return input
	}
}

func assertNoPackageCaptures(t *testing.T, store *Store) {
	t.Helper()
	if entries, err := os.ReadDir(store.workRoot); err != nil || len(entries) != 0 {
		t.Fatal("package request retained temporary bytes", err)
	}
}

func TestConcurrentColdPackageOpenInspectsOnce(t *testing.T) {
	store, pkg, capture := capturedOpenFixture(t)
	firstInput, secondInput := capture(), capture()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(finish)
	var calls atomic.Int32
	inspect := func(context.Context, *capturedArtifact, control.ReleasePackage) (control.ReleasePackage, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return pkg, nil
	}
	first, second := make(chan capturedOpenResult, 1), make(chan capturedOpenResult, 1)
	go func() {
		reader, err := store.openCaptured(context.Background(), firstInput, pkg, inspect)
		first <- capturedOpenResult{reader, err}
	}()
	awaitPackageCacheWait(t, entered)
	waiter := &packageCacheWaitContext{Context: context.Background(), waiting: make(chan struct{})}
	go func() {
		reader, err := store.openCaptured(waiter, secondInput, pkg, inspect)
		second <- capturedOpenResult{reader, err}
	}()
	awaitPackageCacheWait(t, waiter.waiting)
	if calls.Load() != 1 {
		t.Fatal("concurrent cold request began a duplicate archive inspection")
	}
	finish()
	for _, result := range []capturedOpenResult{awaitCapturedOpen(t, first), awaitCapturedOpen(t, second)} {
		if result.err != nil || result.reader == nil {
			t.Fatal("same captured package could not share the completed parse", result.err)
		}
		if err := result.reader.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 || len(store.packages) != 1 {
		t.Fatal("completed cold parsing was repeated or not cached")
	}
	assertNoPackageCaptures(t, store)
}

func TestWaitingPackageOpenCancellationCleansCaptureWithoutLock(t *testing.T) {
	store, pkg, capture := capturedOpenFixture(t)
	input := capture()
	store.mu.Lock()
	defer store.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiter := &packageCacheWaitContext{Context: ctx, waiting: make(chan struct{})}
	var calls atomic.Int32
	result := make(chan capturedOpenResult, 1)
	go func() {
		reader, err := store.openCaptured(waiter, input, pkg, func(context.Context, *capturedArtifact, control.ReleasePackage) (control.ReleasePackage, error) {
			calls.Add(1)
			return pkg, nil
		})
		result <- capturedOpenResult{reader, err}
	}()
	awaitPackageCacheWait(t, waiter.waiting)
	cancel()
	value := awaitCapturedOpen(t, result)
	if value.reader != nil || !errors.Is(value.err, context.Canceled) || calls.Load() != 0 || len(store.packages) != 0 {
		t.Fatal("cancelled waiter required the occupied lock or entered inspection", value.err)
	}
	assertNoPackageCaptures(t, store)
}

func TestCancelledColdPackageOpenLetsNextRequestRebuildCache(t *testing.T) {
	store, pkg, capture := capturedOpenFixture(t)
	firstInput, secondInput := capture(), capture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	var calls atomic.Int32
	inspect := func(ctx context.Context, _ *capturedArtifact, _ control.ReleasePackage) (control.ReleasePackage, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			// Even a validator finishing just after cancellation cannot commit.
			return pkg, nil
		}
		if len(store.packages) != 0 {
			return control.ReleasePackage{}, errors.New("cancelled parse populated the cache")
		}
		return pkg, nil
	}
	first, second := make(chan capturedOpenResult, 1), make(chan capturedOpenResult, 1)
	go func() {
		reader, err := store.openCaptured(ctx, firstInput, pkg, inspect)
		first <- capturedOpenResult{reader, err}
	}()
	awaitPackageCacheWait(t, entered)
	waiter := &packageCacheWaitContext{Context: context.Background(), waiting: make(chan struct{})}
	go func() {
		reader, err := store.openCaptured(waiter, secondInput, pkg, inspect)
		second <- capturedOpenResult{reader, err}
	}()
	awaitPackageCacheWait(t, waiter.waiting)
	cancel()
	if value := awaitCapturedOpen(t, first); value.reader != nil || !errors.Is(value.err, context.Canceled) {
		t.Fatal("cancelled cold parse became a downloadable result", value.err)
	}
	value := awaitCapturedOpen(t, second)
	if value.err != nil || value.reader == nil {
		t.Fatal("next request could not complete a fresh parse", value.err)
	}
	if err := value.reader.Close(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(store.packages) != 1 {
		t.Fatal("next request reused a cancelled parse or did not cache its completed parse")
	}
	assertNoPackageCaptures(t, store)
}
