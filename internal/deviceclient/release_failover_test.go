package deviceclient

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

func privateReleaseWorkspace(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDownloadReleaseValidatesEachCandidateBeforeWriting(t *testing.T) {
	for _, scenario := range []string{"http-unavailable", "truncated", "wrong-length", "wrong-digest", "idle"} {
		t.Run(scenario, func(t *testing.T) {
			temporary := privateReleaseWorkspace(t)
			body := []byte("signed bytes")
			var requests, active, maximum atomic.Int32
			release := make(chan struct{})
			defer close(release)
			handler := func(primary bool) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					count := active.Add(1)
					defer active.Add(-1)
					for prior := maximum.Load(); count > prior && !maximum.CompareAndSwap(prior, count); prior = maximum.Load() {
					}
					if !primary {
						_, _ = w.Write(body)
						return
					}
					switch scenario {
					case "http-unavailable":
						w.WriteHeader(http.StatusServiceUnavailable)
					case "truncated":
						w.Header().Set("Content-Length", strconv.Itoa(len(body)))
						_, _ = w.Write(body[:len(body)-1])
					case "wrong-length":
						_, _ = w.Write(append(append([]byte{}, body...), '!'))
					case "wrong-digest":
						_, _ = w.Write(bytes.Repeat([]byte{'x'}, len(body)))
					case "idle":
						<-release // No response, despite completed TLS/device authentication.
					}
				}
			}
			fixture := newDeviceRequestFixture(t, handler(true), handler(false))
			request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			var destination bytes.Buffer
			destination.WriteString("existing prefix:")
			if err := DownloadReleaseTo(fixture.context(ctx), fixture.store, request, int64(len(body)), temporary, &destination); err != nil {
				t.Fatal("failed candidate blocked exact alternative", err)
			}
			if destination.String() != "existing prefix:"+string(body) || requests.Load() != 2 {
				t.Fatalf("failed candidate polluted caller output: %q requests=%d", destination.String(), requests.Load())
			}
			// An idle test server handler deliberately remains blocked until the
			// test exits. Actual client candidate sockets are still sequential.
			if scenario != "idle" && maximum.Load() != 1 {
				t.Fatal("download candidates ran concurrently")
			}
			entries, err := os.ReadDir(temporary)
			if err != nil || len(entries) != 0 {
				t.Fatal("download retained temporary candidate bytes", entries, err)
			}
		})
	}
}

func TestDownloadWriterFailureDoesNotReplayOrRetainCandidate(t *testing.T) {
	temporary := privateReleaseWorkspace(t)
	body := []byte("signed bytes")
	var requests atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write(body) }
	fixture := newDeviceRequestFixture(t, handler, handler)
	request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
	want := errors.New("demo caller storage failure")
	err := DownloadReleaseTo(fixture.context(context.Background()), fixture.store, request, int64(len(body)), temporary, failedReleaseWriter{want})
	if !errors.Is(err, want) || requests.Load() != 1 {
		t.Fatalf("caller storage failure retried another candidate: %v requests=%d", err, requests.Load())
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed caller storage retained temporary bytes", entries, err)
	}
}

func TestDownloadCancellationLeavesCallerUntouched(t *testing.T) {
	requested := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var alternative atomic.Int32
	fixture := newDeviceRequestFixture(t,
		func(w http.ResponseWriter, r *http.Request) { close(requested); <-release },
		func(w http.ResponseWriter, r *http.Request) {
			alternative.Add(1)
			_, _ = w.Write([]byte("signed bytes"))
		})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest([]byte("signed bytes"))}
	var destination bytes.Buffer
	done := make(chan error, 1)
	workspace := privateReleaseWorkspace(t)
	go func() {
		done <- DownloadReleaseTo(fixture.context(ctx), fixture.store, request, 12, workspace, &destination)
	}()
	select {
	case <-requested:
	case err := <-done:
		t.Fatal("download failed before the candidate started", err)
	case <-time.After(time.Second):
		t.Fatal("download candidate did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || destination.Len() != 0 || alternative.Load() != 0 {
			t.Fatal("cancellation wrote or replayed a partial download", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled download did not join its candidate")
	}
}

func TestReleaseReadIdleDeadlineRenewsAfterProgress(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	connection := &releaseIdleConnection{Conn: client, timeout: 50 * time.Millisecond}
	go func() { _, _ = server.Write([]byte("a")) }()
	var body [1]byte
	if _, err := connection.Read(body[:]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond) // The next read needs a fresh idle window.
	go func() { _, _ = server.Write([]byte("b")) }()
	if _, err := connection.Read(body[:]); err != nil || body[0] != 'b' {
		t.Fatal("progress inherited the previous read deadline", err)
	}
	if _, err := connection.Read(body[:]); err == nil {
		t.Fatal("stalled body read had no idle deadline")
	}
}
