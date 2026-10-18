package deviceclient

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
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
	for _, scenario := range []string{"http-unavailable", "truncated", "wrong-length", "wrong-digest", "header-idle", "body-idle", "partial-body-idle"} {
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
					case "header-idle":
						<-release // No response, despite completed TLS/device authentication.
					case "body-idle", "partial-body-idle":
						w.Header().Set("Content-Length", strconv.Itoa(len(body)))
						w.WriteHeader(http.StatusOK)
						if scenario == "partial-body-idle" {
							_, _ = w.Write(body[:len(body)/2])
						}
						w.(http.Flusher).Flush()
						<-release
					}
				}
			}
			fixture := newDeviceRequestFixture(t, handler(true), handler(false))
			request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			firstClosed := make(chan struct{})
			ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == "192.0.2.2:443" {
					select {
					case <-firstClosed:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				connection, err := fixture.dial(ctx, network, address)
				if err == nil && address == "192.0.2.1:443" {
					connection = &releaseCloseSignalConnection{Conn: connection, closed: firstClosed}
				}
				return connection, err
			})
			var destination bytes.Buffer
			destination.WriteString("existing prefix:")
			if err := downloadReleaseTo(ctx, fixture.store, request, int64(len(body)), temporary, &destination, 500*time.Millisecond, 100*time.Millisecond); err != nil {
				t.Fatal("failed candidate blocked exact alternative", err)
			}
			if destination.String() != "existing prefix:"+string(body) || requests.Load() != 2 {
				t.Fatalf("failed candidate polluted caller output: %q requests=%d", destination.String(), requests.Load())
			}
			// The alternative's delayed authentication exposes the first failure.
			// Idle server handlers remain blocked after that socket was closed.
			if scenario != "header-idle" && scenario != "body-idle" && scenario != "partial-body-idle" && maximum.Load() != 1 {
				t.Fatal("delayed alternative started before first handler returned")
			}
			entries, err := os.ReadDir(temporary)
			if err != nil || len(entries) != 0 {
				t.Fatal("download retained temporary candidate bytes", entries, err)
			}
		})
	}
}

func TestDownloadSeparatesHeaderPreparationFromProgressingBody(t *testing.T) {
	for _, scenario := range []string{"header-preparation", "progressing-body"} {
		t.Run(scenario, func(t *testing.T) {
			body := []byte("signed release bytes")
			fixture := newDeviceRequestFixture(t,
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					if scenario == "header-preparation" {
						time.Sleep(250 * time.Millisecond) // Valid preparation exceeds the body idle budget.
						_, _ = w.Write(body)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					for _, value := range body {
						_, _ = w.Write([]byte{value})
						w.(http.Flusher).Flush()
						time.Sleep(30 * time.Millisecond)
					}
				})
			request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			var destination bytes.Buffer
			if err := downloadReleaseTo(fixture.context(ctx), fixture.store, request, int64(len(body)), privateReleaseWorkspace(t), &destination, 500*time.Millisecond, 150*time.Millisecond); err != nil {
				t.Fatal("valid preparation or progressing body lost its own I/O budget", err)
			}
			if !bytes.Equal(destination.Bytes(), body) {
				t.Fatal("valid download changed")
			}
		})
	}
}

func TestDownloadWriterFailureDoesNotReplayOrRetainCandidate(t *testing.T) {
	temporary := privateReleaseWorkspace(t)
	body := []byte("signed bytes")
	var requests atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write(body) }
	fixture := newDeviceRequestFixture(t, handler, handler, handler)
	request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
	want := errors.New("demo caller storage failure")
	err := DownloadReleaseTo(fixture.context(context.Background()), fixture.store, request, int64(len(body)), temporary, failedReleaseWriter{want})
	if !errors.Is(err, want) || requests.Load() < 1 || requests.Load() > 2 {
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
	var requests atomic.Int32
	var requestedOnce sync.Once
	handler := func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		requestedOnce.Do(func() { close(requested) })
		<-release
	}
	fixture := newDeviceRequestFixture(t,
		handler, handler, handler)
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
		if !errors.Is(err, context.Canceled) || destination.Len() != 0 || requests.Load() > 2 {
			t.Fatal("cancellation wrote or replayed a partial download", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled download did not join its candidate")
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 0 {
		t.Fatal("canceled download retained candidate bytes", entries, err)
	}
}

func TestDownloadCallerDeadlineBoundsBothReadBudgets(t *testing.T) {
	for _, scenario := range []string{"headers", "body"} {
		t.Run(scenario, func(t *testing.T) {
			requested := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			body := []byte("signed bytes")
			fixture := newDeviceRequestFixture(t,
				func(w http.ResponseWriter, r *http.Request) {
					if scenario == "body" {
						w.Header().Set("Content-Length", strconv.Itoa(len(body)))
						_, _ = w.Write(body[:len(body)/2])
						w.(http.Flusher).Flush()
					}
					close(requested)
					<-release
				})
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
			workspace := privateReleaseWorkspace(t)
			var destination bytes.Buffer
			done := make(chan error, 1)
			go func() {
				done <- downloadReleaseTo(fixture.context(ctx), fixture.store, request, int64(len(body)), workspace, &destination, time.Second, time.Second)
			}()
			select {
			case <-requested:
			case err := <-done:
				t.Fatal("caller deadline expired before the read started", err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) || destination.Len() != 0 {
					t.Fatal("I/O budget overrode caller deadline or replayed partial bytes", err)
				}
			case <-time.After(time.Second):
				t.Fatal("caller deadline did not join its download candidate")
			}
		})
	}
}

type releaseCloseSignalConnection struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (connection *releaseCloseSignalConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(func() { close(connection.closed) })
	return err
}

func TestDownloadFastCompleteCandidateCancelsProgressingSlowBody(t *testing.T) {
	for _, scenario := range []string{"signed-prefix", "wrong-prefix"} {
		t.Run(scenario, func(t *testing.T) {
			workspace := privateReleaseWorkspace(t)
			body := bytes.Repeat([]byte("signed bytes"), 1024)
			slowBody := body
			if scenario == "wrong-prefix" {
				slowBody = bytes.Repeat([]byte{'x'}, len(body))
			}
			progress := make(chan struct{})
			slowClosed := make(chan struct{})
			var third atomic.Int32
			fixture := newDeviceRequestFixture(t,
				func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					for offset := 0; offset < len(body); offset += 128 {
						if _, err := w.Write(slowBody[offset : offset+128]); err != nil {
							return
						}
						w.(http.Flusher).Flush()
						if offset == 256 {
							close(progress)
						}
						time.Sleep(30 * time.Millisecond)
					}
				},
				func(w http.ResponseWriter, r *http.Request) {
					<-progress
					entries, err := os.ReadDir(workspace)
					if err != nil || len(entries) != 2 {
						t.Error("parallel candidates did not own two separate files", entries, err)
					}
					for _, entry := range entries {
						info, err := entry.Info()
						if err != nil || info.Mode().Perm()&0077 != 0 {
							t.Error("candidate file was not protected", err)
						}
					}
					_, _ = w.Write(body)
				},
				func(w http.ResponseWriter, r *http.Request) { third.Add(1) })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == "192.0.2.3:443" {
					third.Add(1)
				}
				connection, err := fixture.dial(ctx, network, address)
				if err == nil && address == "192.0.2.1:443" {
					connection = &releaseCloseSignalConnection{Conn: connection, closed: slowClosed}
				}
				return connection, err
			})
			request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
			var destination bytes.Buffer
			if err := downloadReleaseTo(ctx, fixture.store, request, int64(len(body)), workspace, &destination, time.Second, 150*time.Millisecond); err != nil {
				t.Fatal("progressing slow body consumed the fast candidate's opportunity", err)
			}
			select {
			case <-slowClosed:
			default:
				t.Fatal("winner returned before the slow connection closed")
			}
			if !bytes.Equal(destination.Bytes(), body) || third.Load() != 0 {
				t.Fatal("download changed bytes or exceeded two active candidates", third.Load())
			}
			entries, err := os.ReadDir(workspace)
			if err != nil || len(entries) != 0 {
				t.Fatal("winner or canceled loser retained candidate bytes", entries, err)
			}
		})
	}
}

func TestDownloadAllInvalidCandidatesLeaveCallerAndWorkspaceUntouched(t *testing.T) {
	workspace := privateReleaseWorkspace(t)
	body := []byte("signed bytes")
	var requests atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		entries, err := os.ReadDir(workspace)
		if err != nil || len(entries) > 2 {
			t.Error("failed candidate files survived into another active attempt", entries, err)
		}
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, len(body)))
	}
	fixture := newDeviceRequestFixture(t, handler, handler, handler)
	before, err := os.ReadFile(fixture.store.path)
	if err != nil {
		t.Fatal(err)
	}
	request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
	var destination bytes.Buffer
	destination.WriteString("existing prefix:")
	if err := DownloadReleaseTo(fixture.context(context.Background()), fixture.store, request, int64(len(body)), workspace, &destination); err == nil {
		t.Fatal("accepted wrong digest from an alternative")
	}
	if destination.String() != "existing prefix:" || requests.Load() != 3 {
		t.Fatal("failed candidates wrote or did not try the remaining alternative", destination.String(), requests.Load())
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed candidates retained protected files", entries, err)
	}
	after, err := os.ReadFile(fixture.store.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only download changed device identity, LKG or progress", err)
	}
}

func TestDownloadLaterCandidateGetsBudgetAfterTwoProgressingSlowBodies(t *testing.T) {
	workspace := privateReleaseWorkspace(t)
	body := bytes.Repeat([]byte("signed bytes"), 1024)
	var starts atomic.Int32
	started := make(chan struct{})
	slow := func(w http.ResponseWriter, r *http.Request) {
		if starts.Add(1) == 2 {
			close(started)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		for offset := 0; offset < len(body); offset += 128 {
			if _, err := w.Write(body[offset : offset+128]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(30 * time.Millisecond)
		}
	}
	var last atomic.Int32
	fixture := newDeviceRequestFixture(t, slow, slow, func(w http.ResponseWriter, r *http.Request) {
		last.Add(1)
		_, _ = w.Write(body)
	})
	firstClosed, secondClosed := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "192.0.2.3:443" {
			select {
			case <-started:
			default:
				t.Error("later candidate started before the first two occupied their slots")
			}
			select {
			case <-firstClosed:
			case <-secondClosed:
			default:
				t.Error("later candidate exceeded the two-request bound")
			}
		}
		connection, err := fixture.dial(ctx, network, address)
		if err == nil && address == "192.0.2.1:443" {
			connection = &releaseCloseSignalConnection{Conn: connection, closed: firstClosed}
		} else if err == nil && address == "192.0.2.2:443" {
			connection = &releaseCloseSignalConnection{Conn: connection, closed: secondClosed}
		}
		return connection, err
	})
	request := control.DeviceReleaseDownload{Schema: 3, Platform: "linux-amd64", ViewDigest: fixture.store.LKG().ViewDigest, CatalogDigest: control.ReleaseDigest([]byte("demo-catalog")), ArtifactDigest: control.ReleaseDigest(body)}
	var destination bytes.Buffer
	destination.WriteString("existing prefix:")
	if err := downloadReleaseTo(ctx, fixture.store, request, int64(len(body)), workspace, &destination, time.Second, 150*time.Millisecond); err != nil {
		t.Fatal("first two progressing bodies consumed the later endpoint's opportunity", err)
	}
	if destination.String() != "existing prefix:"+string(body) || last.Load() != 1 {
		t.Fatal("later complete candidate did not win without prefix pollution", last.Load())
	}
	for _, closed := range []chan struct{}{firstClosed, secondClosed} {
		select {
		case <-closed:
		default:
			t.Fatal("winner returned before a progressing loser closed")
		}
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 0 {
		t.Fatal("wave timeout or winning candidate retained protected files", entries, err)
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

type releaseReadSignalConnection struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (connection *releaseReadSignalConnection) Read(body []byte) (int, error) {
	connection.once.Do(func() { close(connection.started) })
	return connection.Conn.Read(body)
}

func TestReleaseBodyDeadlineReplacesPendingHeaderRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	read := &releaseReadSignalConnection{Conn: client, started: make(chan struct{})}
	connection := &releaseIdleConnection{Conn: read, timeout: 50 * time.Millisecond, readTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() {
		var body [1]byte
		_, err := connection.Read(body[:])
		done <- err
	}()
	<-read.started // net/http can have this body read pending when headers return.
	if err := connection.setReadTimeout(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("pending body read did not use its idle deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending body read retained the header preparation deadline")
	}
}
