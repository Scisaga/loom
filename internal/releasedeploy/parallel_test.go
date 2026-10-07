package releasedeploy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

func TestIndependentNodesOverlapAndSameNodeStopsOnFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := make(chan struct{})
	failed := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	failure := errors.New("demo node failure")
	var forbidden atomic.Bool
	go func() {
		done <- parallelByNode(ctx, []string{"demo-a", "demo-a", "demo-b"}, func(i int) error {
			switch i {
			case 0:
				select {
				case <-started:
				case <-ctx.Done():
					return ctx.Err()
				}
				close(failed)
				return failure
			case 1:
				forbidden.Store(true)
			case 2:
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		})
	}()
	select {
	case <-failed:
	case <-ctx.Done():
		close(release)
		<-done
		t.Fatal("independent node never ran concurrently")
	}
	select {
	case err := <-done:
		close(release)
		t.Fatal("returned while a node was still running", err)
	default:
	}
	close(release)
	if err := <-done; !errors.Is(err, failure) || forbidden.Load() {
		t.Fatal("lost failure or ran dependent work after it", err)
	}
}

func TestHTTPSRootsOverlapAndRequireCompleteBodies(t *testing.T) {
	body := "demo artifact"
	entry := control.ReleaseEntry{Artifact: control.ReleaseArtifact{Digest: control.ReleaseDigest([]byte(body)), Size: control.U64(len(body))}}
	set := control.ReleaseSet{Catalog: control.ReleaseCatalog{Entries: []control.ReleaseEntry{entry}}}
	for _, truncated := range []bool{false, true} {
		barrier := pairedOperations()
		var closed atomic.Int64
		client := &http.Client{Transport: demoHTTP(func(r *http.Request) (*http.Response, error) {
			if err := barrier(r.Context(), "https"); err != nil {
				return nil, err
			}
			text := body
			if truncated && r.URL.Host == "b.example" {
				text = "demo"
			}
			return &http.Response{StatusCode: http.StatusOK, Body: &closedBody{Reader: strings.NewReader(text), closed: &closed}}, nil
		})}
		err := verifyHTTPS(context.Background(), client, []string{"https://a.example/", "https://b.example/"}, set, func(Result) {})
		if (err != nil) != truncated || closed.Load() != 2 {
			t.Fatal("HTTPS result ignored content or left a response running", err, closed.Load())
		}
	}
}

type closedBody struct {
	io.Reader
	closed *atomic.Int64
}

func (b *closedBody) Close() error { b.closed.Add(1); return nil }
