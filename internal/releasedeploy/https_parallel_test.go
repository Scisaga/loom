package releasedeploy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

func TestHTTPSArtifactsOverlapWithinBoundAndDrainBeforeResult(t *testing.T) {
	for _, corrupted := range []bool{false, true} {
		t.Run(fmt.Sprint("corrupted=", corrupted), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			entries := []control.ReleaseEntry{}
			bodies := map[string]string{}
			for i := range 5 {
				body := fmt.Sprintf("demo immutable artifact %d", i)
				artifact := demoPublicArtifact(body)
				entries = append(entries, control.ReleaseEntry{Artifact: artifact})
				bodies[strings.TrimPrefix(artifact.Digest, "sha256:")] = body
			}
			started := make(chan struct{}, len(entries))
			firstReleased, restReleased := make(chan struct{}), make(chan struct{})
			var active, maximum, closed, requests atomic.Int64
			var rootVerified atomic.Bool
			client := &http.Client{Transport: demoHTTP(func(request *http.Request) (*http.Response, error) {
				body := bodies[strings.TrimPrefix(request.URL.Path, "/bin/")]
				if body == "" {
					return nil, fmt.Errorf("unexpected artifact path")
				}
				current := active.Add(1)
				for old := maximum.Load(); current > old && !maximum.CompareAndSwap(old, current); old = maximum.Load() {
				}
				gate := restReleased
				if requests.Add(1) == 1 {
					gate = firstReleased
					if corrupted {
						body = strings.Repeat("x", len(body))
					}
				}
				started <- struct{}{}
				return &http.Response{StatusCode: http.StatusOK, Body: &artifactBarrierBody{
					Reader: strings.NewReader(body), ctx: request.Context(), gate: gate,
					active: &active, closed: &closed,
				}}, nil
			})}
			finished := make(chan struct{})
			var result error
			go func() {
				result = verifyHTTPS(ctx, client, []string{"https://demo.example/"}, control.ReleaseSet{Catalog: control.ReleaseCatalog{Entries: entries}}, func(value Result) {
					if value.Operation == "https" && value.Verified {
						rootVerified.Store(true)
					}
				}, nil)
				close(finished)
			}()
			defer func() { cancel(); <-finished }()
			for range 4 {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("independent artifact bodies did not overlap")
				}
			}
			if active.Load() != 4 || maximum.Load() != 4 || closed.Load() != 0 {
				t.Fatal("artifact concurrency did not retain exactly four active bodies")
			}
			select {
			case <-started:
				t.Fatal("more than four artifact bodies were started")
			default:
			}
			close(firstReleased)
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("remaining independent artifact was not checked after the first result")
			}
			select {
			case <-finished:
				t.Fatal("HTTPS returned while started bodies remained open")
			default:
			}
			close(restReleased)
			<-finished
			if (result != nil) != corrupted || rootVerified.Load() == corrupted || active.Load() != 0 || closed.Load() != 5 || maximum.Load() != 4 {
				t.Fatal("HTTPS lost a failure, exceeded its bound, or left bodies running", result, active.Load(), closed.Load(), maximum.Load())
			}
		})
	}
}

type artifactBarrierBody struct {
	io.Reader
	ctx            context.Context
	gate           <-chan struct{}
	active, closed *atomic.Int64
}

func (body *artifactBarrierBody) Read(value []byte) (int, error) {
	select {
	case <-body.gate:
		return body.Reader.Read(value)
	case <-body.ctx.Done():
		return 0, body.ctx.Err()
	}
}

func (body *artifactBarrierBody) Close() error {
	body.closed.Add(1)
	body.active.Add(-1)
	return nil
}
