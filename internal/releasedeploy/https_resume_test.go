package releasedeploy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"loom/internal/control"
)

func TestHTTPSBodyResumesOnlyExactRemainingBytes(t *testing.T) {
	const body = "demo immutable package payload for HTTPS reconnect"
	for _, mode := range []string{"resume", "full-response", "wrong-range", "corrupt-suffix", "exhausted", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls, resumes atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := calls.Add(1)
				if attempt == 1 {
					if r.Header.Get("Range") != "" {
						t.Error("initial request did not start at the full body")
					}
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					w.Header().Set("Connection", "close")
					fmt.Fprint(w, body[:6])
					if mode == "canceled" {
						cancel()
					}
					return
				}
				start := 6
				if mode == "exhausted" {
					start = 6 * int(attempt-1)
				}
				if r.Header.Get("Range") != fmt.Sprintf("bytes=%d-", start) {
					t.Error("resume requested different prefix coordinates", r.Header.Get("Range"))
				}
				if mode == "full-response" {
					fmt.Fprint(w, body)
					return
				}
				declared := start
				if mode == "wrong-range" {
					declared++
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", declared, len(body)-1, len(body)))
				w.Header().Set("Content-Length", strconv.Itoa(len(body)-start))
				w.Header().Set("Connection", "close")
				w.WriteHeader(http.StatusPartialContent)
				suffix := body[start:]
				if mode == "corrupt-suffix" {
					suffix = strings.Repeat("x", len(suffix))
				} else if mode == "exhausted" {
					suffix = suffix[:6]
				}
				fmt.Fprint(w, suffix)
			}))
			defer server.Close()
			artifact := demoPublicArtifact(body)
			set := control.ReleaseSet{Catalog: control.ReleaseCatalog{Entries: []control.ReleaseEntry{{Artifact: artifact}}}}
			verified := false
			err := verifyHTTPS(ctx, server.Client(), []string{server.URL + "/"}, set, func(v Result) {
				if v.Operation == "https_artifact_resume" {
					resumes.Add(1)
					if v.Attempt < 2 || v.Attempt > 3 || v.ReadBytes == 0 {
						t.Error("reconnect diagnostics lost its original prefix", v)
					}
				}
				if v.Operation == "https_artifact" && v.Verified {
					verified = true
					if v.ReadBytes != int64(len(body)) {
						t.Error("partial length became a verified body")
					}
				}
			}, nil)
			wantSuccess := mode == "resume" || mode == "full-response"
			if (err == nil) != wantSuccess || verified != wantSuccess {
				t.Fatal("reconnect did not retain complete-body acceptance", err)
			}
			wantCalls := int32(2)
			if mode == "exhausted" {
				wantCalls = 3
			} else if mode == "canceled" {
				wantCalls = 1
			}
			if calls.Load() != wantCalls || mode == "canceled" && resumes.Load() != 0 {
				t.Fatal("reconnect exceeded its bound or retried canceled work", calls.Load(), resumes.Load())
			}
		})
	}
}
