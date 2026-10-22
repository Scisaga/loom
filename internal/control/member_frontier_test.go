package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMemberFrontierConfirmsUnchangedAuthorityThroughTLS(t *testing.T) {
	f := newMaterialFixture(t)
	var mu sync.Mutex
	paths := map[string]int{}
	statuses := []int{}
	bytes := 0
	peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(index int, next http.Handler) http.Handler {
		if index != 1 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := httptest.NewRecorder()
			next.ServeHTTP(recorder, r)
			mu.Lock()
			paths[r.URL.Path]++
			if r.URL.Path == "/internal/frontier" {
				statuses = append(statuses, recorder.Code)
				bytes += recorder.Body.Len()
			}
			mu.Unlock()
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
		})
	})
	a := peers[0].server.Runtime
	for range 2 {
		if err := a.reconcilePeerAttempt(context.Background(), f.members[1]); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	if paths["/internal/frontier"] != 2 || paths["/internal/control-proof"] != 0 || paths["/internal/material-conflicts"] != 0 || paths["/internal/report-ranges"] != 2 || bytes != 0 || len(statuses) != 2 || statuses[0] != http.StatusNotModified || statuses[1] != http.StatusNotModified {
		t.Error("unchanged authority still transferred separate metadata", paths, statuses, bytes)
	}
	mu.Unlock()
	accepted := submitAuthority(t, peers[1].server.Runtime, authorityService("demo-frontier-service", "demo-frontier-write"))
	if err := a.reconcilePeerAttempt(context.Background(), f.members[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authority.Material(accepted.MaterialID); err != nil {
		t.Fatal("frontier confirmation hid an ordinary fact", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if paths["/internal/control-proof"] != 0 || paths["/internal/material-conflicts"] != 0 || statuses[len(statuses)-1] != http.StatusOK {
		t.Fatal("ordinary fact needed a redundant proof or hid a changed frontier", paths, statuses)
	}
	closedRoot := a.Authority.root
	peers[0].close()
	reopened, err := OpenAuthority(closedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Material(accepted.MaterialID); err != nil {
		t.Fatal("frontier fact did not survive reopening", err)
	}
}

func TestMemberFrontierRequiresProofAndRepresentationConfirmation(t *testing.T) {
	f := newMaterialFixture(t)
	var mode atomic.Int32
	var proofReads, conflictReads atomic.Int32
	peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(index int, next http.Handler) http.Handler {
		if index != 1 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/internal/control-proof" {
				proofReads.Add(1)
			}
			if r.URL.Path == "/internal/material-conflicts" {
				conflictReads.Add(1)
			}
			recorder := httptest.NewRecorder()
			next.ServeHTTP(recorder, r)
			if r.URL.Path == "/internal/frontier" {
				switch mode.Load() {
				case 1:
					recorder.Header().Del(frontierProofHeader)
				case 2:
					recorder.Header().Set(frontierProofHeader, "\"demo-unverified-proof\"")
				case 3:
					recorder.Header().Set(frontierConflictsHeader, "demo-unknown")
				case 4:
					recorder.Header().Add(frontierConflictsHeader, "none")
				case 5:
					recorder.Header().Del("ETag")
				case 6:
					recorder.Header().Add("ETag", recorder.Header().Get("ETag"))
				}
			}
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
		})
	})
	a := peers[0].server.Runtime
	for _, fault := range []int32{1, 2, 3, 4} {
		mode.Store(fault)
		proofBefore, conflictsBefore := proofReads.Load(), conflictReads.Load()
		if err := a.reconcilePeerAttempt(context.Background(), f.members[1]); err != nil {
			t.Fatal("original proof/index path was unavailable", fault, err)
		}
		proofWant := int32(0)
		if fault <= 2 {
			proofWant = 1
		}
		if proofReads.Load()-proofBefore != proofWant || conflictReads.Load()-conflictsBefore != 1 {
			t.Fatal("an unconfirmed hint bypassed original verification", fault)
		}
	}
	for _, fault := range []int32{5, 6} {
		mode.Store(fault)
		if _, _, _, err := a.peerFrontier(context.Background(), f.members[1]); err == nil {
			t.Fatal("invalid 304 supplied a frontier", fault)
		}
	}
}
