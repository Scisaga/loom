package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

const (
	frontierProofHeader     = "Loom-Control-Proof"
	frontierConflictsHeader = "Loom-Material-Conflicts"
	factsChangedHeader      = "Loom-Facts-Changed"
)

func (server *Server) internalFrontier(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		http.Error(w, "fact frontier query is invalid", http.StatusBadRequest)
		return
	}
	if values := r.Header.Values(factsChangedHeader); len(values) != 0 {
		if len(values) != 1 || values[0] != "1" {
			http.Error(w, "invalid member change hint", http.StatusBadRequest)
			return
		}
		// The ordinary private handler has authenticated the current member.
		// Only schedule the existing pull; the hint is never an authority input.
		select {
		case server.Runtime.wake <- struct{}{}:
		default:
		}
	}
	body, proofETag, noConflicts, err := server.Runtime.Authority.frontierRepresentation()
	if err != nil {
		http.Error(w, "fact frontier unavailable", http.StatusServiceUnavailable)
		return
	}
	etag := canonicalETag(body)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", etag)
	w.Header().Set(frontierProofHeader, proofETag)
	conflicts := "present"
	if noConflicts {
		conflicts = "none"
	}
	w.Header().Set(frontierConflictsHeader, conflicts)
	if len(r.Header.Values("If-None-Match")) == 1 && r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// One authority snapshot: equal frontiers alone cannot exclude old forks or
// confirm the complete member proof. No representation survives this request.
func (a *Authority) frontierRepresentation() ([]byte, string, bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	proof, err := a.controlProofLocked()
	if err != nil {
		return nil, "", false, err
	}
	_, proofETag, err := controlProofRepresentation(proof)
	if err != nil {
		return nil, "", false, err
	}
	conflicts, err := a.materialConflictsAfterLocked("")
	if err != nil {
		return nil, "", false, err
	}
	body, err := CanonicalEncode(a.projection.Frontier)
	return body, proofETag, len(conflicts.MaterialIDs) == 0, err
}

func (runtime *Runtime) peerFrontier(ctx context.Context, member Member) ([]FactFrontier, bool, bool, error) {
	proof, err := runtime.Authority.ControlProof()
	if err != nil {
		return nil, false, false, err
	}
	_, proofETag, err := controlProofRepresentation(proof)
	if err != nil {
		return nil, false, false, err
	}
	known, err := CanonicalEncode(runtime.Authority.Frontier())
	if err != nil {
		return nil, false, false, err
	}
	etag := canonicalETag(known)
	header := http.Header{"If-None-Match": {etag}}
	if scope, ok := ctx.Value(memberHTTPAttemptKey{}).(memberHTTPAttempt); ok && scope.factsChanged {
		header.Set(factsChangedHeader, "1")
	}
	var confirmed, noConflicts bool
	body, err := runtime.peerRead(ctx, member, http.MethodGet, "/internal/frontier", nil, header, func(response *http.Response) ([]byte, error) {
		confirmed = len(response.Header.Values(frontierProofHeader)) == 1 && response.Header.Get(frontierProofHeader) == proofETag
		noConflicts = len(response.Header.Values(frontierConflictsHeader)) == 1 && response.Header.Get(frontierConflictsHeader) == "none"
		switch response.StatusCode {
		case http.StatusNotModified:
			if !confirmedRepresentation(response, etag) {
				return nil, errors.New("unchanged member frontier was not confirmed")
			}
			return known, nil
		case http.StatusOK:
			return readPeerResponseBody(response, 64<<20)
		default:
			return nil, fmt.Errorf("private member frontier failed: HTTP %d", response.StatusCode)
		}
	})
	if err != nil {
		return nil, false, false, err
	}
	var remote []FactFrontier
	if err := DecodeCanonical(body, &remote, ContractDecodeLimits{MaxBytes: 64 << 20, MaxDepth: 64, MaxItems: 1 << 20}); err != nil {
		return nil, false, false, err
	}
	return remote, confirmed, noConflicts, nil
}
