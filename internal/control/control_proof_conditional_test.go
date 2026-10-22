package control

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestControlProofConditionalReadThroughMemberTLS(t *testing.T) {
	f := newMaterialFixture(t)
	type received struct {
		status, bytes int
		condition     string
	}
	reads := make(chan received, 16)
	var fault atomic.Int32
	peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(index int, next http.Handler) http.Handler {
		if index != 1 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/internal/control-proof" && fault.Load() != 4 {
				next.ServeHTTP(w, r)
				return
			}
			switch fault.Load() {
			case 1: // An unconfirmed 304 cannot manufacture a remote proof.
				w.WriteHeader(http.StatusNotModified)
				return
			case 2:
				w.Header().Set("ETag", "\"demo-wrong-proof\"")
				w.WriteHeader(http.StatusNotModified)
				return
			case 3:
				w.Header().Add("ETag", r.Header.Get("If-None-Match"))
				w.Header().Add("ETag", r.Header.Get("If-None-Match"))
				w.WriteHeader(http.StatusNotModified)
				return
			case 4:
				w.WriteHeader(http.StatusNotModified)
				return
			}
			recorder := httptest.NewRecorder()
			next.ServeHTTP(recorder, r)
			reads <- received{recorder.Code, recorder.Body.Len(), r.Header.Get("If-None-Match")}
			for name, values := range recorder.Header() {
				w.Header()[name] = append([]string(nil), values...)
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
		})
	})
	a := peers[0].server.Runtime
	proof, err := a.Authority.ControlProof()
	if err != nil {
		t.Fatal(err)
	}
	original, etag, err := controlProofRepresentation(proof)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := a.memberClients(f.members[1])
	if err != nil {
		t.Fatal(err)
	}
	defer clients.close()
	ctx := context.WithValue(context.Background(), memberHTTPAttemptKey{}, clients)
	for range 2 {
		body, err := a.peerBody(ctx, f.members[1], http.MethodGet, "/internal/control-proof", nil)
		if err != nil || !bytes.Equal(body, original) {
			t.Fatalf("confirmed proof did not preserve its original: %v", err)
		}
		read := <-reads
		if read.status != http.StatusNotModified || read.bytes != 0 || read.condition != etag {
			t.Fatalf("identical proof was transferred again: %+v", read)
		}
	}
	for _, condition := range []string{"", "\"demo-other-proof\"", "W/" + etag} {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://control.loom/internal/control-proof", nil)
		if condition != "" {
			request.Header.Set("If-None-Match", condition)
		}
		response, err := clients.proof.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("ETag") != etag || !bytes.Equal(body, original) {
			t.Fatalf("unmatched condition lost the complete proof: %v", readErr)
		}
		<-reads
	}
	for mode := int32(1); mode <= 3; mode++ {
		fault.Store(mode)
		if _, err := a.peerBody(ctx, f.members[1], http.MethodGet, "/internal/control-proof", nil); err == nil {
			t.Fatalf("invalid proof confirmation accepted: %d", mode)
		}
	}
	fault.Store(4)
	if _, err := a.peerBody(ctx, f.members[1], http.MethodGet, "/internal/frontier", nil); err == nil {
		t.Fatal("body-free response was accepted outside the proof entry")
	}
	after, err := a.Authority.ControlProof()
	if err != nil {
		t.Fatal(err)
	}
	afterBody, err := CanonicalEncode(after)
	if err != nil || !bytes.Equal(afterBody, original) {
		t.Fatal("conditional reads or invalid confirmations changed authority", err)
	}
}
