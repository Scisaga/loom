package clientadapter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"loom/protocol"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSelectedCandidateHTTPSUsesOneAuthenticatedEntryAndOriginalTarget(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/demo-target" {
			t.Error("original target path changed")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer endpoint.Close()
	choice := protocol.RouteChoice{EntryNodeID: "demo-entry", FirstResourceID: "demo-resource", FinalExit: "demo-exit"}
	candidate, err := protocol.CandidateID("demo-service", "demo-policy", choice)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := json.Marshal(map[string]any{"now": candidate, "policy_id": "demo-policy", "revision": "demo-revision", "targets": map[string]string{}, "choices": map[string]protocol.RouteChoice{candidate: choice}})
	var relays sync.WaitGroup
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer demo-secret" {
			http.Error(w, "denied", 403)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/proxies/access" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(snapshot)
			return
		}
		key, _ := protocol.ConnectionTargetKey("tcp", strings.Split(strings.TrimPrefix(endpoint.URL, "https://"), ":")[0], uint16(endpoint.Listener.Addr().(*net.TCPAddr).Port))
		if r.Method != http.MethodConnect || r.URL.Path != "/loom/probe" || r.Header.Get("X-Loom-Target") != key || r.Header.Get("X-Loom-Scope") != "access" || r.Header.Get("X-Loom-Expected-Revision") != "demo-revision" {
			t.Error("probe lost complete source/target binding")
			http.Error(w, "denied", 403)
			return
		}
		remote, err := net.Dial("tcp", endpoint.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		local, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			remote.Close()
			t.Error(err)
			return
		}
		io.WriteString(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n")
		buffered.Flush()
		relays.Add(1)
		go func() {
			defer relays.Done()
			done := make(chan struct{})
			go func() { io.Copy(remote, buffered); remote.Close(); close(done) }()
			io.Copy(local, remote)
			local.Close()
			<-done
		}()
	}))
	defer api.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	diagnostic, err := NativeDiagnosticContext(ctx, "demo-secret", func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:61800" {
			return nil, errors.New("request escaped authenticated loopback")
		}
		return (&net.Dialer{}).DialContext(ctx, network, api.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	result := probeCandidateBusiness(WithCandidateScope(diagnostic, "access"), candidate, endpoint.URL+"/demo-target", endpoint.Client().Transport.(*http.Transport).TLSClientConfig)
	if !result.Available || result.Action != "https_request" || result.Target != endpoint.URL+"/demo-target" {
		t.Fatal("selected candidate request did not complete", result)
	}
	relays.Wait()
	if result := probeCandidateBusiness(diagnostic, candidate, endpoint.URL+"/demo-target", endpoint.Client().Transport.(*http.Transport).TLSClientConfig); !result.Deferred {
		t.Fatal("unscoped candidate request retained a retired diagnostic identity")
	}
}
