package linuxclient

import (
	"context"
	"encoding/json"
	"fmt"
	"loom/protocol"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"loom/internal/clientadapter"
)

func TestHTTPSelectorReadsBoundedCandidateMetadata(t *testing.T) {
	const scope = "access"
	const secret = "demo-local-secret"
	for _, test := range []struct {
		name       string
		candidates int
		accepted   bool
	}{
		{"automatic network candidates exceed four KiB", 57, true},
		{"reply exceeds one MiB", clientadapter.SelectorReadbackLimit/74 + 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidates := make([]string, test.candidates)
			for i := range candidates {
				candidates[i] = fmt.Sprintf("sha256:%064x", i+1)
			}
			selected := candidates[len(candidates)-1]
			body, err := json.Marshal(map[string]any{"all": candidates, "history": []any{}, "name": scope, "now": selected, "type": "Selector", "udp": true, "revision": "1", "targets": map[string]string{}, "policy_id": "demo-policy", "choices": map[string]protocol.RouteChoice{selected: {FinalExit: "direct"}}})
			if err != nil {
				t.Fatal(err)
			}
			if test.accepted && (len(body) <= 4<<10 || len(body) > clientadapter.SelectorReadbackLimit) || !test.accepted && len(body) <= clientadapter.SelectorReadbackLimit {
				t.Fatal("fixture does not exercise its response size class", len(body))
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/proxies/"+scope || r.Header.Get("Authorization") != "Bearer "+secret {
					http.Error(w, "unexpected selector request", http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer server.Close()
			selector, err := NewHTTPSelector(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-local-secret"}}}`)
			if err != nil {
				t.Fatal(err)
			}
			selector.SetDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "127.0.0.1:61800" {
					return nil, fmt.Errorf("unexpected selector dial target")
				}
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			})
			value, err := selector.Read(context.Background(), scope)
			if test.accepted {
				if err != nil || value != selected {
					t.Fatal("authorized candidate metadata was rejected", value, err)
				}
				if err := waitSelector(context.Background(), selector, []string{scope}); err != nil {
					t.Fatal("startup selector readback failed", err)
				}
			} else if err == nil || value != "" {
				t.Fatal("oversized selector metadata was accepted", value, err)
			}
		})
	}
}
