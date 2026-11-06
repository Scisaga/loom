package clientadapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
		{"reply exceeds one MiB", SelectorReadbackLimit/74 + 2, false},
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
			if test.accepted && (len(body) <= 4<<10 || len(body) > SelectorReadbackLimit) || !test.accepted && len(body) <= SelectorReadbackLimit {
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
			transport := selector.client.Transport.(*http.Transport)
			defer transport.CloseIdleConnections()
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "127.0.0.1:61800" {
					return nil, fmt.Errorf("unexpected selector dial target")
				}
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			value, err := selector.Read(context.Background(), scope)
			if test.accepted {
				if err != nil || value != selected {
					t.Fatal("authorized candidate metadata was rejected", value, err)
				}
				if err := WaitSelector(context.Background(), selector, []string{scope}); err != nil {
					t.Fatal("startup selector readback failed", err)
				}
			} else if err == nil || value != "" {
				t.Fatal("oversized selector metadata was accepted", value, err)
			}
		})
	}
}

func TestHTTPSelectorConfirmsItsOwnUpdateAndRejectsLaterIdenticalReadback(t *testing.T) {
	for _, interleave := range []bool{false, true} {
		t.Run(fmt.Sprint(interleave), func(t *testing.T) {
			at, routes, samples := engineEvidence()
			actual := clientmodel.Selection{Scope: "access", CandidateID: "reject", Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{}, Revision: "demo-initial"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/proxies/access" || r.Header.Get("Authorization") != "Bearer demo-local-secret" {
					http.Error(w, "unexpected selector request", http.StatusForbidden)
					return
				}
				if r.Method == http.MethodGet {
					_ = json.NewEncoder(w).Encode(map[string]any{"now": actual.CandidateID, "policy_id": actual.PolicyID, "choices": actual.Choices, "targets": actual.Targets, "revision": actual.Revision})
					return
				}
				if r.Method != http.MethodPut {
					http.Error(w, "must preserve existing connections", http.StatusBadRequest)
					return
				}
				var update struct {
					PolicyID         string                          `json:"policy_id"`
					Choices          map[string]protocol.RouteChoice `json:"choices"`
					ExpectedPolicyID string                          `json:"expected_policy_id"`
					ExpectedChoices  map[string]protocol.RouteChoice `json:"expected_choices"`
					Name             string                          `json:"name"`
					Targets          map[string]string               `json:"targets"`
					ExpectedName     string                          `json:"expected_name"`
					ExpectedTargets  map[string]string               `json:"expected_targets"`
					Revision         string                          `json:"expected_revision"`
				}
				if json.NewDecoder(r.Body).Decode(&update) != nil || update.ExpectedName != actual.CandidateID || update.Revision != actual.Revision || len(update.ExpectedTargets) != 0 {
					http.Error(w, "stale comparison", http.StatusConflict)
					return
				}
				actual.PolicyID, actual.Choices = update.PolicyID, update.Choices
				actual.CandidateID, actual.Targets, actual.Revision = update.Name, update.Targets, "demo-applied"
				_ = json.NewEncoder(w).Encode(map[string]any{"now": actual.CandidateID, "policy_id": actual.PolicyID, "choices": actual.Choices, "targets": actual.Targets, "revision": actual.Revision})
				if interleave {
					actual.Revision = "demo-later-identical-operation"
				}
			}))
			defer server.Close()
			selector, err := NewHTTPSelector(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-local-secret"}}}`)
			if err != nil {
				t.Fatal(err)
			}
			selector.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			})
			result, err := Activate(context.Background(), selector, routes, State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network", ResourceObservations: samples}, nil, func() time.Time { return at })
			if interleave {
				if !errors.Is(err, ErrSelectionSuperseded) || len(result.State.SelectionMemory[control.AccessSelectorScope].Decisions) != 0 {
					t.Fatal("later identical readback confirmed an old update", err)
				}
			} else if err != nil || len(result.Selections) != 1 {
				t.Fatal("actual API update and readback failed", err)
			}
		})
	}
}
