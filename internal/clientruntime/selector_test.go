package clientruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"loom/internal/clientcore"
)

func TestWindowsSelectorPlanUsesOnlyCommonSignedExits(t *testing.T) {
	config := singBoxConfig{Experimental: &singBoxExperimental{ClashAPI: &singBoxAPI{
		ExternalController: "127.0.0.1:61800", Secret: "secret",
	}}, Outbounds: []singBoxOutbound{
		{Type: "selector", Tag: "decl:auto", Default: "cand:auto:edge-a", Outbounds: []string{
			"cand:auto:direct", "cand:auto:edge-a", "cand:auto:relay>edge-b",
		}},
		{Type: "selector", Tag: "svc:web", Default: "cand:web:edge-b", Outbounds: []string{
			"cand:web:direct", "cand:web:edge-b", "cand:web:relay>edge-a",
		}},
	}}
	plan, err := windowsSelectorPlanFromConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	policy := plan.Policy()
	if !plan.DirectAvailable() || len(policy.Exits) != 2 || policy.Exits[0].ID != "edge-a" || policy.Exits[1].ID != "edge-b" {
		t.Fatalf("plan policy=%+v direct=%t", policy, plan.DirectAvailable())
	}
}

func TestApplySelectorTargetsRollsBackPartialChange(t *testing.T) {
	current := map[string]string{"decl:auto": "old-a", "svc:web": "old-b"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := strings.TrimPrefix(r.URL.Path, "/proxies/")
		if r.Header.Get("Authorization") != "Bearer local-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"now": current[tag]})
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if tag == "svc:web" && body.Name == "new-b" {
			http.Error(w, "rejected", http.StatusConflict)
			return
		}
		current[tag] = body.Name
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	err := applySelectorTargets(context.Background(), server.Client(), server.URL, "local-secret", map[string]string{
		"decl:auto": "new-a", "svc:web": "new-b",
	})
	if err == nil || current["decl:auto"] != "old-a" || current["svc:web"] != "old-b" {
		t.Fatalf("partial apply err=%v current=%v", err, current)
	}
}

func TestApplyWindowsPreferenceRejectsUnsignedExitBeforeAPI(t *testing.T) {
	plan := &WindowsSelectorPlan{
		controller: "http://127.0.0.1:1", secret: "secret",
		policy:    clientcore.Policy{Schema: 1, Exits: []clientcore.Exit{{ID: "edge-a"}}},
		selectors: []windowsSelector{{tag: "decl:auto", fixedExit: map[string]string{"edge-a": "cand:auto:edge-a"}}},
	}
	err := ApplyWindowsPreference(context.Background(), http.DefaultClient, plan, clientcore.Preference{
		Schema: 1, Mode: clientcore.FixedExit, Exit: "not-authorized",
	})
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unauthorized preference error=%v", err)
	}
}

func TestApplySelectorTargetsClosesExistingConnections(t *testing.T) {
	current := map[string]string{"decl:auto": "old-a", "svc:web": "old-b"}
	closed := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/connections/" {
			if r.Method != http.MethodDelete {
				http.Error(w, "wrong method", http.StatusMethodNotAllowed)
				return
			}
			closed++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		tag := strings.TrimPrefix(r.URL.Path, "/proxies/")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"now": current[tag]})
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		current[tag] = body.Name
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if err := applySelectorTargets(context.Background(), server.Client(), server.URL, "local-secret", map[string]string{
		"decl:auto": "new-a", "svc:web": "new-b",
	}); err != nil {
		t.Fatal(err)
	}
	if closed != 1 || current["decl:auto"] != "new-a" || current["svc:web"] != "new-b" {
		t.Fatalf("closed=%d current=%v", closed, current)
	}
}

func TestApplySelectorTargetsRollsBackWhenConnectionsCannotClose(t *testing.T) {
	current := map[string]string{"decl:auto": "old-a", "svc:web": "old-b"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connections/" {
			http.Error(w, "cannot close", http.StatusServiceUnavailable)
			return
		}
		tag := strings.TrimPrefix(r.URL.Path, "/proxies/")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{"now": current[tag]})
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		current[tag] = body.Name
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	err := applySelectorTargets(context.Background(), server.Client(), server.URL, "local-secret", map[string]string{
		"decl:auto": "new-a", "svc:web": "new-b",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") || current["decl:auto"] != "old-a" || current["svc:web"] != "old-b" {
		t.Fatalf("close failure err=%v current=%v", err, current)
	}
}
