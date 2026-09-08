package clientruntime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/agent"
	"loom/internal/clientcore"
)

type agentNetwork struct {
	mu      sync.Mutex
	current string
	puts    []string
	failed  map[string]bool
	targets []string
	refuse  bool
	entered chan struct{}
	release chan struct{}
}

func agentNetworkFixture(t *testing.T) (*agentNetwork, *agent.Config) {
	t.Helper()
	body, planBody := pathPlanFixture(t)
	return agentNetworkFixturePlan(t, body, planBody)
}

func agentNetworkFixturePlan(t *testing.T, body, planBody []byte) (*agentNetwork, *agent.Config) {
	t.Helper()
	p, err := validateWindowsAgentPair(body, planBody, "")
	if err != nil {
		t.Fatal(err)
	}
	_, cfg, err := p.Derive(body, clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"})
	if err != nil {
		t.Fatal(err)
	}
	net := &agentNetwork{current: cfg.Declarations[0].Candidates[0].Tag, failed: map[string]bool{}}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		net.mu.Lock()
		defer net.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+cfg.APISecret {
			http.Error(w, "auth", 401)
			return
		}
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]string{"now": net.current, "type": "Selector"})
			return
		}
		if r.Method != "PUT" {
			http.Error(w, "method", 405)
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		allowed := false
		for _, c := range cfg.Declarations[0].Candidates {
			allowed = allowed || c.Tag == req.Name
		}
		if !allowed {
			t.Errorf("PUT escaped fixed exit: %q", req.Name)
			http.Error(w, "unauthorized", 403)
			return
		}
		net.puts = append(net.puts, req.Name)
		if !net.refuse {
			net.current = req.Name
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(api.Close)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic "))
		user, secret, _ := strings.Cut(string(decoded), ":")
		if secret != cfg.ProbeSecret {
			http.Error(w, "auth", 407)
			return
		}
		net.mu.Lock()
		failed := net.failed[user]
		net.targets = append(net.targets, r.URL.String())
		entered, release := net.entered, net.release
		net.mu.Unlock()
		if entered != nil {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		delay := 5 * time.Millisecond
		if user == "demo-slow" {
			delay = 100 * time.Millisecond
		}
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		if failed {
			http.Error(w, "unreachable", 503)
			return
		}
		_, _ = w.Write([]byte("demo response"))
	}))
	t.Cleanup(proxy.Close)
	cfg.API = strings.TrimPrefix(api.URL, "http://")
	cfg.Probe = strings.TrimPrefix(proxy.URL, "http://")
	cfg.Declarations[0].Targets = []string{"http://demo-target.example/service-a", "http://demo-target.example/service-b"}
	cfg.Declarations[0].MinSamples = 6
	return net, cfg
}
func agentTestOptions(t *testing.T) agent.Options {
	root := t.TempDir()
	return agent.Options{StatePath: filepath.Join(root, "state.json"), MeasurementPath: filepath.Join(root, "measurements.jsonl"), EventsPath: filepath.Join(root, "events.jsonl"), Once: true, Log: io.Discard}
}
func runRound(t *testing.T, cfg *agent.Config, opts agent.Options) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entries := []agent.ClientEntry{{Node: "demo-prefix-a", Address: "192.0.2.1"}, {Node: "demo-prefix-b", Address: "192.0.2.2"}}
	done := make(chan error, 1)
	go func() {
		done <- agent.RunClient(ctx, cfg, agent.ClientOptions{StatePath: opts.StatePath, Entries: entries, Probe: func(_ context.Context, e agent.ClientEntry) (time.Duration, error) {
			if e.Node == "demo-prefix-a" {
				return 100 * time.Millisecond, nil
			}
			return 5 * time.Millisecond, nil
		}})
	}()
	deadline := time.Now().Add(time.Second)
	for {
		st, err := agent.ReadState(opts.StatePath)
		if err == nil && st != nil && len(st.Selections) == len(cfg.Declarations) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not publish selection")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWindowsClientChoosesEntryWithoutBusinessRequests(t *testing.T) {
	network, cfg := agentNetworkFixture(t)
	opts := agentTestOptions(t)
	runRound(t, cfg, opts)
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.current != "opaque:z@fast" || len(network.targets) != 0 || len(network.puts) != 1 {
		t.Fatalf("current=%s business requests=%d puts=%v", network.current, len(network.targets), network.puts)
	}
	st, err := agent.ReadState(opts.StatePath)
	if err != nil || st.Selections[0].Health.SelectedP50MS != nil || st.Selections[0].Health.SelectedSamples != 0 {
		t.Fatal("fabricated full-path sample", err)
	}
}

func TestWindowsAgentCancelAndReconnectLeaveNoOldWrites(t *testing.T) {
	network, cfg := agentNetworkFixture(t)
	network.entered = make(chan struct{}, 1)
	network.release = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	a, err := StartWindowsAgent(ctx, cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	before := agentEvidence(t, filepath.Dir(a.statePath))
	close(network.release)
	time.Sleep(30 * time.Millisecond)
	if !reflect.DeepEqual(before, agentEvidence(t, filepath.Dir(a.statePath))) {
		t.Fatal("canceled generation wrote evidence")
	}
	if _, err := a.Report(context.Background(), time.Now()); err == nil {
		t.Fatal("canceled generation reported")
	}
	network.mu.Lock()
	puts := len(network.puts)
	network.entered = nil
	network.release = nil
	network.mu.Unlock()
	if puts != 0 || len(network.targets) != 0 {
		t.Fatal("canceled generation sent selector PUT or business probes")
	}
	fresh, err := StartWindowsAgent(context.Background(), cfg, filepath.Dir(filepath.Dir(filepath.Dir(a.statePath))))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.statePath == a.statePath {
		t.Fatal("reconnect reused old state")
	}
	if err := fresh.Stop(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, agentEvidence(t, filepath.Dir(a.statePath))) {
		t.Fatal("reconnect changed old generation")
	}
}
func agentEvidence(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[path] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
