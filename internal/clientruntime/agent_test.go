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
	"loom/internal/measure"
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
	if err := agent.Run(context.Background(), cfg, opts); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsSharedAgentMeasuresRanksSwitchesFixedExit(t *testing.T) {
	network, cfg := agentNetworkFixture(t)
	opts := agentTestOptions(t)
	for round := 0; round < 3; round++ {
		runRound(t, cfg, opts)
		network.mu.Lock()
		current, puts := network.current, len(network.puts)
		network.mu.Unlock()
		if round < 2 && puts != 0 {
			t.Fatal("switched before min_samples")
		}
		if round == 2 && (current != "opaque:z@fast" || puts != 1) {
			t.Fatalf("faster complete prefix did not win: %q, PUTs %d", current, puts)
		}
	}
	st, err := agent.ReadState(opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	s := st.Selections[0]
	if !reflect.DeepEqual(s.Chain, []string{"demo-prefix-b", "demo-exit"}) || s.DecisionScope == "" || s.Health == nil || s.Health.SelectedP50MS == nil || s.Health.BestP50MS == nil || s.Reason == "" {
		t.Fatalf("missing actual evidence: %+v", s)
	}
	measurements, err := measure.Load(opts.MeasurementPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(measurements) != 12 {
		t.Fatalf("full candidates × targets × rounds: %d", len(measurements))
	}
	for _, m := range measurements {
		if m.DecisionScope != s.DecisionScope || !strings.HasPrefix(m.Target, "http://demo-target.example/service-") || m.Kind != measure.Active {
			t.Fatalf("foreign evidence %+v", m)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &WindowsAgent{ctx: ctx, done: make(chan struct{}), config: cfg, statePath: opts.StatePath}
	actual, err := runtime.Report(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if actual.Selections[0].Candidate != s.Candidate || !reflect.DeepEqual(actual.Selections[0].Chain, s.Chain) || !strings.Contains(actual.Selections[0].Reason, "decision_scope="+s.DecisionScope) {
		t.Fatalf("report=%+v", actual)
	}
	// 报告必须重新 GET：外部改变 selector 后，不能把之前质量移植给新的实际路径。
	network.mu.Lock()
	network.current = "opaque:a@slow"
	network.mu.Unlock()
	actual, err = runtime.Report(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if actual.Selections[0].Candidate != "opaque:a@slow" || actual.Selections[0].Health != nil || actual.Selections[0].Chain[0] != "demo-prefix-a" {
		t.Fatal("report fabricated actual quality/chain")
	}
}

func TestWindowsSharedAgentCurrentFailureAndReadbackRefusal(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure switch", true: "readback refuses intent"}[refuse], func(t *testing.T) {
			network, cfg := agentNetworkFixture(t)
			opts := agentTestOptions(t)
			network.failed["demo-slow"] = true
			network.refuse = refuse
			runRound(t, cfg, opts)
			st, err := agent.ReadState(opts.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			network.mu.Lock()
			puts := len(network.puts)
			network.mu.Unlock()
			if puts != 1 {
				t.Fatal("current all-failed did not switch before sample threshold")
			}
			if refuse {
				for _, s := range st.Selections {
					if s.Candidate == "opaque:z@fast" {
						t.Fatal("PUT intent appeared as actual")
					}
				}
			} else if st.Selections[0].Candidate != "opaque:z@fast" {
				t.Fatal("failed path remained selected")
			}
		})
	}
}

func TestWindowsSharedAgentChangedScopeDiscardsSamples(t *testing.T) {
	for _, change := range []string{"candidates", "targets", "parameters"} {
		t.Run(change, func(t *testing.T) {
			network, cfg := agentNetworkFixture(t)
			opts := agentTestOptions(t)
			for i := 0; i < 3; i++ {
				runRound(t, cfg, opts)
			}
			old, _ := agent.ReadState(opts.StatePath)
			scope := old.Selections[0].DecisionScope
			network.mu.Lock()
			network.current = "opaque:a@slow"
			network.puts = nil
			network.mu.Unlock()
			switch change {
			case "candidates":
				cfg.Declarations[0].Candidates[1].Chain[0] = "demo-new-prefix"
			case "targets":
				cfg.Declarations[0].Targets = []string{"http://demo-new-target.example/"}
			case "parameters":
				cfg.Declarations[0].SwitchThreshold = 0.3
			}
			runRound(t, cfg, opts)
			current, _ := agent.ReadState(opts.StatePath)
			network.mu.Lock()
			puts := len(network.puts)
			network.mu.Unlock()
			if puts != 0 || current.Selections[0].DecisionScope == scope || current.Selections[0].Health.SelectedSamples > 2 {
				t.Fatal("old scope influenced new decision")
			}
		})
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
	select {
	case <-network.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("probe never started")
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
	if puts != 0 {
		t.Fatal("canceled generation sent selector PUT")
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
