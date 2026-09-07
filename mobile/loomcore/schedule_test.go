package loomcore

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeAndroidCandidateUsesAuthenticatedExplicitProxy(t *testing.T) {
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("probe-user:probe-secret"))
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Proxy-Authorization"); got != wantAuth {
			http.Error(writer, "missing proxy authentication", http.StatusProxyAuthRequired)
			return
		}
		writer.WriteHeader(http.StatusOK)
		time.Sleep(10 * time.Millisecond)
		_, _ = writer.Write(make([]byte, 64<<10))
	}))
	defer proxy.Close()
	address := proxy.Listener.Addr().String()
	host, _, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		t.Fatalf("proxy address=%q error=%v", address, err)
	}
	result, err := probeAndroidCandidate(address, "probe-secret", "probe-user", "http://target.invalid/payload", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.firstByteMS < 0 || result.kbps <= 0 {
		t.Fatalf("probe result=%+v", result)
	}
	if _, err := probeAndroidCandidate(address, "wrong-secret", "probe-user", "http://target.invalid/payload", time.Second); err == nil ||
		!strings.Contains(err.Error(), "407") {
		t.Fatalf("proxy authentication failure=%v", err)
	}
}

func TestAndroidProbeBudgetAlwaysKeepsCurrentAndRotates(t *testing.T) {
	candidates := []androidRouteCandidate{{Tag: "a"}, {Tag: "b"}, {Tag: "c"}, {Tag: "d"}}
	first, cursor, skipped := pickAndroidProbeCandidates(candidates, "c", 2, "")
	if len(first) != 2 || first[0].Tag != "c" || first[1].Tag != "a" || cursor != "b" || skipped != 2 {
		t.Fatalf("first bounded round=%+v cursor=%q skipped=%d", first, cursor, skipped)
	}
	second, cursor, skipped := pickAndroidProbeCandidates(candidates, "c", 2, cursor)
	if len(second) != 2 || second[0].Tag != "c" || second[1].Tag != "b" || cursor != "d" || skipped != 2 {
		t.Fatalf("second bounded round=%+v cursor=%q skipped=%d", second, cursor, skipped)
	}
}

func TestDecideAndroidRouteLeavesDeadCurrentImmediately(t *testing.T) {
	declaration := androidRouteDeclaration{
		ID: "web", Selector: "decl:web", Objective: "latency", MinSamples: 4, SwitchThreshold: 0.9,
	}
	candidates := []androidRouteCandidate{{Tag: "dead"}, {Tag: "healthy"}}
	decision := decideAndroidRoute(declaration, candidates, "dead", []androidRouteSummary{
		{Candidate: "dead", Samples: 1, Failures: 1},
		{Candidate: "healthy", Samples: 1, P50: 400, P95: 400},
	})
	if !decision.Switch || decision.Choice != "healthy" || !strings.Contains(decision.Reason, "全部失败") {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestDecideAndroidRouteHonorsThreshold(t *testing.T) {
	declaration := androidRouteDeclaration{
		ID: "web", Selector: "decl:web", Objective: "latency", MinSamples: 2, SwitchThreshold: 0.2,
	}
	candidates := []androidRouteCandidate{{Tag: "current"}, {Tag: "challenger"}}
	decision := decideAndroidRoute(declaration, candidates, "current", []androidRouteSummary{
		{Candidate: "current", Samples: 2, P50: 100, P95: 100},
		{Candidate: "challenger", Samples: 2, P50: 85, P95: 85},
	})
	if decision.Switch {
		t.Fatalf("15%% gain crossed 20%% threshold: %+v", decision)
	}
	decision = decideAndroidRoute(declaration, candidates, "current", []androidRouteSummary{
		{Candidate: "current", Samples: 2, P50: 100, P95: 100},
		{Candidate: "challenger", Samples: 2, P50: 70, P95: 70},
	})
	if !decision.Switch || decision.Choice != "challenger" {
		t.Fatalf("30%% gain did not cross 20%% threshold: %+v", decision)
	}
}

func TestRunAndroidRouteTickDirectModeDoesNotProbe(t *testing.T) {
	planBody, _ := androidRouteFixture(t)
	var plan androidRoutePlan
	if err := json.Unmarshal(planBody, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Declarations = []androidRouteDeclaration{{
		ID: "web", Selector: "decl:auto", Objective: "latency", Targets: []string{"https://unreachable.invalid/"},
		TuningPeriod: "1m", SwitchThreshold: 0.2, Window: "1h", MinSamples: 2, StaleAfter: "10m",
		Candidates: plan.Selectors[0].Candidates,
	}}
	planBody, err := marshalCanonical(&plan)
	if err != nil {
		t.Fatal(err)
	}
	resultBody, err := RunAndroidRouteTick(
		planBody,
		[]byte(`{"schema":1,"mode":"direct"}`),
		nil,
		nil,
		time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
	)
	if err != nil {
		t.Fatal(err)
	}
	var result androidRouteTick
	if err := json.Unmarshal(resultBody, &result); err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Application.Mode != androidRouteModeDirect || !strings.Contains(result.Detail, "不执行") {
		t.Fatalf("direct tick=%+v", result)
	}
}

func TestAndroidDecisionScopeChangesWithMobilePreference(t *testing.T) {
	declaration := androidRouteDeclaration{
		ID: "web", Selector: "decl:web", Objective: "latency", Targets: []string{"https://example.test/"},
		TuningPeriod: "1m", SwitchThreshold: 0.2, Window: "1h", MinSamples: 2, StaleAfter: "10m",
	}
	candidates := []androidRouteCandidate{{Tag: "opaque", Chain: []string{"edge-a"}, ProbeUser: "probe-a"}}
	auto := androidDecisionScope("phone", declaration, androidRouteModeAuto, "", candidates)
	fixed := androidDecisionScope("phone", declaration, androidRouteModeFixed, "edge-a", candidates)
	if auto == fixed || !validLowerHex(auto, 64) || !validLowerHex(fixed, 64) {
		t.Fatalf("scopes auto=%q fixed=%q", auto, fixed)
	}
}
