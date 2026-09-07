package report

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/attest"
)

// Windows and other NAT clients use the existing canonical-v5 report path.
// The receiver, gossip table, and UI view must preserve the Agent's measured
// complete path, quality, and switch reason without a parallel protocol.
func TestSignedClientAgentSelectionSurvivesReportPipeline(t *testing.T) {
	now := time.Date(2026, 9, 5, 15, 20, 0, 0, time.UTC)
	ca, key, cert := reportTestIdentity(t, "workstation")
	selectedP50, selectedP95, bestP50 := 28, 41, 28
	observation := Observation{
		Node: "workstation", TS: now.Format(time.RFC3339), Applied: "snapshot-v5",
		Agent: &AgentState{
			Node: "workstation", TS: now.Format(time.RFC3339), ComponentVersion: "0.1.0",
			Selections: []AgentSelection{{
				Declaration: "catalog", Selector: "svc:catalog",
				Candidate: "cand:catalog:relay-a>fixed-exit",
				Chain:     []string{"relay-a", "fixed-exit"},
				Reason:    "measured complete path is faster", UpdatedAt: now.Format(time.RFC3339),
				Health: &AgentCandidateHealth{
					Candidates: 3, RecentSuccess: 3, SelectedState: "success",
					SelectedSamples: 6, SelectedP50MS: &selectedP50, SelectedP95MS: &selectedP95,
					BestP50MS: &bestP50,
				},
			}},
		},
	}
	_, current := claimsForObservation(&observation, 5)
	var err error
	observation.Attest, err = attest.Sign(current, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	observation.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: observation.Node,
		TS: observation.TS, Healthy: true,
	}, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := clientReportPublicKey(&observation)
	if err != nil {
		t.Fatal(err)
	}
	ssotPath, err := filepath.Abs("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "registry.json")
	writeClientReportRegistry(t, registryPath, "ready", publicKey)
	table := newTable(5)
	table.verify = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := VerifyObservationAtLeast(got, ca, at, maxAge, 5)
		return err
	}
	table.verifySelfCheck = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := verifySelfCheckAttachment(got, ca, at, maxAge)
		return err
	}
	receiver := newClientReportReceiver(table, &Control{
		SSOTPath: ssotPath, ClientRegistryPath: registryPath,
	}, func() time.Time { return now }, 10*time.Minute, nil)
	receiver.readCA = func(string) ([]byte, error) { return ca, nil }

	response := postClientReport(t, receiver, &observation)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("signed Agent client report response = %d %q", response.Code, response.Body.String())
	}
	learned := table.snapshot("control", now, 10*time.Minute)
	if len(learned) != 1 || learned[0].Agent == nil || len(learned[0].Agent.Selections) != 1 {
		t.Fatalf("NAT receiver lost signed Agent state before gossip: %+v", learned)
	}

	view := buildViewWithCA(&Config{
		Node: "control", AttestationMinVersion: 5,
		ExpectedNodes: []string{"control", observation.Node},
		ExpectedRoutes: []ExpectedRoute{{
			Access: observation.Node, Declaration: "catalog",
			Chain: []string{"relay-a", "fixed-exit"},
		}},
	}, &Status{
		Node: "control", TS: now.Format(time.RFC3339), Learned: learned,
	}, now, func(string) ([]byte, error) { return ca, nil })
	if len(view.Routes) != 1 {
		t.Fatalf("signed Agent route did not enter UI view: %+v", view.Routes)
	}
	route := view.Routes[0]
	if route.Selector != "svc:catalog" || route.Candidate != "cand:catalog:relay-a>fixed-exit" ||
		route.Reason != "measured complete path is faster" || len(route.Chain) != 3 ||
		route.Chain[0] != observation.Node || route.Chain[1] != "relay-a" ||
		route.Chain[2] != "fixed-exit" || route.Health == nil ||
		route.Health.SelectedMetrics != "p50 28ms · p95 41ms" ||
		route.Health.BestMetrics != "p50 28ms" {
		t.Fatalf("signed path, quality, or switch reason changed across NAT/gossip/UI: %+v", route)
	}
	if len(view.Candidates) != 1 || view.Candidates[0].State != "selected" {
		t.Fatalf("signed actual path did not select its expected candidate in UI: %+v", view.Candidates)
	}
}
