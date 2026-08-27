package report

import (
	"encoding/json"
	"strings"
	"testing"

	"loom/internal/attest"
	"loom/internal/version"
)

func TestClaimMustBindOuterObservation(t *testing.T) {
	c := &attest.Claim{Node: "gz02", TS: "2026-08-26T12:00:00Z", Applied: "snap",
		Commit: "abc", Binary: "def"}
	base := Observation{Node: c.Node, TS: c.TS, Applied: c.Applied}
	if err := bindClaim(&base, c); err != nil {
		t.Fatalf("相同的外层与 Claim 绑定失败:%v", err)
	}

	for name, mutate := range map[string]func(*Observation){
		"节点": func(o *Observation) { o.Node = "hz01" },
		"时间": func(o *Observation) { o.TS = "2099-01-01T00:00:00Z" },
		"快照": func(o *Observation) { o.Applied = "other" },
	} {
		o := base
		mutate(&o)
		if err := bindClaim(&o, c); err == nil || !strings.Contains(err.Error(), "不一致") {
			t.Errorf("改%s后仍绑定成功:%v", name, err)
		}
	}
}

func TestClaimBindsExtendedOuterFields(t *testing.T) {
	c := &attest.Claim{Node: "gz02", TS: "2026-08-26T12:00:00Z", Applied: "snap",
		Commit: "abc", Binary: "def",
		Rollout: &attest.RolloutClaim{Snapshot: "snap", Stage: "failed", Error: "boom"}}
	o := Observation{Node: c.Node, TS: c.TS, Applied: c.Applied,
		Version: &version.Coordinate{Commit: "abc", Binary: "def"},
		Rollout: &RolloutState{Snapshot: "snap", Stage: "failed", Error: "boom"}}
	if err := bindClaim(&o, c); err != nil {
		t.Fatal(err)
	}
	o.Rollout.Error = "被 relay 改过"
	if err := bindClaim(&o, c); err == nil || !strings.Contains(err.Error(), "rollout") {
		t.Fatalf("外层 rollout 被改后仍绑定成功:%v", err)
	}
}

func TestClaimBindsMeasurementPayload(t *testing.T) {
	o := Observation{Node: "gz02", TS: "2026-08-26T12:00:00Z", Applied: "snap",
		Edges:   []Edge{{To: "sg02", RTTMs: 17, Samples: 5}},
		Targets: []Reach{{Target: "https://example.test", FirstByteMs: 42, Samples: 5}},
	}
	c := &attest.Claim{Node: o.Node, TS: o.TS, Applied: o.Applied,
		MeasurementsSHA256: measurementDigest(&o)}
	if err := bindClaim(&o, c); err != nil {
		t.Fatal(err)
	}
	o.Edges[0].RTTMs = 1
	if err := bindClaim(&o, c); err == nil || !strings.Contains(err.Error(), "链路观测") {
		t.Fatalf("relay 改写边后仍绑定成功:%v", err)
	}
	o.Edges[0].RTTMs = 17
	o.Targets[0].Error = "relay forged unreachable"
	if err := bindClaim(&o, c); err == nil || !strings.Contains(err.Error(), "链路观测") {
		t.Fatalf("relay 改写 Targets 后仍绑定成功:%v", err)
	}
}

func TestClaimBindsComponentVersions(t *testing.T) {
	o := Observation{
		Node: "gz02", TS: "2026-08-26T12:00:00Z", Applied: "snap",
		Components: []ComponentStatus{{
			Name: "wireguard", Expected: "1.0.20250521", Actual: "1.0.20210914",
		}},
	}
	c := &attest.Claim{
		CanonicalVersion: 5, Node: o.Node, TS: o.TS, Applied: o.Applied,
		Components: []attest.ComponentClaim{{
			Name: "wireguard", Expected: "1.0.20250521", Actual: "1.0.20210914",
		}},
	}
	if err := bindClaim(&o, c); err != nil {
		t.Fatal(err)
	}
	o.Components[0].Actual = "1.0.20250521"
	if err := bindClaim(&o, c); err == nil || !strings.Contains(err.Error(), "组件版本") {
		t.Fatalf("relay changed component status without rejection: %v", err)
	}
}

func TestMeasurementDigestNormalizesEmptySlicesAcrossJSON(t *testing.T) {
	o := Observation{Node: "n", Edges: []Edge{}, Targets: []Reach{}}
	want := measurementDigest(&o)
	b, err := json.Marshal(&o)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Observation
	if err := json.Unmarshal(b, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if got := measurementDigest(&roundTrip); got != want {
		t.Fatalf("empty slices changed digest after JSON transit: %s != %s", got, want)
	}
}

func TestLegacyClaimKeepsTrustedAppliedWithoutMeasurementTrust(t *testing.T) {
	c := &attest.Claim{Node: "gz02", TS: "2026-08-26T12:00:00Z", Applied: "signed-snapshot"}
	st := stateFromClaim(c)
	if st.Applied != "signed-snapshot" {
		t.Fatalf("legacy signed Applied was lost: %+v", st)
	}
	if st.MeasurementsVerified {
		t.Fatal("legacy claim unexpectedly authorized Edges/Targets")
	}
}

func TestClaimBindsAgentHealthAndComponentVersion(t *testing.T) {
	p50, p95, best, selectedKBps, bestKBps := 120, 190, 80, 300, 500
	claimHealth := &attest.CandidateHealthClaim{
		Candidates: 3, RecentSuccess: 1, RecentDegraded: 1, RecentFailed: 1,
		SelectedState: "degraded", SelectedSamples: 5, SelectedFailures: 2,
		SelectedP50MS: &p50, SelectedP95MS: &p95, BestP50MS: &best,
		SelectedKBps: &selectedKBps, BestKBps: &bestKBps,
	}
	c := &attest.Claim{
		Node: "gz02", TS: "2026-08-26T12:00:00Z", Applied: "snap",
		CanonicalVersion: 4,
		Agent: &attest.AgentClaim{
			Node: "gz02", TS: "2026-08-26T12:00:00Z", ComponentVersion: "0.1.0",
			Selections: []attest.SelectionClaim{{
				Declaration: "d", Selector: "svc:d", Candidate: "cand:d:gz02",
				UpdatedAt: "2026-08-26T12:00:00Z", Health: claimHealth,
			}},
		},
	}
	o := Observation{
		Node: c.Node, TS: c.TS, Applied: c.Applied,
		Agent: stateFromClaim(c).Agent,
	}
	if err := bindClaim(&o, c); err != nil {
		t.Fatalf("相同 Agent 健康没有绑定:%v", err)
	}
	if o.Agent.ComponentVersion != "0.1.0" || o.Agent.Selections[0].Health == nil ||
		*o.Agent.Selections[0].Health.SelectedP50MS != 120 {
		t.Fatalf("健康/Agent 版本没有从 claim 安全重建:%+v", o.Agent)
	}

	o.Agent.Selections[0].Health.RecentFailed++
	if err := bindClaim(&o, c); err == nil || !strings.Contains(err.Error(), "Agent") {
		t.Fatalf("relay 改写候选健康后仍绑定成功:%v", err)
	}
	o.Agent = stateFromClaim(c).Agent
	o.Agent.ComponentVersion = "forged"
	if err := bindClaim(&o, c); err == nil || !strings.Contains(err.Error(), "Agent") {
		t.Fatalf("relay 改写 Agent component_version 后仍绑定成功:%v", err)
	}
}
