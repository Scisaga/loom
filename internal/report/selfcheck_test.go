package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/rollout"
)

func TestSelfCheckClaimCoversCompleteLocalVerdict(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	st := &Status{
		Node: "demo-b", TS: now.Format(time.RFC3339),
		Errors: []string{"wg collector failed\nwith detail"},
		Rollout: &RolloutState{
			Stage:     string(rollout.Activating),
			EnteredAt: now.Add(-20 * time.Minute).Format(time.RFC3339),
		},
		Components: []ComponentStatus{{Name: "wireguard", Expected: "2", Actual: "1"}},
		Agent: &AgentState{Selections: []AgentSelection{{
			Declaration: "best", Health: &AgentCandidateHealth{Candidates: 2, RecentFailed: 2},
		}}},
		Tunnels: []Tunnel{{Interface: "wg-demo-e", HandshakeAgeSec: 900, Stale: true, UnitState: "failed"}},
		Drift:   &Drift{Modified: []string{"/etc/loom/a"}},
		Observation: &Observation{Targets: []Reach{{
			Target: "https://uplink.test", Uplink: true, Error: "timeout",
		}}},
	}
	claim := selfCheckClaimFromStatus(st, now)
	if claim.Healthy || len(claim.Problems) < 7 {
		t.Fatalf("incomplete unhealthy self-check: %+v", claim)
	}
	joined := strings.Join(claim.Problems, "\n")
	for _, want := range []string{
		"wg collector failed with detail", "rollout 卡在", "组件 wireguard 版本漂移",
		"Agent best", "隧道握手陈旧", "隧道单元异常", "配置被改过", "直连探测失败",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("self-check lacks %q: %s", want, joined)
		}
	}
	for i := 1; i < len(claim.Problems); i++ {
		if claim.Problems[i-1] >= claim.Problems[i] {
			t.Fatalf("problems are not strictly sorted/deduplicated: %q", claim.Problems)
		}
	}

	healthy := selfCheckClaimFromStatus(&Status{
		Node: "demo-b", TS: now.Format(time.RFC3339),
		Tunnels: []Tunnel{{Interface: "wg-demo-e", HandshakeAgeSec: 20, UnitState: "active"}},
	}, now)
	if !healthy.Healthy || len(healthy.Problems) != 0 {
		t.Fatalf("healthy local status did not produce explicit green: %+v", healthy)
	}
}

func TestSelfCheckProblemCompactionRespectsWireBounds(t *testing.T) {
	input := make([]string, 100)
	for i := range input {
		input[i] = fmt.Sprintf("problem-%03d %s\n", i, strings.Repeat("x", 600))
	}
	got := compactSelfCheckProblems(input)
	if len(got) != attest.SelfCheckMaxProblems {
		t.Fatalf("compacted count=%d, want %d", len(got), attest.SelfCheckMaxProblems)
	}
	total := 0
	for i, problem := range got {
		if len(problem) > attest.SelfCheckMaxProblemSize || strings.ContainsAny(problem, "\r\n\t") {
			t.Fatalf("problem %d violates wire bounds: %q", i, problem)
		}
		if i > 0 && got[i-1] >= problem {
			t.Fatalf("compacted problems not strictly sorted: %q", got)
		}
		total += len(problem)
	}
	if total > attest.SelfCheckMaxTotalSize {
		t.Fatalf("compacted total=%d, max=%d", total, attest.SelfCheckMaxTotalSize)
	}
	if !strings.Contains(strings.Join(got, "\n"), "问题列表已截断") {
		t.Fatalf("truncation was silent: %q", got)
	}
}

func TestSelfCheckAttachmentBindsOuterObservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, key, cert := reportTestIdentity(t, "demo-b")
	o := &Observation{Node: "demo-b", TS: now.Format(time.RFC3339)}
	var err error
	o.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: o.Node, TS: o.TS, Healthy: true,
	}, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySelfCheckAttachment(o, ca, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	bad := *o
	bad.TS = now.Add(time.Second).Format(time.RFC3339)
	if _, err := verifySelfCheckAttachment(&bad, ca, now, time.Minute); err == nil ||
		!strings.Contains(err.Error(), "外层") {
		t.Fatalf("outer timestamp was not bound: %v", err)
	}
}

func TestBuildViewUsesOnlySignedSelfCheckForRemoteHealth(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, key, cert := reportTestIdentity(t, "demo-b")
	viewFor := func(claim *attest.SelfCheckClaim) string {
		o := Observation{
			Node: "demo-b", TS: now.Format(time.RFC3339),
			// These mutable outer values must never create a remote verdict.
			Rollout:    &RolloutState{Stage: string(rollout.Failed), Error: "outer only"},
			Components: []ComponentStatus{{Name: "wireguard", Expected: "2", Actual: "1"}},
		}
		if claim != nil {
			var err error
			o.SelfCheck, err = attest.SignSelfCheck(*claim, key, cert)
			if err != nil {
				t.Fatal(err)
			}
		}
		v := buildViewWithCA(&Config{Node: "demo-d", ExpectedNodes: []string{"demo-d", "demo-b"}},
			&Status{Node: "demo-d", TS: now.Format(time.RFC3339), Learned: []Observation{o}},
			now, func(string) ([]byte, error) { return ca, nil })
		for _, node := range v.Nodes {
			if node.ID == "demo-b" {
				return node.Health + "\x00" + strings.Join(node.Problems, "|")
			}
		}
		t.Fatal("remote node missing from view")
		return ""
	}

	if got := viewFor(nil); got != "unknown\x00" {
		t.Fatalf("missing self-check did not remain unknown: %q", got)
	}
	healthy := &attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: "demo-b", TS: now.Format(time.RFC3339), Healthy: true,
	}
	if got := viewFor(healthy); got != "healthy\x00" {
		t.Fatalf("explicit signed healthy was not green: %q", got)
	}
	unhealthy := &attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: "demo-b", TS: now.Format(time.RFC3339),
		Healthy: false, Problems: []string{"隧道 wg-demo-e down"},
	}
	if got := viewFor(unhealthy); !strings.HasPrefix(got, "problem\x00隧道 wg-demo-e down") {
		t.Fatalf("explicit signed problem was not red/explained: %q", got)
	}
}

func TestTableRejectsInvalidSelfCheckBeforeGossip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tbl := newTable()
	tbl.verifySelfCheck = func(*Observation, time.Time, time.Duration) error {
		return errors.New("bad signature")
	}
	o := &Observation{Node: "demo-b", TS: now.Format(time.RFC3339), SelfCheck: &attest.SelfCheckAttest{}}
	if err := tbl.put(o, now, time.Minute); err == nil || !strings.Contains(err.Error(), "自检") {
		t.Fatalf("invalid self-check entered table: %v", err)
	}
	if got := tbl.snapshot("demo-d", now, time.Minute); len(got) != 0 {
		t.Fatalf("invalid self-check was retained for gossip: %+v", got)
	}
}

func TestSelfCheckSurvivesSignedJSONGossipAndView(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, key, cert := reportTestIdentity(t, "demo-b")
	o := Observation{Node: "demo-b", TS: now.Format(time.RFC3339), Applied: "snap"}
	legacy, current := claimsForObservation(&o, 5)
	var err error
	o.Attest, err = attest.Sign(legacy, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	o.AttestExtended, err = attest.Sign(current, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	o.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: o.Node, TS: o.TS, Healthy: true,
	}, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(&o)
	if err != nil {
		t.Fatal(err)
	}
	var relayed Observation
	if err := json.Unmarshal(wire, &relayed); err != nil {
		t.Fatal(err)
	}

	tbl := newTable(5)
	tbl.verify = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := VerifyObservationAtLeast(got, ca, at, maxAge, 5)
		return err
	}
	tbl.verifySelfCheck = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := verifySelfCheckAttachment(got, ca, at, maxAge)
		return err
	}
	if err := tbl.put(&relayed, now, time.Minute); err != nil {
		t.Fatalf("signed self-check did not enter gossip table: %v", err)
	}
	learned := tbl.snapshot("demo-d", now, time.Minute)
	if len(learned) != 1 || learned[0].SelfCheck == nil {
		t.Fatalf("self-check was lost in gossip: %+v", learned)
	}
	v := buildViewWithCA(&Config{
		Node: "demo-d", AttestationMinVersion: 5, ExpectedNodes: []string{"demo-d", "demo-b"},
	}, &Status{Node: "demo-d", TS: now.Format(time.RFC3339), Learned: learned}, now,
		func(string) ([]byte, error) { return ca, nil })
	for _, node := range v.Nodes {
		if node.ID == "demo-b" {
			if node.Health != "healthy" || node.Source != "签名转述" {
				t.Fatalf("verified relayed self-check did not close remote health: %+v", node)
			}
			return
		}
	}
	t.Fatal("demo-b missing from end-to-end view")
}
