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
