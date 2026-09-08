package agent

import (
	"reflect"
	"testing"
	"time"

	"loom/internal/measure"
	"loom/internal/model"
)

func startupFixture() (*Decl, []measure.Summary) {
	return &Decl{ID: "api", Objective: model.Latency, MinSamples: 4, SwitchThreshold: .2, ProbeBudget: 4,
			Candidates: []Cand{{Tag: "current"}, {Tag: "fast"}, {Tag: "also-fast"}, {Tag: "outside-first-round"}}},
		[]measure.Summary{{CandidateID: "current", Samples: 1, P50: 100}, {CandidateID: "fast", Samples: 1, P50: 40}, {CandidateID: "also-fast", Samples: 1, P50: 60}, {CandidateID: "outside-first-round", Samples: 1, P50: 1}}
}

func TestStartupComparisonOnlyFillsRealDeficitsForOnePromisingChallenger(t *testing.T) {
	d, sums := startupFixture()
	now := time.Now()
	comparison := newStartupComparison(d, "current", d.Candidates[:3], sums, now, 15*time.Second)
	if comparison == nil || comparison.challenger != "fast" || comparison.remaining != 3 {
		t.Fatalf("wrong first comparison: %+v", comparison)
	}
	if got := candidateTags(comparison.candidates(d, "current", sums, now)); !reflect.DeepEqual(got, []string{"current", "fast"}) {
		t.Fatalf("supplementary probes escaped comparison: %v", got)
	}
	sums[0].Samples = d.MinSamples
	if got := candidateTags(comparison.candidates(d, "current", sums, now)); !reflect.DeepEqual(got, []string{"fast"}) {
		t.Fatalf("qualified incumbent was probed only to inflate its samples: %v", got)
	}
	sums[1].Samples = d.MinSamples
	if got := comparison.candidates(d, "current", sums, now); len(got) != 0 {
		t.Fatalf("comparison continued after deficits were filled: %+v", got)
	}
	if d.MinSamples != 4 || d.ProbeBudget != 4 {
		t.Fatal("startup changed declared sample or probe limits")
	}
}

func TestStartupComparisonDoesNotSpendWithoutAUsefulComparison(t *testing.T) {
	for _, scenario := range []string{"qualified-history", "below-threshold", "incumbent-faster", "challenger-failed", "higher-failure-rate", "missing-throughput", "disabled"} {
		t.Run(scenario, func(t *testing.T) {
			d, sums := startupFixture()
			interval := 15 * time.Second
			sums = sums[:2]
			switch scenario {
			case "qualified-history":
				sums[0].Samples, sums[1].Samples = 4, 4
			case "below-threshold":
				sums[1].P50 = 80
			case "incumbent-faster":
				sums[1].P50 = 120
			case "challenger-failed":
				sums[1].Failures = 1
			case "higher-failure-rate":
				sums[1].Samples, sums[1].Failures = 2, 1
			case "missing-throughput":
				d.Objective = model.Throughput
			case "disabled":
				interval = 0
			}
			if got := newStartupComparison(d, "current", d.Candidates[:2], sums, time.Now(), interval); got != nil {
				t.Fatalf("unnecessary startup probe plan: %+v", got)
			}
		})
	}
}

func TestStartupComparisonStopsOnBoundsOrChangedEvidence(t *testing.T) {
	d, sums := startupFixture()
	now := time.Now()
	comparison := newStartupComparison(d, "current", d.Candidates[:3], sums, now, 15*time.Second)
	if comparison.active(now.Add(time.Minute)) || len(comparison.candidates(d, "fast", sums, now)) != 0 {
		t.Fatal("expired comparison or changed actual selector remained active")
	}
	for round := 0; round < d.MinSamples-1; round++ {
		comparison.sampled(now.Add(time.Duration(round+1) * 15 * time.Second))
	}
	if comparison.active(now.Add(46 * time.Second)) {
		t.Fatal("startup supplemented more than min_samples-1 rounds")
	}
	comparison = newStartupComparison(d, "current", d.Candidates[:3], sums, now, 15*time.Second)
	sums[1].Samples, sums[1].Failures = 2, 1
	if len(comparison.candidates(d, "current", sums, now)) != 0 {
		t.Fatal("a failing challenger kept its original optimistic comparison")
	}
	sums[1].Failures = 0
	d.ProbeBudget = 1
	if got := comparison.candidates(d, "current", sums, now); len(got) != 1 || got[0].Tag != "current" {
		t.Fatalf("supplementary round bypassed candidate budget: %+v", got)
	}
}
