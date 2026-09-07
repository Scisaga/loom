package agent

import (
	"fmt"
	"testing"
)

func TestBoundedProbeRotationCoversEveryCandidate(t *testing.T) {
	const total, budget = 20, 4
	candidates := make([]Cand, 0, total)
	for i := 0; i < total; i++ {
		candidates = append(candidates, Cand{Tag: fmt.Sprintf("c%02d", i)})
	}
	current := "c03"
	next := ""
	seen := map[string]int{}
	// Seven rounds provide 7*(budget-1)=21 non-current slots, enough to cover
	// all 19 alternatives. The old cursor advanced by budget and permanently
	// missed indexes 7, 11, 15, and 19 in this production-sized shape.
	for round := 0; round < 7; round++ {
		picked, following, skipped := pickProbeCandidates(candidates, current, budget, next)
		next = following
		if len(picked) != budget || skipped != total-budget {
			t.Fatalf("round %d: bounded result=%d skipped=%d", round, len(picked), skipped)
		}
		inRound := map[string]bool{}
		for _, candidate := range picked {
			if inRound[candidate.Tag] {
				t.Fatalf("round %d duplicated %s", round, candidate.Tag)
			}
			inRound[candidate.Tag] = true
			seen[candidate.Tag]++
		}
		if !inRound[current] {
			t.Fatalf("round %d did not probe current candidate", round)
		}
	}
	for _, candidate := range candidates {
		if seen[candidate.Tag] == 0 {
			t.Errorf("candidate %s was starved", candidate.Tag)
		}
	}
}

func TestProbeRotationCursorSurvivesPruningAndCandidateChanges(t *testing.T) {
	all := []Cand{{Tag: "a"}, {Tag: "b"}, {Tag: "c"}, {Tag: "d"}, {Tag: "e"}, {Tag: "f"}}
	picked, next, _ := pickProbeCandidates(all, "c", 3, "")
	if tags := candidateTags(picked); fmt.Sprint(tags) != "[c a b]" || next != "d" {
		t.Fatalf("first rotation=%v next=%q", tags, next)
	}

	// d is pruned exactly when it is due. A tag cursor resumes at the next
	// eligible member, then reaches d once it returns; a numeric slice index is
	// silently retargeted whenever the candidate list changes.
	withoutD := []Cand{{Tag: "f"}, {Tag: "e"}, {Tag: "c"}, {Tag: "b"}, {Tag: "a"}}
	picked, next, _ = pickProbeCandidates(withoutD, "c", 3, next)
	if tags := candidateTags(picked); fmt.Sprint(tags) != "[c e f]" || next != "a" {
		t.Fatalf("pruned rotation=%v next=%q", tags, next)
	}
	picked, next, _ = pickProbeCandidates(all, "c", 3, next)
	if tags := candidateTags(picked); fmt.Sprint(tags) != "[c a b]" || next != "d" {
		t.Fatalf("restored rotation prelude=%v next=%q", tags, next)
	}
	picked, _, _ = pickProbeCandidates(all, "c", 3, next)
	if tags := candidateTags(picked); fmt.Sprint(tags) != "[c d e]" {
		t.Fatalf("restored candidate did not re-enter rotation:%v", tags)
	}

	// If current was pruned, no slot is reserved for it.
	picked, _, _ = pickProbeCandidates([]Cand{{Tag: "a"}, {Tag: "b"}, {Tag: "d"}, {Tag: "e"}}, "c", 3, "")
	if len(picked) != 3 {
		t.Fatalf("pruned current wasted a probe slot:%v", candidateTags(picked))
	}
}

func candidateTags(candidates []Cand) []string {
	tags := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		tags = append(tags, candidate.Tag)
	}
	return tags
}
