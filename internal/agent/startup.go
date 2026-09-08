package agent

import (
	"time"

	"loom/internal/measure"
	"loom/internal/model"
)

// startupComparison only chooses which missing physical observations to
// collect. It never supplies a selector decision or changes MinSamples.
// Exploration is the existing first bounded round; only its best promising
// successful challenger can receive a short, bounded follow-up comparison.
type startupComparison struct {
	current, challenger string
	next, deadline      time.Time
	interval            time.Duration
	remaining           int
}

func newStartupComparison(d *Decl, current string, probed []Cand, sums []measure.Summary, now time.Time, interval time.Duration) *startupComparison {
	if interval <= 0 || d.MinSamples <= 1 {
		return nil
	}
	byTag := startupSummaries(sums)
	cur, ok := byTag[current]
	if !ok || cur.Samples <= cur.Failures {
		return nil // The ordinary Decide loop owns failure recovery.
	}
	var best measure.Summary
	for _, c := range probed {
		s, ok := byTag[c.Tag]
		if !ok || c.Tag == current || !worthStartupComparison(d, cur, s) {
			continue
		}
		if best.CandidateID == "" || rankOf(d.Objective, s).less(rankOf(d.Objective, best)) ||
			rankOf(d.Objective, s) == rankOf(d.Objective, best) && s.CandidateID < best.CandidateID {
			best = s
		}
	}
	if best.CandidateID == "" || cur.Samples >= d.MinSamples && best.Samples >= d.MinSamples {
		return nil
	}
	return &startupComparison{current: current, challenger: best.CandidateID, next: now.Add(interval), deadline: now.Add(time.Minute), interval: interval, remaining: d.MinSamples - 1}
}

func startupSummaries(sums []measure.Summary) map[string]measure.Summary {
	byTag := make(map[string]measure.Summary, len(sums))
	for _, summary := range sums {
		byTag[summary.CandidateID] = summary
	}
	return byTag
}

func worthStartupComparison(d *Decl, current, candidate measure.Summary) bool {
	if candidate.Samples <= candidate.Failures || current.Samples <= current.Failures {
		return false
	}
	if d.Objective == model.Throughput && (candidate.KBps <= 0 || current.KBps <= 0) {
		return false
	}
	challenger, incumbent := rankOf(d.Objective, candidate), rankOf(d.Objective, current)
	if challenger.failureRate != incumbent.failureRate {
		return challenger.failureRate < incumbent.failureRate
	}
	return incumbent.score > 0 && (incumbent.score-challenger.score)/incumbent.score > d.SwitchThreshold
}

func (s *startupComparison) active(now time.Time) bool {
	return s != nil && s.remaining > 0 && now.Before(s.deadline)
}

// candidates returns only actual sample deficits. Repeated/multitarget samples
// are counted by the same Summary as Decide, and signed ProbeBudget still caps
// each supplementary round. No candidate outside the first comparison enters.
func (s *startupComparison) candidates(d *Decl, current string, sums []measure.Summary, now time.Time) []Cand {
	if !s.active(now) || current != s.current {
		return nil
	}
	byTag := startupSummaries(sums)
	cur, haveCur := byTag[s.current]
	other, haveOther := byTag[s.challenger]
	if !haveCur || !haveOther || !worthStartupComparison(d, cur, other) {
		return nil
	}
	var picked []Cand
	for _, tag := range []string{s.current, s.challenger} {
		if byTag[tag].Samples >= d.MinSamples {
			continue
		}
		for _, candidate := range d.Candidates {
			if candidate.Tag == tag {
				picked = append(picked, candidate)
				break
			}
		}
	}
	if d.ProbeBudget > 0 && len(picked) > d.ProbeBudget {
		picked = picked[:d.ProbeBudget]
	}
	return picked
}

func (s *startupComparison) sampled(now time.Time) {
	s.remaining--
	s.next = now.Add(s.interval)
}
