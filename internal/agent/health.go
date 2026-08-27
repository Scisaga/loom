package agent

import (
	"time"

	"loom/internal/measure"
)

const (
	healthSuccess  = "success"
	healthDegraded = "degraded"
	healthFailed   = "failed"
	healthStale    = "stale"
	healthUnknown  = "unknown"
)

// summarizeCandidateHealth 把 Decide 使用的同一份 fresh summary 变成对外摘要。
// all 只用来区分“曾经量过但已过期”和“从未见过”；陈旧样本绝不重新参与
// 成功/失败或延迟计算。
func summarizeCandidateHealth(d *Decl, selected string, fresh []measure.Summary,
	all []measure.Measurement) *CandidateHealth {

	h := &CandidateHealth{Candidates: len(d.Candidates), SelectedState: healthUnknown}
	configured := make(map[string]bool, len(d.Candidates))
	for _, c := range d.Candidates {
		configured[c.Tag] = true
	}
	seenBefore := make(map[string]bool, len(d.Candidates))
	for i := range all {
		m := &all[i]
		if m.Declaration != d.ID || !configured[m.CandidateID] {
			continue
		}
		if _, err := time.Parse(time.RFC3339, m.TS); err == nil {
			seenBefore[m.CandidateID] = true
		}
	}
	byTag := make(map[string]measure.Summary, len(fresh))
	for _, s := range fresh {
		if configured[s.CandidateID] && s.Samples > 0 {
			byTag[s.CandidateID] = s
		}
	}

	var bestP50, bestKBps *int
	for _, c := range d.Candidates {
		state := healthUnknown
		s, ok := byTag[c.Tag]
		switch {
		case ok && s.Failures == 0:
			state = healthSuccess
			h.RecentSuccess++
		case ok && s.Failures < s.Samples:
			state = healthDegraded
			h.RecentDegraded++
		case ok:
			state = healthFailed
			h.RecentFailed++
		case seenBefore[c.Tag]:
			state = healthStale
			h.Stale++
		default:
			h.Unknown++
		}
		if ok && s.Samples > s.Failures && (bestP50 == nil || s.P50 < *bestP50) {
			v := s.P50
			bestP50 = &v
		}
		if ok && s.Samples > s.Failures && s.KBps > 0 && (bestKBps == nil || s.KBps > *bestKBps) {
			v := s.KBps
			bestKBps = &v
		}
		if c.Tag == selected {
			h.SelectedState = state
			if ok {
				h.SelectedSamples = s.Samples
				h.SelectedFailures = s.Failures
				if s.Samples > s.Failures {
					p50, p95 := s.P50, s.P95
					h.SelectedP50MS, h.SelectedP95MS = &p50, &p95
					if s.KBps > 0 {
						kbps := s.KBps
						h.SelectedKBps = &kbps
					}
				}
			}
		}
	}
	h.BestP50MS, h.BestKBps = bestP50, bestKBps
	return h
}
