package traffic

import (
	"fmt"
	"os"
	"sort"
	"time"
)

// QueryLinkQuality derives rolling RTT percentiles from unique, already
// verified report.neighbors summaries. Repeated control collection frames can
// carry the same node-owned observation timestamp; those copies count once.
func (s *Store) QueryLinkQuality(start, end time.Time) ([]LinkQuality, error) {
	if s == nil {
		return nil, fmt.Errorf("traffic store is nil")
	}
	start, end = start.UTC(), end.UTC()
	if !end.After(start) {
		return nil, fmt.Errorf("traffic quality query end must be after start")
	}

	s.mu.Lock()
	if s.closed || s.lock == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("traffic store is closed")
	}
	frames, err := s.framesLocked()
	frames = append([]Frame(nil), frames...)
	s.mu.Unlock()
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	type aggregate struct {
		from, to       string
		values         []int
		observations   int
		failed         int
		lastObservedAt string
	}
	byLink := map[string]*aggregate{}
	seen := map[string]EdgeSample{}
	for _, frame := range frames {
		for _, edge := range frame.Edges {
			at, err := time.Parse(time.RFC3339, edge.TS)
			if err != nil {
				return nil, fmt.Errorf("parse retained edge timestamp: %w", err)
			}
			at = at.UTC()
			if at.Before(start) || !at.Before(end) {
				continue
			}
			key := edgeSampleKey(edge)
			if previous, ok := seen[key]; ok {
				if previous != edge {
					return nil, fmt.Errorf("conflicting retained edge sample %s/%s at %s", edge.Node, edge.Peer, edge.TS)
				}
				continue
			}
			seen[key] = edge
			linkID := LinkID(edge.Node, edge.Peer)
			agg := byLink[linkID]
			if agg == nil {
				from, to := LinkEndpoints(edge.Node, edge.Peer)
				agg = &aggregate{from: from, to: to}
				byLink[linkID] = agg
			}
			agg.observations++
			if edge.Failures >= edge.Samples {
				agg.failed++
			} else {
				agg.values = append(agg.values, edge.RTTMS)
			}
			if edge.TS > agg.lastObservedAt {
				agg.lastObservedAt = edge.TS
			}
		}
	}

	ids := make([]string, 0, len(byLink))
	for id := range byLink {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]LinkQuality, 0, len(ids))
	for _, id := range ids {
		agg := byLink[id]
		sort.Ints(agg.values)
		quality := LinkQuality{
			From: agg.from, To: agg.to, Observations: agg.observations,
			FailedObservations: agg.failed, LastObservedAt: agg.lastObservedAt,
		}
		if len(agg.values) > 0 {
			quality.P50MS = nearestRank(agg.values, 50)
			quality.P95MS = nearestRank(agg.values, 95)
		}
		out = append(out, quality)
	}
	return out, nil
}

func nearestRank(sorted []int, percentile int) int {
	if len(sorted) == 0 {
		return 0
	}
	index := (percentile*len(sorted)+99)/100 - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
