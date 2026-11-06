package clientmodel

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"time"

	"loom/internal/control"
	"loom/protocol"
)

// TCPRecoveryMeasurement is a disposable request for one already-authorized
// candidate/target pair. It neither applies that candidate nor grants access.
type TCPRecoveryMeasurement struct {
	CandidateID string `json:"candidate_id"`
	Target      string `json:"target"`
}

// TCPRecoveryMeasurements extracts this round's confirmed transport proposals.
// The caller runs ChooseWithNativeStability first and owns the same complete
// binding while admitting requests to the node's existing measurement budget.
// Only ordinary connections establish activity; calibration cannot renew it.
func TCPRecoveryMeasurements(routes []RouteCandidate, current Selection, memory SelectionMemory, native []Observation, generation string, now time.Time, rule PerformanceRule, activityWindow time.Duration) ([]TCPRecoveryMeasurement, error) {
	if rule.Validate() != nil || activityWindow <= 0 || !validName(generation) {
		return nil, errors.New("invalid TCP recovery input")
	}
	result := []TCPRecoveryMeasurement{}
	binding := memory.NativeBinding
	if current.Scope != control.AccessSelectorScope || current.Revision == "" || memory.PolicyID != current.PolicyID || memory.NetworkGeneration != generation || binding == nil || binding.Revision != current.Revision || binding.NetworkGeneration != generation || binding.ExecutionSpec == "" {
		return result, nil
	}
	allowed := map[string]bool{}
	for _, route := range routes {
		if route.Validate() != nil {
			return nil, errors.New("invalid TCP recovery candidate")
		}
		if route.PolicyID != current.PolicyID || CandidateSelectorScope(route) != current.Scope {
			continue
		}
		if route.FixedExit {
			return result, nil
		}
		allowed[route.ID] = true
	}
	recent := map[string]bool{}
	for _, sample := range native {
		if sample.Validate() != nil {
			return nil, errors.New("invalid TCP recovery observation")
		}
		if sample.Action != "tcp_connect" || sample.NetworkGeneration != generation || !allowed[sample.CandidateID] {
			continue
		}
		completed, _ := time.Parse(time.RFC3339Nano, sample.ObservedAt)
		started := time.UnixMilli(completed.UnixMilli() - sample.MetricMillis)
		if completed.After(now) || !now.Before(started.Add(activityWindow)) {
			continue
		}
		host, text, _ := net.SplitHostPort(sample.Target)
		port, _ := strconv.ParseUint(text, 10, 16)
		key, err := protocol.ConnectionTargetKey("tcp", host, uint16(port))
		if err != nil {
			return nil, err
		}
		recent[key] = true
	}
	for target, decision := range memory.Decisions {
		if target == "" || !decision.CalibrateTCP || !recent[target] || decision.Confirmations < rule.Confirmations || decision.Current != selectedTarget(current, target) || !allowed[decision.Pending] || decision.Pending == decision.Current {
			continue
		}
		network, _, _, err := protocol.ParseConnectionTargetKey(target)
		if err != nil {
			return nil, err
		}
		if network == "tcp" {
			result = append(result, TCPRecoveryMeasurement{CandidateID: decision.Pending, Target: target})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Target < result[j].Target })
	return result, nil
}
