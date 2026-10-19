package control

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// Read original positions, including reports which break a failure sequence.
// The policy, rather than this reader, checks current View and sample scope.
// Passing a prior acceptance time also provides the pre-change baseline; the
// pinned database high-water remains real even when its original is later.
func (server *Server) wgPortRecoveryReports(ctx context.Context, projection Projection, now time.Time) ([]WGPortRecoveryReports, error) {
	if server.Runtime == nil || server.Runtime.Reports == nil || now.IsZero() || now.Add(-wgPortRecoveryWindow).UnixMilli() < 0 {
		return nil, errors.New("WG port recovery report originals or time unavailable")
	}
	ids := map[string]bool{}
	for _, device := range projection.DeviceAuthorizations {
		ids[device.ID] = true
	}
	for _, member := range projection.Config.Members {
		if _, found := identityFor(projection, member.NodeID); found {
			ids[member.NodeID] = true
		}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	result := make([]WGPortRecoveryReports, 0, len(ordered))
	for _, id := range ordered {
		history := WGPortRecoveryReports{DeviceID: id, Reports: []DeviceReport{}}
		err := server.Runtime.Reports.walkDeviceHistorySnapshot(ctx, projection.NetworkID, id, func(highest U64, ref reportReference, original *reportHistoryOriginal) error {
			history.Highest = highest
			if original == nil {
				if ref.ReportedAt >= now.Add(-wgPortRecoveryWindow).UnixMilli() && ref.ReportedAt <= now.UnixMilli() {
					history.Forked = true
				}
				return nil
			}
			report := original.report
			if report.ReportedAt <= now.UnixMilli() {
				history.Reports = append(history.Reports, report)
			}
			return nil
		}, reportHistoryWindow{kind: reportTime, from: now.Add(-wgPortRecoveryWindow).UnixMilli(), until: now.UnixMilli()})
		if err != nil {
			return nil, err
		}
		result = append(result, history)
	}
	return result, nil
}

// Resource facts and their existing protected first-reception annotations are
// sufficient to reconstruct cooldown and automatic-attempt limits after restart.
// Older manual receipts are irrelevant; a missing automatic receipt cannot be
// assumed to precede the attempt window. This does not create a recovery store.
func (authority *Authority) wgPortRecoveryChanges(resourceID string, now time.Time) ([]WGPortRecoveryChange, error) {
	head, facts, err := authority.wgPortRecoveryResourceFacts(resourceID, now)
	if err != nil {
		return nil, err
	}
	result := []WGPortRecoveryChange{}
	for id, material := range facts {
		if id != head && !wgPortRecoveryAutomatic(material) {
			continue
		}
		value, err := authority.wgPortRecoveryReceipt(id, material, now)
		if err != nil {
			return nil, err
		}
		if id == head || !value.ReceivedAt.Before(now.Add(-wgPortRecoveryAttemptWindow)) {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].ReceivedAt.Equal(result[j].ReceivedAt) {
			return result[i].ReceivedAt.Before(result[j].ReceivedAt)
		}
		return result[i].MaterialID < result[j].MaterialID
	})
	return result, nil
}

// Avoid only ports replaced by an automatic attempt in the last seven days.
// Both a failed old port and an unverified replacement restored by a subsequent
// ordinary put can be reconstructed from the immutable same-target dependency.
// Expiration restores eligibility; there is no durable blacklist.
func (authority *Authority) wgPortRecoveryAvoidedPorts(resourceID string, now time.Time) ([]int, error) {
	head, facts, err := authority.wgPortRecoveryResourceFacts(resourceID, now)
	if err != nil {
		return nil, err
	}
	if _, err := authority.wgPortRecoveryReceipt(head, facts[head], now); err != nil {
		return nil, err
	}
	ports := map[int]bool{}
	for id, material := range facts {
		if !wgPortRecoveryAutomatic(material) {
			continue
		}
		received, err := authority.wgPortRecoveryReceipt(id, material, now)
		if err != nil {
			return nil, err
		}
		if !received.ReceivedAt.After(now.Add(-7 * 24 * time.Hour)) {
			continue
		}
		current, found := wgPortRecoveryResourceValue(material, resourceID)
		if !found || current.Kind != "wireguard" {
			return nil, errors.New("WG port recovery automatic original has no WG resource")
		}
		var parents []Material
		for _, dependency := range material.Dependencies {
			if parent, exists := facts[dependency]; exists {
				parents = append(parents, parent)
			}
		}
		if len(parents) != 1 {
			return nil, errors.New("WG port recovery automatic change has no unique resource parent")
		}
		parent := parents[0]
		original, parentID, err := EncodeMaterial(parent)
		if err != nil {
			return nil, err
		}
		body, err := authority.Material(parentID)
		if err != nil || !bytes.Equal(original, body) {
			return nil, errors.New("WG port recovery parent original unavailable or changed")
		}
		previous, found := wgPortRecoveryResourceValue(parent, resourceID)
		if !found || previous.Kind != "wireguard" {
			return nil, errors.New("WG port recovery parent has no WG resource")
		}
		if previous.DialPort != current.DialPort {
			ports[previous.DialPort] = true
		}
	}
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result, nil
}

func wgPortRecoveryAutomatic(material Material) bool {
	return material.Operation == "resource.put" && strings.HasPrefix(material.RequestID, "wg-port-recovery-")
}

func wgPortRecoveryResourceValue(material Material, resourceID string) (TransportResource, bool) {
	switch value := effectiveMaterial(material).Payload.(type) {
	case TransportResource:
		return value, value.ID == resourceID
	}
	return TransportResource{}, false
}

// Capture immutable references under the authority lock; original-byte and
// reception reads run outside it, as they do for the existing event projection.
func (authority *Authority) wgPortRecoveryResourceFacts(resourceID string, now time.Time) (string, map[string]Material, error) {
	if ValidateID(resourceID) != nil || now.IsZero() || now.UnixNano() <= 0 {
		return "", nil, errors.New("WG port recovery resource history scope is invalid")
	}
	authority.mu.RLock()
	if authority.blocked != nil {
		err := authority.blocked
		authority.mu.RUnlock()
		return "", nil, err
	}
	target, found := authority.projection.CurrentTarget("resource", resourceID)
	target.MaterialIDs = append([]string{}, target.MaterialIDs...)
	originals := []Material{}
	for _, material := range authority.materials {
		if material.TargetKind == "resource" && material.TargetID == resourceID {
			originals = append(originals, material)
		}
	}
	authority.mu.RUnlock()
	if !found || target.Deleted || target.Conflicted || len(target.MaterialIDs) != 1 {
		return "", nil, errors.New("WG port recovery requires one active resource head")
	}
	facts := map[string]Material{}
	for _, material := range originals {
		if _, found := wgPortRecoveryResourceValue(material, resourceID); !found {
			continue
		}
		id, err := MaterialID(material)
		if err != nil {
			return "", nil, err
		}
		facts[id] = material
	}
	head := target.MaterialIDs[0]
	if _, found := facts[head]; !found {
		return "", nil, errors.New("WG port recovery resource head original unavailable")
	}
	return head, facts, nil
}

func (authority *Authority) wgPortRecoveryReceipt(id string, material Material, now time.Time) (WGPortRecoveryChange, error) {
	original, expectedID, err := EncodeMaterial(material)
	if err != nil || expectedID != id {
		return WGPortRecoveryChange{}, errors.New("WG port recovery material identity changed")
	}
	body, err := authority.Material(id)
	if err != nil || !bytes.Equal(original, body) {
		return WGPortRecoveryChange{}, errors.New("WG port recovery material original unavailable or changed")
	}
	path, err := authority.materialPath(id)
	if err != nil {
		return WGPortRecoveryChange{}, err
	}
	received, err := fileReception(path, receptionAttribute)
	if err != nil || received.IsZero() || received.After(now) {
		return WGPortRecoveryChange{}, errors.New("WG port recovery resource receipt is absent or not yet valid")
	}
	return WGPortRecoveryChange{MaterialID: id, ReceivedAt: received, Automatic: wgPortRecoveryAutomatic(material) && !strings.HasPrefix(material.RequestID, "wg-port-recovery-restore-")}, nil
}
