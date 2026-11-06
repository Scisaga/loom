package clientadapter

import (
	"errors"
	"sort"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

// ReportSelections projects actual complete selector readback. Target choices
// must share the saved Policy and Service; they cannot add a grant.
func ReportSelections(view control.DeviceView, preference clientmodel.Preference, statuses []SelectionStatus) ([]control.ReportSelection, error) {
	_, err := ReportedPolicyID(view, preference)
	if err != nil {
		return nil, err
	}
	if _, err := ReportedLANPolicyIDs(view, preference); err != nil {
		return nil, err
	}
	execution, err := control.ProjectDeviceCandidates(view, clientmodel.MeasurementPolicies(preference))
	if err != nil {
		return nil, err
	}
	seenScopes := map[string]bool{}
	routes := map[string]control.RouteCandidate{}
	for _, route := range execution.Routes {
		routes[route.ID] = route
	}
	result := []control.ReportSelection{}
	for _, status := range statuses {
		base, exists := routes[status.CandidateID]
		policy := preference.PolicyForScope(status.Scope)
		if !exists || !clientmodel.ValidSelectorScope(status.Scope) || seenScopes[status.Scope] || base.PolicyID != policy || clientmodel.CandidateSelectorScope(clientmodel.RouteCandidate{Scope: base.Scope}) != status.Scope {
			return nil, errors.New("actual selection is outside the current Policy")
		}
		seenScopes[status.Scope] = true
		result = append(result, control.ReportSelection{ServiceID: base.ServiceID, PolicyID: policy, CandidateID: base.ID})
		for target, id := range status.Targets {
			route, exists := routes[id]
			_, _, _, targetErr := protocol.ParseConnectionTargetKey(target)
			if !exists || targetErr != nil || route.PolicyID != policy || route.ServiceID != base.ServiceID {
				return nil, errors.New("actual target selection is outside the current Policy")
			}
			result = append(result, control.ReportSelection{ServiceID: base.ServiceID, PolicyID: policy, CandidateID: id, Target: target})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ServiceID+"\x00"+result[i].Target < result[j].ServiceID+"\x00"+result[j].Target
	})
	return result, nil
}
