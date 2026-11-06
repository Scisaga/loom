package control

import (
	"errors"
	"sort"
)

// DeviceExecution is a one-way calculation result, never a signed value, LKG,
// durable authorization, input decoder or independently managed lifecycle.
type DeviceExecution struct {
	DeviceView
	SelectedPolicyIDs    []string
	Links                []NetworkLink
	Routes               []RouteCandidate
	RuntimeProfile       *RuntimeProfile
	BusinessProbeTargets []ServiceProbeTargets
	WireGuardPeers       []WireGuardAccessPeer
	AccessGrants         []AccessGrant
	PolicyExits          []PolicyExits
}
type AccessGrant struct {
	DeviceID string
	PolicyID string
}
type PolicyExits struct {
	PolicyID string
	NodeIDs  []string
}

func (DeviceExecution) MarshalJSON() ([]byte, error) {
	return nil, errors.New("execution projections cannot be signed or persisted as authorization")
}

// ProjectDeviceExecution derives only explicitly selected access Policies. A
// nil/empty selection means pending, never "all granted" or an implicit default.
func ProjectDeviceExecution(view DeviceView, selected []string) (DeviceExecution, error) {
	execution, err := ProjectDeviceCandidates(view, selected)
	if err != nil {
		return DeviceExecution{}, err
	}
	credentials, err := executionCredentials(view)
	if err != nil {
		return DeviceExecution{}, err
	}
	_, execution.RuntimeProfile, err = renderSegmentedRuntime(execution, credentials)
	return execution, err
}

// ProjectDeviceCandidates omits native rendering for selection, reports and UI.
func ProjectDeviceCandidates(view DeviceView, selected []string) (DeviceExecution, error) {
	if err := view.Validate(); err != nil {
		return DeviceExecution{}, err
	}
	execution, err := executionFacts(view)
	if err != nil {
		return DeviceExecution{}, err
	}
	if selected == nil {
		selected = []string{}
	}
	if err = validateIDSet(selected); err != nil {
		return DeviceExecution{}, err
	}
	services, policies, err := servicePermissionValues(view)
	if err != nil {
		return DeviceExecution{}, err
	}
	internet := false
	lan := map[string]bool{}
	for _, id := range selected {
		policy, ok := policies[id]
		service := services[policy.ServiceID]
		if !ok || policy.Action != "allow" {
			return DeviceExecution{}, errors.New("execution requested an unassigned Policy")
		}
		if service.Kind == "internet" {
			if internet {
				return DeviceExecution{}, errors.New("only one Internet Policy can execute")
			}
			internet = true
		} else {
			if lan[service.ID] {
				return DeviceExecution{}, errors.New("LAN Service has multiple selected Policies")
			}
			lan[service.ID] = true
		}
		candidates, err := candidateEntries(execution, service, policy)
		if err != nil {
			return DeviceExecution{}, err
		}
		execution.Routes = append(execution.Routes, candidates...)
	}
	execution.SelectedPolicyIDs = append([]string{}, selected...)
	sort.Slice(execution.Routes, func(i, j int) bool { return execution.Routes[i].ID < execution.Routes[j].ID })
	return execution, nil
}
