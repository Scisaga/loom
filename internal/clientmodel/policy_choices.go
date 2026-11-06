package clientmodel

import (
	"errors"
	"sort"
	"strings"

	"loom/internal/control"
)

func EmptyPreference() Preference { return Preference{Schema: 3} }

// InitialPreference is used once, when the identity accepts its first LKG.
// Later changes reconcile an existing value and never initialize it again.
func InitialPreference(view control.DeviceView) Preference {
	services, options := PolicyOptions(view)
	kinds := map[string]string{}
	for _, service := range services {
		kinds[service.ID] = service.Kind
	}
	internet := []string{}
	lan := map[string][]string{}
	for _, policy := range options {
		if kinds[policy.ServiceID] == "local_network" {
			lan[policy.ServiceID] = append(lan[policy.ServiceID], policy.ID)
		} else {
			internet = append(internet, policy.ID)
		}
	}
	result := EmptyPreference()
	if len(internet) == 1 {
		result.PolicyID = internet[0]
	}
	for service, choices := range lan {
		if len(choices) == 1 {
			if result.LANPolicyIDs == nil {
				result.LANPolicyIDs = map[string]string{}
			}
			result.LANPolicyIDs[service] = choices[0]
		}
	}
	return result
}

// PolicyOptions projects only this device's own usable grants. Receiver-side
// policies and references to a deleted Service never become client choices.
func PolicyOptions(view control.DeviceView) ([]control.Service, []control.NetworkPolicy) {
	services := []control.Service{}
	policies := []control.NetworkPolicy{}
	for _, service := range view.Services {
		found := false
		for _, policy := range view.Policies {
			if policy.ServiceID == service.ID && policy.Action == "allow" && containsPolicy(view.PolicyIDs, policy.ID) {
				policies = append(policies, policy)
				found = true
			}
		}
		if found {
			services = append(services, service)
		}
	}
	sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	return services, policies
}

// Missing grants clear the single current choice. Reauthorization or a new
// Service cannot choose another Policy on the user's behalf.
func ReconcilePreference(preference Preference, view control.DeviceView) (Preference, error) {
	if err := preference.Validate(); err != nil {
		return Preference{}, err
	}
	result := preference.Clone()
	result.PolicyID = ""
	result.LANPolicyIDs = nil
	services, options := PolicyOptions(view)
	kinds := map[string]string{}
	for _, service := range services {
		kinds[service.ID] = service.Kind
	}
	for _, policy := range options {
		if kinds[policy.ServiceID] == "internet" && policy.ID == preference.PolicyID {
			result.PolicyID = policy.ID
		}
		if kinds[policy.ServiceID] == "local_network" && preference.LANPolicyIDs[policy.ServiceID] == policy.ID {
			if result.LANPolicyIDs == nil {
				result.LANPolicyIDs = map[string]string{}
			}
			result.LANPolicyIDs[policy.ServiceID] = policy.ID
		}
	}
	return result, nil
}
func ChoosePolicy(preference Preference, view control.DeviceView, policyID string) (Preference, error) {
	if err := preference.Validate(); err != nil {
		return Preference{}, err
	}
	services, options := PolicyOptions(view)
	kinds := map[string]string{}
	for _, service := range services {
		kinds[service.ID] = service.Kind
	}
	for _, policy := range options {
		if policy.ID == policyID {
			next := preference.Clone()
			if kinds[policy.ServiceID] == "local_network" {
				if next.LANPolicyIDs == nil {
					next.LANPolicyIDs = map[string]string{}
				}
				next.LANPolicyIDs[policy.ServiceID] = policy.ID
			} else {
				next.PolicyID = policy.ID
			}
			return next, nil
		}
	}
	return Preference{}, errors.New("requested Policy is not granted for this Service")
}

// Exactly one granted user choice may change under the identity file lock.
func ValidatePreferenceChange(before, after Preference, view control.DeviceView) error {
	if after.Validate() != nil {
		return errors.New("invalid saved Policy choices")
	}
	_, options := PolicyOptions(view)
	for _, policy := range options {
		next, err := ChoosePolicy(before, view, policy.ID)
		if err == nil && next.Equal(after) {
			return nil
		}
	}
	return errors.New("choose one granted Policy against the current protected profile")
}

func containsPolicy(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// SelectedServiceID is a display/sampling projection of the one saved Policy.
func SelectedServiceID(view control.DeviceView, preference Preference) string {
	_, options := PolicyOptions(view)
	for _, policy := range options {
		if policy.ID == preference.PolicyID {
			return policy.ServiceID
		}
	}
	return ""
}

// SelectorScopes identifies the one local access selection, independently of
// the number of granted Services or currently executable candidates.
func SelectorScopes(view control.DeviceView) []string {
	if !containsPolicy(view.Responsibilities, "access") {
		return []string{}
	}
	scopes := []string{control.AccessSelectorScope}
	services, _ := PolicyOptions(view)
	for _, service := range services {
		if service.Kind == "local_network" {
			scopes = append(scopes, "local_network:"+service.ID)
		}
	}
	sort.Strings(scopes)
	return scopes
}

// MeasurementPolicies limits access exploration to the current Internet choice
// and independent selected LAN mappings; egress coverage remains role-owned.
func MeasurementPolicies(preference Preference) []string {
	values := []string{}
	if preference.PolicyID != "" {
		values = append(values, preference.PolicyID)
	}
	for _, policy := range preference.LANPolicyIDs {
		if !containsPolicy(values, policy) {
			values = append(values, policy)
		}
	}
	sort.Strings(values)
	return values
}

func PolicyForSelector(preference Preference, scope string) Preference {
	if strings.HasPrefix(scope, "local_network:") {
		return Preference{Schema: 3, PolicyID: preference.PolicyForScope(scope)}
	}
	return Preference{Schema: 3, PolicyID: preference.PolicyID}
}

// ChangedSelectorScopes confines an explicit user operation to its Internet or
// LAN choice. Performance-only updates never use this connection-close path.
func ChangedSelectorScopes(before, after Preference) []string {
	scopes := []string{}
	if before.PolicyID != after.PolicyID {
		scopes = append(scopes, control.AccessSelectorScope)
	}
	services := map[string]bool{}
	for service := range before.LANPolicyIDs {
		services[service] = true
	}
	for service := range after.LANPolicyIDs {
		services[service] = true
	}
	for service := range services {
		if before.LANPolicyIDs[service] != after.LANPolicyIDs[service] {
			scopes = append(scopes, "local_network:"+service)
		}
	}
	sort.Strings(scopes)
	return scopes
}
