package clientmodel

import (
	"errors"
	"sort"

	"loom/internal/control"
)

func EmptyPreference() Preference { return Preference{Schema: 3, Services: []ServicePreference{}} }

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

// ReconcilePreference initializes a Service once. Missing grants clear a choice
// but retain its record, so restart or later reauthorization cannot pick for it.
func ReconcilePreference(preference Preference, view control.DeviceView) (Preference, error) {
	if err := preference.Validate(); err != nil {
		return Preference{}, err
	}
	allowed := map[string][]string{}
	_, options := PolicyOptions(view)
	for _, policy := range options {
		allowed[policy.ServiceID] = append(allowed[policy.ServiceID], policy.ID)
	}
	values := map[string]ServicePreference{}
	for _, choice := range preference.Services {
		if !containsPolicy(allowed[choice.ServiceID], choice.PolicyID) {
			choice.PolicyID = ""
		}
		values[choice.ServiceID] = choice
	}
	for service, policies := range allowed {
		if _, initialized := values[service]; initialized {
			continue
		}
		choice := ServicePreference{ServiceID: service}
		if len(policies) == 1 {
			choice.PolicyID = policies[0]
		}
		values[service] = choice
	}
	result := EmptyPreference()
	for _, choice := range values {
		result.Services = append(result.Services, choice)
	}
	sort.Slice(result.Services, func(i, j int) bool { return result.Services[i].ServiceID < result.Services[j].ServiceID })
	return result, result.Validate()
}

func ChoosePolicy(preference Preference, view control.DeviceView, serviceID, policyID string) (Preference, error) {
	allowed := false
	_, options := PolicyOptions(view)
	for _, policy := range options {
		allowed = allowed || policy.ID == policyID && policy.ServiceID == serviceID && policy.Action == "allow" && containsPolicy(view.PolicyIDs, policyID)
	}
	if !allowed {
		return Preference{}, errors.New("requested policy is not granted for this Service")
	}
	result, err := ReconcilePreference(preference, view)
	if err != nil {
		return Preference{}, err
	}
	for i := range result.Services {
		if result.Services[i].ServiceID == serviceID {
			result.Services[i].PolicyID = policyID
		}
	}
	return result, nil
}

func containsPolicy(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// ServiceScopes is a disposable projection that includes Services with zero
// usable routes. Such Services must keep their default rejecting selector.
func ServiceScopes(view control.DeviceView) []string {
	values := []string{}
	for _, service := range view.Services {
		for _, policy := range view.Policies {
			if policy.ServiceID == service.ID && policy.Action == "allow" && containsPolicy(view.PolicyIDs, policy.ID) {
				values = append(values, service.Scope())
				break
			}
		}
	}
	sort.Strings(values)
	return values
}
