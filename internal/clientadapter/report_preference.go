package clientadapter

import (
	"errors"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// ReportedPolicyID samples the one saved setting, independently of execution.
func ReportedPolicyID(view control.DeviceView, preference clientmodel.Preference) (string, error) {
	if err := preference.Validate(); err != nil {
		return "", err
	}
	if preference.PolicyID == "" {
		return "", nil
	}
	_, options := clientmodel.PolicyOptions(view)
	for _, policy := range options {
		if policy.ID == preference.PolicyID {
			for _, service := range view.Services {
				if service.ID == policy.ServiceID && service.Kind == "internet" {
					return policy.ID, nil
				}
			}
			return "", errors.New("LAN choice cannot replace the current Internet Policy")
		}
	}
	return "", errors.New("reported Policy is not currently granted")
}

// ReportedLANPolicyIDs is a read-only sample of the same identity Preference.
func ReportedLANPolicyIDs(view control.DeviceView, preference clientmodel.Preference) (map[string]string, error) {
	reconciled, err := clientmodel.ReconcilePreference(preference, view)
	if err != nil {
		return nil, err
	}
	for service, policy := range preference.LANPolicyIDs {
		if reconciled.LANPolicyIDs[service] != policy {
			return nil, errors.New("saved LAN choice is outside current authorization")
		}
	}
	return reconciled.LANPolicyIDs, nil
}
