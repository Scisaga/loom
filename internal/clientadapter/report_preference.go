package clientadapter

import (
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// ReportedPolicyChoices samples the saved setting independently of actual paths.
func ReportedPolicyChoices(view control.DeviceView, preference clientmodel.Preference) (*[]control.PolicyChoice, error) {
	access := false
	for _, role := range view.Responsibilities {
		access = access || role == "access"
	}
	if !access {
		return nil, nil
	}
	if err := preference.Validate(); err != nil {
		return nil, err
	}
	values := append([]control.PolicyChoice{}, preference.Services...)
	return &values, nil
}
