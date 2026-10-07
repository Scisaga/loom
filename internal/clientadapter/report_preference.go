package clientadapter

import (
	"loom/internal/clientmodel"
	"loom/internal/control"
)

// ReportedPreference projects the existing local setting without deriving it
// from the current selector, or granting permission to the requested exit.
func ReportedPreference(view control.DeviceView, preference clientmodel.Preference) (*control.ReportPreference, error) {
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
	value := &control.ReportPreference{Mode: string(preference.Mode), Exit: preference.Exit}
	return value, value.Validate()
}
