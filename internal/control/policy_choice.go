package control

import "errors"

// PolicyChoice is a local intent sampled by a report, never an authorization.
// Omitting PolicyID means this initialized Service is waiting for a choice.
type PolicyChoice struct {
	ServiceID string `json:"service_id"`
	PolicyID  string `json:"policy_id,omitempty"`
}

func (value PolicyChoice) Validate() error {
	if ValidateID(value.ServiceID) != nil || value.PolicyID != "" && ValidateID(value.PolicyID) != nil {
		return errors.New("Service policy choice is invalid")
	}
	return nil
}

func ValidatePolicyChoices(values []PolicyChoice) error {
	if values == nil {
		return errors.New("policy choices require an explicit collection")
	}
	for i, value := range values {
		if value.Validate() != nil || i > 0 && values[i-1].ServiceID >= value.ServiceID {
			return errors.New("policy choices are invalid or not uniquely sorted")
		}
	}
	return nil
}
