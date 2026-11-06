package protocol

import "errors"

// PolicyScope is the same canonical value used by control and receivers. It
// has no authority or lifecycle separate from its containing Policy.
type PolicyScope struct {
	Mode    string   `json:"mode"`
	NodeIDs []string `json:"node_ids"`
}

func (scope PolicyScope) Validate() error {
	if scope.NodeIDs == nil {
		return errors.New("policy scope node IDs must be an explicit collection")
	}
	switch scope.Mode {
	case "any", "none":
		if len(scope.NodeIDs) != 0 {
			return errors.New("policy scope mode cannot carry node IDs")
		}
	case "only":
		if len(scope.NodeIDs) == 0 {
			return errors.New("policy only scope requires node IDs")
		}
	default:
		return errors.New("policy scope mode is invalid")
	}
	for index, node := range scope.NodeIDs {
		if ValidateID(node) != nil || node == "direct" || index > 0 && scope.NodeIDs[index-1] >= node {
			return errors.New("policy scope node IDs are invalid or not uniquely sorted")
		}
	}
	return nil
}
func (scope PolicyScope) Allows(node string) bool {
	if scope.Validate() != nil || ValidateID(node) != nil || node == "direct" {
		return false
	}
	if scope.Mode == "any" {
		return true
	}
	if scope.Mode == "only" {
		for _, allowed := range scope.NodeIDs {
			if allowed == node {
				return true
			}
		}
	}
	return false
}
