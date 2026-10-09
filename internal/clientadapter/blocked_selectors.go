package clientadapter

import (
	"encoding/json"
	"errors"
)

// WithBlockedSelectors adds only a local rejection position. The signed profile,
// authorized candidates and reported selections never contain this position.
func WithBlockedSelectors(config string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	outbounds, ok := document["outbounds"].([]any)
	if !ok {
		return "", errors.New("runtime outbounds are invalid")
	}
	block := false
	for _, raw := range outbounds {
		value, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("runtime outbound is invalid")
		}
		if value["tag"] == BlockedSelection {
			if value["type"] != "block" {
				return "", errors.New("runtime rejection outbound is invalid")
			}
			block = true
		}
		if value["type"] == "selector" {
			members, ok := value["outbounds"].([]any)
			if !ok {
				return "", errors.New("runtime selector is invalid")
			}
			present := false
			for _, member := range members {
				present = present || member == BlockedSelection
			}
			if !present {
				value["outbounds"] = append(members, BlockedSelection)
			}
			value["default"] = BlockedSelection
		}
	}
	if !block {
		return "", errors.New("runtime rejection outbound is missing")
	}
	body, err := json.Marshal(document)
	return string(body), err
}
