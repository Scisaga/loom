package clientadapter

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// ServiceConnectionIDs projects the data plane's actual connection chains.
// It never infers ownership from a destination, an exit, or a shared resource.
func ServiceConnectionIDs(body []byte, scopes []string) ([]string, error) {
	var snapshot struct {
		Connections json.RawMessage `json:"connections"`
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return nil, err
	}
	var connections []struct {
		ID     string   `json:"id"`
		Chains []string `json:"chains"`
	}
	if len(snapshot.Connections) == 0 || json.Unmarshal(snapshot.Connections, &connections) != nil {
		return nil, errors.New("Service connection snapshot is missing or invalid")
	}
	wanted := map[string]bool{}
	for _, scope := range scopes {
		wanted[scope] = true
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, connection := range connections {
		matches := false
		for _, scope := range connection.Chains {
			matches = matches || wanted[scope]
		}
		if !matches {
			continue
		}
		id := connection.ID
		if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' || seen[id] {
			return nil, errors.New("Service connection identity is invalid")
		}
		decoded, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
		if err != nil || len(decoded) != 16 || strings.ToLower(id) != id {
			return nil, errors.New("Service connection identity is invalid")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
