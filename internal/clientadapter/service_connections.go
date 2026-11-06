package clientadapter

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"loom/internal/control"
	"sort"
	"strings"
)

// ServiceConnectionIDs selects the pinned Service within its actual source
// scope. Shared access chains alone cannot identify an older connection's Service.
func ServiceConnectionIDs(body []byte, serviceID, scope string) ([]string, error) {
	if control.ValidateID(serviceID) != nil || scope != "access" && scope != "local_network:"+serviceID || len(body) == 0 || len(body) > 8<<20 {
		return nil, errors.New("invalid Service connection request")
	}
	var snapshot struct {
		Connections json.RawMessage `json:"connections"`
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return nil, err
	}
	var connections []struct {
		ID       string   `json:"id"`
		Chains   []string `json:"chains"`
		Metadata struct {
			ServiceID string `json:"serviceID"`
		} `json:"metadata"`
	}
	if len(snapshot.Connections) == 0 || json.Unmarshal(snapshot.Connections, &connections) != nil {
		return nil, errors.New("Service connection snapshot is missing or invalid")
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, connection := range connections {
		matches := false
		for _, chain := range connection.Chains {
			matches = matches || chain == scope
		}
		if !matches {
			continue
		}
		if control.ValidateID(connection.Metadata.ServiceID) != nil {
			return nil, errors.New("source connection is missing its pinned Service")
		}
		if connection.Metadata.ServiceID != serviceID {
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
