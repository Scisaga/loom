package control

import (
	"net/http"
	"sort"
)

// ReleaseDeploymentInputs is a disposable projection of the current verified
// authority. It conveys no signing capability, runtime key, or release state.
type ReleaseDeploymentInputs struct {
	NetworkID        string                  `json:"network_id"`
	GenesisDigest    string                  `json:"genesis_digest"`
	ControlConfigID  string                  `json:"control_config_id"`
	Nodes            []ReleaseDeploymentNode `json:"nodes"`
	DistributionURLs []string                `json:"distribution_urls"`
}

type ReleaseDeploymentNode struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
}

func (server *Server) releaseDeploymentInputs(w http.ResponseWriter, r *http.Request) {
	if !server.admin(r) {
		http.Error(w, "administrator certificate required", http.StatusForbidden)
		return
	}
	if server.Runtime == nil || !server.Runtime.Writable() {
		http.Error(w, "control authority unavailable", http.StatusServiceUnavailable)
		return
	}
	p := server.Runtime.Authority.Snapshot()
	value := ReleaseDeploymentInputs{NetworkID: p.NetworkID, GenesisDigest: server.Config.GenesisID,
		ControlConfigID: p.ControlConfigID, Nodes: []ReleaseDeploymentNode{}, DistributionURLs: []string{}}
	urls := map[string]bool{}
	for _, device := range p.DeviceAuthorizations {
		value.Nodes = append(value.Nodes, ReleaseDeploymentNode{NodeID: device.ID, PublicKey: device.DevicePublicKey})
		for _, url := range device.DistributionURLs {
			urls[url] = true
		}
	}
	sort.Slice(value.Nodes, func(i, j int) bool { return value.Nodes[i].NodeID < value.Nodes[j].NodeID })
	for url := range urls {
		value.DistributionURLs = append(value.DistributionURLs, url)
	}
	sort.Strings(value.DistributionURLs)
	writeJSON(w, http.StatusOK, value)
}
