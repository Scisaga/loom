package control

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

type WebCapabilityV2 struct {
	Credential string   `json:"credential"`
	Admin      bool     `json:"admin"`
	Operations []string `json:"operations"`
}

type WebWarningV2 struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type WebUIStateV2 struct {
	QuorumWritable bool           `json:"quorum_writable"`
	Warnings       []WebWarningV2 `json:"warnings"`
}

type WebSnapshotV2 struct {
	Schema       int              `json:"schema"`
	Head         string           `json:"head"`
	Sequence     uint64           `json:"sequence"`
	Capabilities WebCapabilityV2  `json:"capabilities"`
	UIState      WebUIStateV2     `json:"ui_state"`
	Devices      []Device         `json:"devices"`
	Links        []Link           `json:"links"`
	Paths        []Path           `json:"paths"`
	Policies     []NetworkPolicy  `json:"policies"`
	Services     []Service        `json:"services"`
	Releases     []Release        `json:"releases"`
	Publisher    *PublisherStatus `json:"publisher,omitempty"`
	Deployments  []Deployment     `json:"deployments"`
	Events       []Event          `json:"events"`
	Traffic      []TrafficBucket  `json:"traffic"`
}

func warningCode(message string) string {
	known := []struct{ text, code string }{
		{"deployment readback", "publisher_observation_unavailable"},
		{"release catalog", "release_catalog_unavailable"},
		{"event history", "event_history_unavailable"},
		{"conflicts with", "reserved_identity_conflict"},
	}
	lower := strings.ToLower(message)
	for _, value := range known {
		if strings.Contains(lower, value.text) {
			return value.code
		}
	}
	sum := sha256.Sum256([]byte(message))
	return "warning_" + hex.EncodeToString(sum[:6])
}

func snapshotWarnings(messages []string) []WebWarningV2 {
	byCode := map[string]string{}
	for _, message := range messages {
		if strings.TrimSpace(message) != "" {
			byCode[warningCode(message)] = message
		}
	}
	codes := make([]string, 0, len(byCode))
	for code := range byCode {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	result := make([]WebWarningV2, 0, len(codes))
	for _, code := range codes {
		result = append(result, WebWarningV2{Code: code, Message: byCode[code]})
	}
	return result
}

func snapshotEvents(events []Event) []Event {
	result := append([]Event(nil), events...)
	for index := range result {
		if result[index].ID == "" {
			sum := sha256.Sum256([]byte(result[index].At + "\x00" + result[index].Kind + "\x00" + result[index].Subject + "\x00" +
				result[index].From + "\x00" + result[index].To + "\x00" + result[index].Detail))
			result[index].ID = "event-" + hex.EncodeToString(sum[:8])
		}
		if result[index].Level == "" {
			result[index].Level = "information"
		}
	}
	return result
}

func buildWebSnapshot(projection WebProjection, authority Projection, head GovernanceHead, admin, local, quorumWritable bool) WebSnapshotV2 {
	credential := "reader"
	operations := []string{}
	if admin && quorumWritable {
		credential = "admin"
		operations = append(operations, "device.revoke", "enrollment.approve")
		if authority.NetworkIntent != nil {
			operations = append(operations, "enrollment.create", "service.delete", "service.put")
		}
	} else if admin {
		credential = "admin"
	}
	if local && quorumWritable {
		credential = "local_admin"
		operations = append(operations, "existing-node.rejoin")
		if authority.NetworkIntent == nil {
			operations = append(operations, "network.import")
		}
	} else if local {
		credential = "local_admin"
	}
	sort.Strings(operations)
	policies := []NetworkPolicy{}
	if authority.NetworkIntent != nil {
		policies = append(policies, authority.NetworkIntent.Policies...)
	}
	return WebSnapshotV2{Schema: 2, Head: HeadID(head), Sequence: head.Index,
		Capabilities: WebCapabilityV2{Credential: credential, Admin: admin, Operations: operations},
		UIState:      WebUIStateV2{QuorumWritable: quorumWritable, Warnings: snapshotWarnings(projection.UIState.Warnings)},
		Devices:      projection.Devices, Links: projection.Links, Paths: projection.Paths, Policies: policies,
		Services: projection.Services, Releases: projection.Releases, Publisher: projection.Publisher,
		Deployments: projection.Deployments, Events: snapshotEvents(projection.Events), Traffic: projection.Traffic}
}
