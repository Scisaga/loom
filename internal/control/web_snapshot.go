package control

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// WebSnapshot is a redacted projection for the existing control UI. It is never
// accepted as an operation or used to restore authority.
type WebSnapshot struct {
	Schema          int                `json:"schema"`
	NetworkID       string             `json:"network_id"`
	ControlConfigID string             `json:"control_config_id"`
	FactFrontier    []FactFrontier     `json:"fact_frontier"`
	Targets         []TargetState      `json:"targets"`
	Capabilities    WebCapabilities    `json:"capabilities"`
	UIState         WebUIState         `json:"ui_state"`
	Devices         []Device           `json:"devices"`
	Links           []Link             `json:"links"`
	Paths           []Path             `json:"paths"`
	Policies        []NetworkPolicy    `json:"policies"`
	PolicyInvites   []WebPolicyInvite  `json:"policy_invites"`
	Services        []Service          `json:"services"`
	Releases        []Release          `json:"releases"`
	Publisher       *PublisherStatus   `json:"publisher,omitempty"`
	Deployments     []Deployment       `json:"deployments"`
	Events          []Event            `json:"events"`
	Traffic         []TrafficBucket    `json:"traffic"`
	Administrators  []WebAdministrator `json:"administrators"`
}

type WebAdministrator struct {
	ID          string `json:"id"`
	Subject     string `json:"subject"`
	Fingerprint string `json:"fingerprint"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}

type WebCapabilities struct {
	Credential string   `json:"credential"`
	Admin      bool     `json:"admin"`
	Operations []string `json:"operations"`
}

type WebWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type WebUIState struct {
	LocalWritable bool         `json:"local_writable"`
	Warnings      []WebWarning `json:"warnings"`
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

func snapshotWarnings(messages []string) []WebWarning {
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
	result := make([]WebWarning, 0, len(codes))
	for _, code := range codes {
		result = append(result, WebWarning{Code: code, Message: byCode[code]})
	}
	return result
}

func snapshotEvents(events []Event) []Event {
	result := append([]Event{}, events...)
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

func buildWebSnapshot(projection Projection, admin, local, writable bool, releases ...ReleaseSet) WebSnapshot {
	capabilities := WebCapabilities{Credential: "none", Admin: admin, Operations: []string{}}
	if admin {
		capabilities.Credential = "admin"
	}
	if local {
		capabilities.Credential = "local_admin"
	}
	if admin && writable {
		capabilities.Operations = []string{"admin_certificate.delete", "admin_certificate.put", "device.delete", "device.put", "device.revoke", "expected_component.delete", "expected_component.put", "invite.cancel", "invite.issue", "policy.delete", "policy.put", "service.delete", "service.put"}
	}
	devices := projectWebDevices(projection, releases...)
	warnings := []WebWarning{}
	for _, device := range devices {
		if device.ComponentError != "" {
			warnings = append(warnings, WebWarning{Code: "expected_component_unavailable", Message: device.ID + ": " + device.ComponentError})
		}
	}
	for _, target := range projection.Targets {
		if target.Conflicted {
			warnings = append(warnings, WebWarning{Code: "conflicting_facts", Message: target.TargetKind + " " + target.TargetID + " has conflicting changes."})
		}
	}
	for _, item := range projection.InvalidMaterials {
		warnings = append(warnings, WebWarning{Code: "invalid_fact", Message: item.MaterialID + ": " + item.Reason})
	}
	if len(projection.PendingMaterialIDs) > 0 {
		warnings = append(warnings, WebWarning{Code: "missing_dependencies", Message: "Some authenticated facts await their dependencies; affected targets are unavailable."})
	}
	return WebSnapshot{Schema: 3, NetworkID: projection.NetworkID, ControlConfigID: projection.ControlConfigID,
		FactFrontier: append([]FactFrontier{}, projection.Frontier...), Targets: append([]TargetState{}, projection.Targets...),
		Capabilities: capabilities, UIState: WebUIState{LocalWritable: writable, Warnings: warnings},
		Devices: devices, Links: projectWebLinks(projection), Paths: projectWebPaths(projection, releases...), Policies: append([]NetworkPolicy{}, projection.NetworkIntent.Policies...),
		PolicyInvites: []WebPolicyInvite{},
		Services:      append([]Service{}, projection.NetworkIntent.Services...), Releases: []Release{}, Deployments: []Deployment{},
		Events: []Event{}, Traffic: []TrafficBucket{}, Administrators: projectWebAdministrators(projection)}
}
