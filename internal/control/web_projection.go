package control

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// initialWebProjection recovers the authenticated node inventory imported by
// the genesis material. It is used only to repair the UI projection when an
// already-committed enrollment reused a control/node identity; it is not a
// second writable inventory.
func (authority *Authority) initialWebProjection() (WebProjection, error) {
	consensus, _, _ := authority.Snapshot()
	if len(consensus.Entries) == 0 {
		return WebProjection{}, errors.New("genesis material is unavailable")
	}
	body, err := authority.Material(consensus.Entries[0].MaterialID)
	if err != nil {
		return WebProjection{}, err
	}
	material, err := DecodeMaterial(body)
	if err != nil || material.Kind != "genesis" || material.Genesis == nil {
		return WebProjection{}, errors.New("genesis projection is unavailable")
	}
	return material.Genesis.Projection, nil
}

func projectCurrentEvents(projection WebProjection, reports, history []DeviceReport, now time.Time) []Event {
	events := append([]Event(nil), projection.Events...)
	events = append(events, projectReportHistory(history)...)
	reportedAt := map[string]string{}
	for _, report := range reports {
		reportedAt[report.DeviceID] = report.ReportedAt
	}
	for _, device := range projection.Devices {
		switch device.Availability {
		case "available":
		case "unavailable":
			events = append(events, Event{At: reportedAt[device.ID], Kind: "observation", Subject: device.ID,
				From: "available", To: "unavailable", Detail: "The latest current observation reports this device unavailable.", Level: "problem", Current: true})
		default:
			events = append(events, Event{At: reportedAt[device.ID], Kind: "observation", Subject: device.ID,
				To: "unknown", Detail: "No current availability observation is available.", Level: "problem", Current: true})
		}
		if device.Enrollment != "" && device.Enrollment != "completed" {
			events = append(events, Event{At: now.UTC().Format(time.RFC3339), Kind: "enrollment", Subject: device.ID,
				To: device.Enrollment, Detail: "Enrollment is currently " + device.Enrollment + ".", Level: "pending", Current: true})
		}
	}
	sort.Slice(events, func(i, j int) bool {
		left := events[i].At + "\x00" + events[i].Kind + "\x00" + events[i].Subject + "\x00" + events[i].Detail
		right := events[j].At + "\x00" + events[j].Kind + "\x00" + events[j].Subject + "\x00" + events[j].Detail
		return left < right
	})
	return events
}

func projectReportHistory(reports []DeviceReport) []Event {
	states := map[string]string{}
	events := []Event{}
	emit := func(report DeviceReport, kind, key, value, detail string) {
		stateKey := report.DeviceID + "\x00" + kind + "\x00" + key
		previous, found := states[stateKey]
		if found && previous == value {
			return
		}
		states[stateKey] = value
		events = append(events, Event{At: report.ReportedAt, Kind: kind, Subject: report.DeviceID,
			From: previous, To: value, Detail: detail, Level: "information"})
	}
	for _, report := range reports {
		if report.Runtime != nil {
			value := report.Runtime.State + "\x00" + report.Runtime.AppliedViewDigest + "\x00" + report.Runtime.ErrorCode
			detail := "Runtime reported " + report.Runtime.State + "."
			if report.Runtime.ErrorCode != "" {
				detail = "Runtime reported " + report.Runtime.State + " with error code " + report.Runtime.ErrorCode + "."
			}
			emit(report, "runtime", "runtime", value, detail)
		}
		if report.Selection != "" {
			emit(report, "path", "legacy-selection", report.Selection, "Selected path "+report.Selection+".")
		}
		for _, selection := range report.Selections {
			emit(report, "path", "selection:"+selection.Scope, selection.CandidateID,
				"Selected path "+selection.CandidateID+" for "+selection.Scope+".")
		}
		for _, observation := range report.Observations {
			emit(report, "observation", "candidate:"+observation.CandidateID, observation.Result,
				"Path "+observation.CandidateID+" reported "+observation.Result+".")
		}
		for _, component := range report.Components {
			value := component.Version + "\x00" + component.Digest
			detail := "Component " + component.Name + " reported version " + component.Version
			if component.Digest != "" {
				detail += " (" + component.Digest + ")"
			}
			emit(report, "component", "component:"+component.Name, value, detail+".")
		}
		for _, link := range report.Links {
			detail := "Link " + link.LinkID + " reported " + link.Result
			if link.LatencyMS > 0 {
				detail += fmt.Sprintf(" at %d ms", link.LatencyMS)
			}
			emit(report, "link", "link:"+link.LinkID, link.Result, detail+".")
		}
		if report.Deployment != nil {
			value := fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%t", report.Deployment.Generation,
				report.Deployment.PayloadSHA256, report.Deployment.SelectedSnapshot,
				report.Deployment.AppliedSnapshot, report.Deployment.RolloutVerified)
			status := "pending"
			if report.Deployment.RolloutVerified && report.Deployment.SelectedSnapshot == report.Deployment.AppliedSnapshot {
				status = "verified"
			}
			detail := fmt.Sprintf("Deployment generation %d reported %s", report.Deployment.Generation, status)
			if version := strings.TrimSpace(report.Deployment.Version); version != "" {
				detail += " for version " + version
			}
			emit(report, "deployment", "deployment", value, detail+".")
		}
	}
	return events
}

type webDeviceReport struct {
	Schema       int                 `json:"schema"`
	DeviceID     string              `json:"device_id"`
	ViewDigest   string              `json:"view_digest"`
	Selection    string              `json:"selection,omitempty"`
	ReportedAt   string              `json:"reported_at"`
	Observations []Observation       `json:"observations"`
	Selections   []ReportSelection   `json:"selections,omitempty"`
	Runtime      *RuntimeReadback    `json:"runtime,omitempty"`
	Components   []ComponentReadback `json:"components,omitempty"`
	Links        []LinkReadback      `json:"links,omitempty"`
	Deployment   *DeploymentReadback `json:"deployment,omitempty"`
}

func projectWebReports(reports []DeviceReport) []webDeviceReport {
	result := make([]webDeviceReport, 0, len(reports))
	for _, report := range reports {
		copy := webDeviceReport{Schema: report.Schema, DeviceID: report.DeviceID, ViewDigest: report.ViewDigest,
			Selection: report.Selection, ReportedAt: report.ReportedAt, Observations: report.Observations,
			Selections: report.Selections, Components: report.Components, Links: report.Links, Deployment: report.Deployment}
		if report.Runtime != nil {
			runtime := *report.Runtime
			copy.Runtime = &runtime
		}
		result = append(result, copy)
	}
	return result
}

func restoreReservedDeviceCollisions(web *WebProjection, authority Projection, initial WebProjection) []string {
	if web == nil {
		return nil
	}
	reserved := map[string]bool{}
	for _, member := range uniqueConfigMembers(authority.Config) {
		reserved[member.ID] = true
		reserved[member.Node] = true
	}
	initialDevices := map[string]Device{}
	for _, device := range initial.Devices {
		initialDevices[device.ID] = device
	}
	authorized := map[string]bool{}
	for _, authorization := range authority.DeviceAuthorizations {
		authorized[authorization.DeviceID] = true
	}
	warnings := []string{}
	for index, device := range web.Devices {
		original, found := initialDevices[device.ID]
		if device.EnrollmentID == "" || !reserved[device.ID] || !found {
			continue
		}
		web.Devices[index] = original
		if authorized[device.ID] {
			warnings = append(warnings, "A device enrollment conflicts with the existing node identity "+device.ID+"; revoke that device authorization.")
		}
	}
	filtered := web.Paths[:0]
	for _, path := range web.Paths {
		device := initialDevices[path.Device]
		if reserved[path.Device] && device.ID != "" {
			continue
		}
		filtered = append(filtered, path)
	}
	web.Paths = filtered
	sort.Strings(warnings)
	return warnings
}

func hideRevokedDevices(web *WebProjection) {
	if web == nil {
		return
	}
	visible := web.Devices[:0]
	for _, device := range web.Devices {
		if device.Enrollment == "completed" && !device.Authorized {
			continue
		}
		visible = append(visible, device)
	}
	web.Devices = visible
	paths := web.Paths[:0]
	for _, path := range web.Paths {
		if index := sort.Search(len(web.Devices), func(index int) bool { return web.Devices[index].ID >= path.Device }); index < len(web.Devices) && web.Devices[index].ID == path.Device {
			paths = append(paths, path)
		}
	}
	web.Paths = paths
}
