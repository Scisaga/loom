package control

import (
	"sort"
	"strconv"
	"time"
)

func projectWebDevices(projection Projection) []Device {
	byID := map[string]Device{}
	for _, member := range projection.Config.Members {
		byID[member.NodeID] = Device{ID: member.NodeID, Name: member.NodeID, Roles: []string{"control"}, Authorized: true, Availability: "unknown", PolicyIDs: []string{}, DistributionURLs: []string{}, Dependencies: []string{}, Presence: "unknown", RuntimeState: "unknown"}
	}
	for _, authorization := range projection.DeviceAuthorizations {
		device := byID[authorization.ID]
		device.ID, device.Name, device.Platform = authorization.ID, authorization.Name, authorization.Platform
		device.Roles = append(device.Roles, authorization.Responsibilities...)
		sort.Strings(device.Roles)
		device.Authorized, device.Availability, device.Enrollment = true, "unknown", "completed"
		device.EnrollmentID = authorization.TransactionID
		device.PolicyIDs = append([]string{}, authorization.PolicyIDs...)
		device.DistributionURLs = append([]string{}, authorization.DistributionURLs...)
		device.Presence, device.RuntimeState = "unknown", "unknown"
		byID[device.ID] = device
	}
	for _, invite := range projection.Invites {
		device, found := byID[invite.DeviceID]
		if !found {
			device = Device{ID: invite.DeviceID, Name: invite.Name, Roles: append([]string{}, invite.Responsibilities...), Availability: "unknown", PolicyIDs: append([]string{}, invite.PolicyIDs...), DistributionURLs: []string{}, Dependencies: []string{}, Presence: "unknown", RuntimeState: "unknown"}
		}
		if device.Enrollment == "completed" {
			continue
		}
		state, _ := projection.CurrentTarget("invite", invite.ID)
		device.EnrollmentID = invite.ID
		device.Enrollment = "open"
		for _, binding := range projection.Bindings {
			if binding.TransactionID == invite.ID {
				device.Enrollment = "bound"
				device.Platform = binding.Platform
			}
		}
		if state.Deleted {
			device.Enrollment = "terminated"
		}
		if state.Conflicted {
			device.Enrollment = "conflicted"
		}
		byID[device.ID] = device
	}
	for _, target := range projection.Targets {
		if target.TargetKind != "device" {
			continue
		}
		device, found := byID[target.TargetID]
		if !found {
			device = Device{ID: target.TargetID, Name: target.TargetID, Roles: []string{}, Availability: "unknown", PolicyIDs: []string{}, DistributionURLs: []string{}, Presence: "unknown", RuntimeState: "unknown"}
		}
		device.Dependencies = append([]string{}, target.MaterialIDs...)
		device.Conflicted, device.Deleted = target.Conflicted, target.Deleted
		if target.Conflicted || target.Deleted {
			device.Authorized = false
			device.Availability = "unknown"
			device.Enrollment = "revoked"
			if target.Conflicted {
				device.Enrollment = "conflicted"
			}
		}
		byID[device.ID] = device
	}
	devices := make([]Device, 0, len(byID))
	for _, device := range byID {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	return devices
}

func projectWebPaths(projection Projection) []Path {
	paths := []Path{}
	for _, device := range projection.DeviceAuthorizations {
		view, err := ProjectDeviceView(projection, device.ID)
		if err != nil {
			continue
		}
		for _, candidate := range view.Routes {
			paths = append(paths, Path{CandidateID: candidate.ID, Device: device.ID, Scope: candidate.Scope,
				FinalExit: candidate.FinalExit, Chain: append([]string{}, candidate.NodeChain...), Availability: "unknown"})
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		left, right := paths[i], paths[j]
		return left.Device+"\x00"+left.Scope+"\x00"+left.CandidateID < right.Device+"\x00"+right.Scope+"\x00"+right.CandidateID
	})
	return paths
}

func projectWebLinks(projection Projection) []Link {
	resources := map[string]TransportResource{}
	eligible := map[string]bool{}
	for _, device := range projection.DeviceAuthorizations {
		eligible[device.ID] = containsString(device.Responsibilities, "forward")
	}
	for _, resource := range projection.NetworkIntent.Resources {
		resources[resource.ID] = resource
	}
	result := []Link{}
	for _, link := range projection.NetworkIntent.Links {
		if !eligible[link.FromNodeID] || !eligible[link.ToNodeID] {
			continue
		}
		if _, _, _, err := linkResources(link, resources); err != nil {
			continue
		}
		result = append(result, Link{ID: link.ID, From: link.FromNodeID, To: link.ToNodeID, Transport: "wireguard", Authorized: true, Availability: "unknown"})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// The caller supplies reports already checked against the current signed view.
// Receipt is not a liveness proof; per-service observations are shown separately.
func projectWebObservations(snapshot *WebSnapshot, reports []DeviceReport, now time.Time) {
	for index := range snapshot.Devices {
		device := &snapshot.Devices[index]
		for _, report := range reports {
			if report.DeviceID != device.ID {
				continue
			}
			at := time.UnixMilli(report.ReportedAt)
			device.LastReportAt = at.UTC().Format(time.RFC3339Nano)
			device.Presence = "unknown"
			device.ViewDigest = report.ViewDigest
			device.RuntimeState = report.Runtime.State
			runtime := report.Runtime
			device.Evidence = &DeviceEvidence{ReportedAt: device.LastReportAt, ViewDigest: report.ViewDigest, Selections: append([]ReportSelection{}, report.Selections...), Runtime: &runtime, Components: append([]ComponentReadback{}, report.Components...), Measurements: append([]Observation{}, report.Observations...)}
			// A device may have different results for different services. Do not fold
			// one success or failure into a global device business-health assertion.
			for pathIndex := range snapshot.Paths {
				path := &snapshot.Paths[pathIndex]
				if path.Device != device.ID {
					continue
				}
				for _, selection := range report.Selections {
					if path.Scope == "service:"+selection.ServiceID && path.CandidateID == selection.CandidateID && report.Runtime.State == "running" && report.Runtime.AppliedViewDigest == report.ViewDigest {
						path.Selected = true
					}
				}
				// Multi-target reduction is not defined. Keep the individual
				// measurements above without choosing a winner by array order.
				var matching []Observation
				for _, observation := range report.Observations {
					if observation.Level == "service" && path.Scope == "service:"+observation.ServiceID && path.CandidateID == observation.CandidateID {
						matching = append(matching, observation)
					}
				}
				if len(matching) == 1 && matching[0].NetworkGeneration == report.NetworkGeneration && matching[0].ObservedAt <= now.UnixMilli() && now.UnixMilli() < matching[0].ValidUntil {
					path.Availability = matching[0].Result
				}
			}
		}
	}
}

func projectReportHistory(reports []DeviceReport) []Event {
	events := []Event{}
	for _, report := range reports {
		at := time.UnixMilli(report.ReportedAt).UTC().Format(time.RFC3339Nano)
		events = append(events, Event{ID: "report-" + report.DeviceID + "-" + strconv.FormatInt(report.ReportedAt, 10), At: at, Kind: "runtime", Subject: report.DeviceID, To: report.Runtime.State, Detail: "Authenticated runtime report: " + report.Runtime.State + ".", Level: "information"})
	}
	return events
}
