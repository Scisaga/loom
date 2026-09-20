package control

import (
	"errors"
	"sort"
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

func projectCurrentEvents(projection WebProjection, reports []DeviceReport, now time.Time) []Event {
	events := append([]Event(nil), projection.Events...)
	reportedAt := map[string]string{}
	for _, report := range reports {
		reportedAt[report.DeviceID] = report.ReportedAt
	}
	for _, device := range projection.Devices {
		switch device.Availability {
		case "available":
		case "unavailable":
			events = append(events, Event{At: reportedAt[device.ID], Kind: "observation", Subject: device.ID,
				Detail: "The latest current observation reports this device unavailable."})
		default:
			events = append(events, Event{At: reportedAt[device.ID], Kind: "observation", Subject: device.ID,
				Detail: "No current availability observation is available."})
		}
		if device.Enrollment != "" && device.Enrollment != "completed" {
			events = append(events, Event{At: now.UTC().Format(time.RFC3339), Kind: "enrollment", Subject: device.ID,
				Detail: "Enrollment is currently " + device.Enrollment + "."})
		}
	}
	sort.Slice(events, func(i, j int) bool {
		left := events[i].At + "\x00" + events[i].Kind + "\x00" + events[i].Subject + "\x00" + events[i].Detail
		right := events[j].At + "\x00" + events[j].Kind + "\x00" + events[j].Subject + "\x00" + events[j].Detail
		return left < right
	})
	return events
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
