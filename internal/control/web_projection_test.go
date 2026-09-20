package control

import (
	"strings"
	"testing"
	"time"
)

func TestReservedEnrollmentCannotReplaceImportedNodeInWebProjection(t *testing.T) {
	initial := WebProjection{Schema: 1, Devices: []Device{{ID: "demo-node", Name: "Demo server",
		Roles: []string{"server"}, Authorized: true, Availability: "unknown"}}}
	authority := Projection{Schema: 1, Config: ControlConfig{Mode: "stable", Quorum: 1,
		Members: []Member{{ID: "demo-control", Node: "demo-node"}}},
		DeviceAuthorizations: []DeviceAuthorization{{DeviceID: "demo-node"}}}
	web := WebProjection{Schema: 1, Devices: []Device{{ID: "demo-node", Name: "Phone", Platform: "android",
		Roles: []string{"access"}, Authorized: true, EnrollmentID: "demo-enrollment", Enrollment: "completed"}},
		Paths: []Path{{Device: "demo-node", CandidateID: "demo-path"}}}
	warnings := restoreReservedDeviceCollisions(&web, authority, initial)
	if len(web.Devices) != 1 || web.Devices[0].Name != "Demo server" || len(web.Paths) != 0 {
		t.Fatalf("reserved node identity was not restored: %+v paths=%+v", web.Devices, web.Paths)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "revoke") {
		t.Fatalf("active conflicting authorization was not exposed: %v", warnings)
	}

	authority.DeviceAuthorizations = nil
	web.Devices[0] = Device{ID: "demo-node", EnrollmentID: "demo-enrollment"}
	if warnings := restoreReservedDeviceCollisions(&web, authority, initial); len(warnings) != 0 || web.Devices[0].Name != "Demo server" {
		t.Fatalf("revoked collision did not settle on imported node: warnings=%v device=%+v", warnings, web.Devices[0])
	}
}

func TestCurrentEventsExposeUnknownAndUnavailableWithoutInventingHealth(t *testing.T) {
	projection := WebProjection{Schema: 1, Devices: []Device{
		{ID: "demo-a", Availability: "unknown"},
		{ID: "demo-b", Availability: "unavailable", Enrollment: "bound"},
		{ID: "demo-c", Availability: "available"},
	}}
	reports := []DeviceReport{{DeviceID: "demo-b", ReportedAt: "2030-01-01T00:00:00Z"}}
	events := projectCurrentEvents(projection, reports, time.Unix(100, 0))
	if len(events) != 3 {
		t.Fatalf("events=%+v", events)
	}
	for _, event := range events {
		if event.Subject == "demo-c" {
			t.Fatalf("healthy state was invented as an event: %+v", event)
		}
	}
}
