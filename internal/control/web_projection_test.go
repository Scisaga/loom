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

func TestWebCapabilitiesSeparateCredentialFromQuorumWriteAvailability(t *testing.T) {
	head := GovernanceHead{Index: 1}
	intent := testNetworkIntent(t)
	authority := Projection{NetworkIntent: &intent}
	readonly := buildWebSnapshot(WebProjection{}, authority, head, true, false, false)
	if readonly.Capabilities.Credential != "admin" || !readonly.Capabilities.Admin || len(readonly.Capabilities.Operations) != 0 || readonly.UIState.QuorumWritable {
		t.Fatalf("admin credential was confused with quorum write availability: %+v", readonly)
	}
	writable := buildWebSnapshot(WebProjection{}, authority, head, true, false, true)
	if writable.Capabilities.Credential != "admin" || len(writable.Capabilities.Operations) == 0 || !writable.UIState.QuorumWritable {
		t.Fatalf("writable admin capabilities are incomplete: %+v", writable)
	}
}

func TestCurrentEventsExposeUnknownAndUnavailableWithoutInventingHealth(t *testing.T) {
	projection := WebProjection{Schema: 1, Devices: []Device{
		{ID: "demo-a", Availability: "unknown"},
		{ID: "demo-b", Availability: "unavailable", Enrollment: "bound"},
		{ID: "demo-c", Availability: "available"},
	}}
	reports := []DeviceReport{{DeviceID: "demo-b", ReportedAt: "2030-01-01T00:00:00Z"}}
	events := projectCurrentEvents(projection, reports, nil, time.Unix(100, 0))
	if len(events) != 3 {
		t.Fatalf("events=%+v", events)
	}
	for _, event := range events {
		if event.Subject == "demo-c" {
			t.Fatalf("healthy state was invented as an event: %+v", event)
		}
	}
}

func TestReportHistoryProjectsOnlySignedStateTransitions(t *testing.T) {
	history := []DeviceReport{
		{DeviceID: "demo-a", ReportedAt: "2030-01-01T00:00:00Z", Runtime: &RuntimeReadback{State: "running", AppliedViewDigest: "sha256:" + strings.Repeat("1", 64)},
			Selections:   []ReportSelection{{Scope: "default", CandidateID: "demo-direct"}},
			Observations: []Observation{{CandidateID: "demo-direct", Result: "available"}}},
		{DeviceID: "demo-a", ReportedAt: "2030-01-01T00:01:00Z", Runtime: &RuntimeReadback{State: "running", AppliedViewDigest: "sha256:" + strings.Repeat("1", 64)},
			Selections:   []ReportSelection{{Scope: "default", CandidateID: "demo-direct"}},
			Observations: []Observation{{CandidateID: "demo-direct", Result: "available"}}},
		{DeviceID: "demo-a", ReportedAt: "2030-01-01T00:02:00Z", Runtime: &RuntimeReadback{State: "error", AppliedViewDigest: "sha256:" + strings.Repeat("1", 64), ErrorCode: "preflight_failed"},
			Selections:   []ReportSelection{{Scope: "default", CandidateID: "demo-egress"}},
			Observations: []Observation{{CandidateID: "demo-egress", Result: "unavailable"}}},
	}
	events := projectReportHistory(history)
	if len(events) != 6 {
		t.Fatalf("events=%+v", events)
	}
	for _, event := range events {
		if event.At == "2030-01-01T00:01:00Z" {
			t.Fatalf("unchanged report produced a history event: %+v", event)
		}
	}
}

func TestWebReportProjectionOmitsSignatureAndKeepsOnlyBoundedErrorCode(t *testing.T) {
	reports := projectWebReports([]DeviceReport{{DeviceID: "demo-a", Signature: "secret-signature",
		Runtime: &RuntimeReadback{State: "error", ErrorCode: "preflight_failed"}}})
	if len(reports) != 1 || reports[0].Runtime == nil || reports[0].Runtime.ErrorCode != "preflight_failed" {
		t.Fatalf("bounded runtime error code was not projected: %+v", reports)
	}
}

func TestRevokedCompletedDeviceIsNotCurrentInventory(t *testing.T) {
	projection := WebProjection{Schema: 1, Devices: []Device{
		{ID: "demo-active", Enrollment: "completed", Authorized: true},
		{ID: "demo-pending", Enrollment: "bound", Authorized: false},
		{ID: "demo-revoked", Enrollment: "completed", Authorized: false},
	}, Paths: []Path{{Device: "demo-active"}, {Device: "demo-revoked"}}}
	hideRevokedDevices(&projection)
	if len(projection.Devices) != 2 || projection.Devices[0].ID != "demo-active" || projection.Devices[1].ID != "demo-pending" {
		t.Fatalf("visible devices=%+v", projection.Devices)
	}
	if len(projection.Paths) != 1 || projection.Paths[0].Device != "demo-active" {
		t.Fatalf("visible paths=%+v", projection.Paths)
	}
}
