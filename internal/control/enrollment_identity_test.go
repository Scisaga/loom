package control

import (
	"strings"
	"testing"
)

func enrollmentOpenForID(id string) EnrollmentOpen {
	return EnrollmentOpen{
		TransactionID: "enroll-" + id,
		Intent: EnrollmentIntent{DeviceID: id, Name: "New device", Platform: "linux",
			Roles: []string{"access"}, Routes: []RouteCandidate{}},
		Capability: BootstrapCapability{Schema: 1},
	}
}

func TestEnrollmentRejectsRecoveredDeviceIDCollision(t *testing.T) {
	projection := Projection{Schema: 1, Web: WebProjection{Schema: 1,
		Devices: []Device{{ID: "demo-node", Name: "Existing server", Roles: []string{"server"}, Authorized: true}}}}
	err := validateNewEnrollmentIdentity(projection, "demo-node")
	if err == nil || !strings.Contains(err.Error(), "certified projection") {
		t.Fatalf("recovered device identity was overwritten: %v", err)
	}
}

func TestEnrollmentRejectsControlMemberIDCollision(t *testing.T) {
	projection := Projection{Schema: 1, Config: ControlConfig{Mode: "stable", Quorum: 1,
		Members: []Member{{ID: "control-a", Node: "demo-node"}}},
		Web: WebProjection{Schema: 1, Devices: []Device{}}}
	for _, id := range []string{"control-a", "demo-node"} {
		copy := projection
		err := validateNewEnrollmentIdentity(copy, id)
		if err == nil || !strings.Contains(err.Error(), "control configuration") {
			t.Fatalf("control identity %q was accepted: %v", id, err)
		}
	}
}

func TestEnrollmentAcceptsUnusedStableID(t *testing.T) {
	projection := Projection{Schema: 1, Config: ControlConfig{Mode: "stable", Quorum: 1,
		Members: []Member{{ID: "control-a", Node: "demo-node"}}},
		Web: WebProjection{Schema: 1, Devices: []Device{{ID: "existing"}}}}
	if err := validateNewEnrollmentIdentity(projection, "new-device"); err != nil {
		t.Fatalf("unused device identity was rejected: %v", err)
	}
}

func TestCommittedEnrollmentCollisionStillReplays(t *testing.T) {
	projection := Projection{Schema: 1, Web: WebProjection{Schema: 1,
		Devices: []Device{{ID: "demo-node", Name: "Existing server", Roles: []string{"server"}, Authorized: true}}}}
	if err := reduceEnrollmentOpen(&projection, enrollmentOpenForID("demo-node")); err != nil {
		t.Fatalf("previously committed enrollment no longer replays: %v", err)
	}
}

func TestExistingNodeMayRejoinAfterCompletedAuthorizationWasRevoked(t *testing.T) {
	projection := Projection{Schema: 1, Enrollments: []EnrollmentTransaction{{Schema: 1, ID: "old-enrollment", State: "completed",
		Intent: EnrollmentIntent{DeviceID: "demo-node"}}}}
	if err := reduceEnrollmentOpen(&projection, enrollmentOpenForID("demo-node")); err != nil {
		t.Fatalf("completed enrollment history blocked a rejoin after revocation: %v", err)
	}
	if len(projection.Enrollments) != 2 {
		t.Fatalf("completed enrollment history was not retained: %+v", projection.Enrollments)
	}
}

func TestExistingNodeRejoinStillRejectsActiveEnrollmentOrAuthorization(t *testing.T) {
	for _, state := range []string{"open", "bound", "approved"} {
		projection := Projection{Schema: 1, Enrollments: []EnrollmentTransaction{{Schema: 1, ID: "old-enrollment", State: state,
			Intent: EnrollmentIntent{DeviceID: "demo-node"}}}}
		if err := reduceEnrollmentOpen(&projection, enrollmentOpenForID("demo-node")); err == nil {
			t.Fatalf("active %s enrollment did not block a second transaction", state)
		}
	}
	projection := Projection{Schema: 1,
		DeviceAuthorizations: []DeviceAuthorization{{Schema: 2, DeviceID: "demo-node"}},
		Enrollments: []EnrollmentTransaction{{Schema: 1, ID: "old-enrollment", State: "completed",
			Intent: EnrollmentIntent{DeviceID: "demo-node"}}}}
	if err := reduceEnrollmentOpen(&projection, enrollmentOpenForID("demo-node")); err == nil ||
		!strings.Contains(err.Error(), "authorization") {
		t.Fatalf("current authorization did not block a second enrollment: %v", err)
	}
}
