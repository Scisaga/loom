package ssotedit

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"loom/internal/model"
)

func TestAccessPausePreservesIdentityAndGrants(t *testing.T) {
	plan, id := enrolledAccessDevice(t)
	before := loadResult(t, plan.Content)
	paused, err := SetAccessDevicePaused(plan.Content, id, true)
	if err != nil {
		t.Fatal(err)
	}
	got := loadResult(t, paused)
	if !got.NodeByID()[id].Paused || !reflect.DeepEqual(before.Credentials, got.Credentials) ||
		!reflect.DeepEqual(before.NodeByID()[id].Access, got.NodeByID()[id].Access) {
		t.Fatal("pause changed identity or grants")
	}
	repeated, err := SetAccessDevicePaused(paused, id, true)
	if err != nil || !bytes.Equal(paused, repeated) {
		t.Fatalf("pause is not idempotent: %v", err)
	}
	resumed, err := SetAccessDevicePaused(paused, id, false)
	if err != nil || !reflect.DeepEqual(before, loadResult(t, resumed)) {
		t.Fatalf("resume did not restore original desired state: %v", err)
	}
	if _, err := SetAccessDevicePaused(plan.Content, "cn-bj", true); err == nil {
		t.Fatal("server was allowed to pause")
	}
	stopped, err := DecommissionAccessDevice(paused, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SetAccessDevicePaused(stopped, id, false); err == nil {
		t.Fatal("resume reactivated a decommissioned device")
	}
}

func enrolledAccessDevice(t *testing.T) (ClientPlan, string) {
	t.Helper()
	content := append([]byte("# keep lifecycle comment\n"), fixtureSSOT(t)...)
	plan, err := AddAccessClient(content, ClientInput{
		ID: "d-canary01", Name: "Disposable canary", Platform: model.LinuxServer,
		DestinationGrants: []string{"best-egress"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan, "d-canary01"
}

func TestAccessOnlyEnrollmentDeviceCanDecommissionThenRemove(t *testing.T) {
	plan, id := enrolledAccessDevice(t)
	decommissioned, err := DecommissionAccessDevice(plan.Content, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(decommissioned, []byte("# keep lifecycle comment")) {
		t.Fatal("decommission edit lost unrelated comments")
	}
	node := loadResult(t, decommissioned).NodeByID()[id]
	if node == nil || !node.Decommission {
		t.Fatalf("decommissioned Device = %#v", node)
	}
	repeated, err := DecommissionAccessDevice(decommissioned, id)
	if err != nil || !sameDocument(repeated, decommissioned) {
		t.Fatalf("repeat decommission changed content: err=%v", err)
	}

	removed, err := RemoveDecommissionedAccessDevice(decommissioned, id)
	if err != nil {
		t.Fatal(err)
	}
	ssot := loadResult(t, removed.Content)
	if ssot.NodeByID()[id] != nil {
		t.Fatal("removed Device remains in SSOT")
	}
	for _, credentialID := range plan.CredentialIDs {
		if ssot.CredentialByID()[credentialID] != nil {
			t.Fatalf("removed credential %q remains in SSOT", credentialID)
		}
	}
	if !slices.Equal(removed.CredentialIDs, plan.CredentialIDs) ||
		!slices.Equal(removed.SecretRefs, plan.CredentialRefs) {
		t.Fatalf("removal plan ids=%v refs=%v, want ids=%v refs=%v", removed.CredentialIDs, removed.SecretRefs, plan.CredentialIDs, plan.CredentialRefs)
	}
}

func TestAccessDeviceRemovalRequiresDecommissionAndGeneratedShape(t *testing.T) {
	plan, id := enrolledAccessDevice(t)
	if _, err := RemoveDecommissionedAccessDevice(plan.Content, id); err == nil ||
		!strings.Contains(err.Error(), "decommission") {
		t.Fatalf("remove active Device error = %v", err)
	}

	tampered := bytes.Replace(plan.Content,
		[]byte("owner: d-canary01"), []byte("owner: workstation"), 1)
	if _, err := DecommissionAccessDevice(tampered, id); err == nil {
		t.Fatal("decommission accepted a non-generated credential shape")
	}
}

func TestAccessCleanupRefusesServerOrTopologyChanges(t *testing.T) {
	base := fixtureSSOT(t)
	if _, err := DecommissionAccessDevice(base, "cn-bj"); err == nil ||
		!strings.Contains(err.Error(), "not access-only") {
		t.Fatalf("server Device error = %v", err)
	}

	plan, id := enrolledAccessDevice(t)
	withTunnel := bytes.Replace(plan.Content, []byte("tunnels:\n"), []byte("tunnels:\n  - {from: d-canary01, to: cn-bj, protocol: wireguard, secret_ref: tunnel/canary}\n"), 1)
	if _, err := DecommissionAccessDevice(withTunnel, id); err == nil {
		t.Fatal("access cleanup accepted a Device with topology links")
	}
}
