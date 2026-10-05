package control

import (
	"context"
	"net/http"
	"os"
	"testing"
)

func TestSSHResumeRequiresOriginalIdentityBindingAndAuthorization(t *testing.T) {
	server, invite, id, claim, _, _ := enrollmentAuthorityFixture(t, func(value *Invite) {
		value.Medium, value.SSHTarget = "ssh", "demo-target"
		value.Responsibilities = []string{"access", "forward"}
	})
	bootstrap, err := server.bootstrapInvite(invite.ID)
	if err != nil {
		t.Fatal(err)
	}
	inspection := InstallationReadback{Platform: "linux", Architecture: "amd64", CanInstall: true}
	if err := server.checkSSHIdentity(bootstrap, inspection); err != nil {
		t.Fatal("fresh target refused", err)
	}
	identity := DeviceIdentityReadback{NetworkID: claim.NetworkID, GenesisDigest: claim.GenesisDigest, DeviceID: invite.DeviceID, TransactionID: invite.ID, InviteMaterialID: id, ClaimRequestID: claim.RequestID, DevicePublicKey: claim.DevicePublicKey, Platform: "linux"}
	inspection.Identity = &identity
	if err := server.checkSSHIdentity(bootstrap, inspection); err != nil {
		t.Fatal("same unclaimed identity cannot resume", err)
	}
	for _, alter := range []func(*DeviceIdentityReadback){
		func(v *DeviceIdentityReadback) { v.NetworkID = "demo-other-network" },
		func(v *DeviceIdentityReadback) { v.DeviceID = "demo-other-device" },
		func(v *DeviceIdentityReadback) { v.TransactionID = "demo-other-transaction" },
		func(v *DeviceIdentityReadback) { v.InviteMaterialID = ReleaseDigest([]byte("demo other invite")) },
		func(v *DeviceIdentityReadback) { v.Platform = "windows" },
	} {
		other := identity
		alter(&other)
		inspection.Identity = &other
		if server.checkSSHIdentity(bootstrap, inspection) == nil {
			t.Fatal("different identity accepted")
		}
	}
	inspection.Identity = &identity
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("fixture enrollment failed")
	}
	if err := server.checkSSHIdentity(bootstrap, inspection); err != nil {
		t.Fatal("original durable identity rejected", err)
	}
	for _, alter := range []func(*DeviceIdentityReadback){
		func(v *DeviceIdentityReadback) { v.ClaimRequestID = "demo-other-request" },
		func(v *DeviceIdentityReadback) { v.DevicePublicKey = server.Config.ControlID },
	} {
		other := identity
		alter(&other)
		inspection.Identity = &other
		if server.checkSSHIdentity(bootstrap, inspection) == nil {
			t.Fatal("changed binding accepted")
		}
	}
	inspection.Identity = nil
	if server.checkSSHIdentity(bootstrap, inspection) == nil {
		t.Fatal("a missing bound identity may not be recreated")
	}
	inspection.Identity = &identity
	current, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-revoke-ssh", Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: current.MaterialIDs, Payload: DeleteTarget{ID: invite.DeviceID}})
	if server.checkSSHIdentity(bootstrap, inspection) == nil {
		t.Fatal("completed enrollment reauthorized a revoked device")
	}
}

func TestSSHAcceptedInvitationRetryDoesNotInspectOrRewrite(t *testing.T) {
	server, invite, id, _, _, _ := enrollmentAuthorityFixture(t, func(v *Invite) {
		v.Medium = "ssh"
		v.SSHTarget = "demo-host"
		v.Responsibilities = []string{"access", "forward"}
	})
	material, err := server.Runtime.Authority.Invite(invite.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := EncodeMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	operation := Operation{Schema: 3, RequestID: material.RequestID, Operation: material.Operation, TargetKind: material.TargetKind, TargetID: material.TargetID, Dependencies: material.Dependencies, Payload: invite}
	// No executor or ready endpoint is present: the original accepted request
	// must still return its original material after a lost HTTP response.
	result, extra, err := server.HandleOperation(context.Background(), operation)
	if err != nil || result.MaterialID != id || extra == nil || extra.Invite == "" {
		t.Fatal("accepted retry lost original delivery", err)
	}
	again, _ := server.Runtime.Authority.Invite(invite.ID)
	after, _, _ := EncodeMaterial(again)
	if string(before) != string(after) {
		t.Fatal("retry rewrote signed bytes")
	}
	operation.RequestID = "demo-new-ssh-request"
	operation.TargetID = "demo-new-transaction"
	invite.ID = operation.TargetID
	operation.Payload = invite
	if _, _, err = server.HandleOperation(context.Background(), operation); err == nil {
		t.Fatal("new SSH invitation bypassed preflight")
	}
	if _, _, err = server.Runtime.Authority.MaterialForRequest(operation.RequestID); !os.IsNotExist(err) {
		t.Fatal("failed preflight signed an invite")
	}
}
