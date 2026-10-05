package control

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
)

type demoSSHDelivery struct{ run func(string) ([]byte, error) }

func (demoSSHDelivery) Targets() ([]string, error) { return []string{"demo-target"}, nil }
func (demoSSHDelivery) Resolve(_ context.Context, target string) (SSHTargetReadback, error) {
	return SSHTargetReadback{Alias: target, ResolvedHost: "demo-target.example", ResolvedPort: 2222}, nil
}
func (value demoSSHDelivery) Run(_ context.Context, _ string, script string) ([]byte, error) {
	return value.run(script)
}

func TestSSHFinalReadbackFailurePreservesInstalledIdentityAndOriginalRetry(t *testing.T) {
	server, invite, id, claim, key, _ := enrollmentAuthorityFixture(t, func(v *Invite) {
		v.Medium = "ssh"
		v.SSHTarget = "demo-target"
		v.Responsibilities = []string{"access", "forward"}
	})
	bootstrap, err := server.bootstrapInvite(invite.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := EncodeInvite(bootstrap)
	identity := DeviceIdentityReadback{NetworkID: claim.NetworkID, GenesisDigest: claim.GenesisDigest, DeviceID: invite.DeviceID, TransactionID: invite.ID, InviteMaterialID: id, ClaimRequestID: claim.RequestID, DevicePublicKey: claim.DevicePublicKey, Platform: "linux"}
	checks, installs := 0, 0
	server.SSH = demoSSHDelivery{run: func(script string) ([]byte, error) {
		if strings.Contains(script, " --inspect\n") {
			checks++
			if checks == 2 {
				return nil, errors.New("target could not download the final inspection package")
			}
			body, err := CanonicalEncode(InstallationReadback{Platform: "linux", Architecture: "amd64", CanInstall: true, Identity: &identity})
			return append(body, '\n'), err
		}
		if strings.Count(script, encoded) != 1 {
			t.Fatal("installation replaced or duplicated the original invitation")
		}
		if identity.Joined {
			resume := EnrollmentResumeRequest(claim)
			resume.Signature = ""
			resume, err = SignEnrollmentResume(resume, key)
			if err != nil {
				t.Fatal(err)
			}
			if response := enrollmentHTTP(t, server, "/enrollment/resume", resume, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code != http.StatusOK {
				t.Fatal("authenticated original resume failed")
			}
		} else if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
			t.Fatal("original claim failed")
		}
		identity.Joined = true
		installs++
		return []byte("installer returned successfully\n"), nil
	}}
	artifact := ReleaseArtifact{Name: "loom-bootstrap-linux.sh", Digest: ReleaseDigest([]byte("demo installer")), Size: 14, MediaType: "text/x-shellscript", Audience: "public"}
	value, err := server.installSSH(context.Background(), bootstrap, []string{"https://downloads.example/"}, artifact)
	if err == nil || value.State != "unknown" || value.Inspection == nil || value.Inspection.Installation.Identity == nil || value.Inspection.Installation.Identity.Joined {
		t.Fatal("failed final readback erased the last inspection or claimed installation failure")
	}
	state, err := server.Runtime.Authority.EnrollmentState(invite.ID)
	if err != nil || state != "completed" {
		t.Fatal("observation failure changed durable enrollment")
	}
	before := server.Runtime.Authority.Frontier()[0]
	value, err = server.installSSH(context.Background(), bootstrap, []string{"https://downloads.example/"}, artifact)
	if err != nil || value.State != "succeeded" || value.Inspection == nil || !value.Inspection.Installation.Identity.Joined || installs != 2 {
		t.Fatal("same-identity retry did not recover", err)
	}
	if server.Runtime.Authority.Frontier()[0] != before {
		t.Fatal("same invitation retry signed another identity or authorization")
	}
}

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
