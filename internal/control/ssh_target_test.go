package control

import (
	"bytes"
	"testing"
)

func TestSSHTargetPreservesExistingInvitationBytes(t *testing.T) {
	server, invite, _, _, _, _ := enrollmentAuthorityFixture(t, func(v *Invite) {
		v.Responsibilities = []string{"access", "forward"}
		v.Medium = "ssh"
	})
	original, err := server.Runtime.Authority.Invite(invite.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := EncodeMaterial(original)
	if err != nil || bytes.Contains(body, []byte("ssh_target")) {
		t.Fatal("historical invitation gained target metadata", err)
	}
	decoded, err := DecodeMaterial(body)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := EncodeMaterial(decoded)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("existing authenticated invitation bytes changed", err)
	}
	invite.SSHTarget = "demo-target"
	next := original
	next.Payload = invite
	key, err := server.Config.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	next, err = SignMaterial(next, key)
	if err != nil {
		t.Fatal(err)
	}
	nextBody, _, err := EncodeMaterial(next)
	if err != nil || bytes.Equal(nextBody, body) {
		t.Fatal("new target is not covered by the signature", err)
	}
	read, err := DecodeMaterial(nextBody)
	if err != nil || read.Payload.(Invite).SSHTarget != invite.SSHTarget {
		t.Fatal("target was lost in canonical signed round trip", err)
	}
	for _, target := range []string{"-oProxyCommand=demo", "demo@host", "demo;true", "demo/host", " demo", "演示"} {
		invite.SSHTarget = target
		if invite.Validate() == nil {
			t.Fatal("accepted SSH option, command, address, or noncanonical alias")
		}
	}
	invite.SSHTarget, invite.Medium = "demo-target", "sh"
	if invite.Validate() == nil {
		t.Fatal("shell delivery acquired an SSH execution target")
	}
}
