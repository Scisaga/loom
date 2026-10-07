package control

import (
	"context"
	"testing"
	"time"
)

func TestControlMemberRetryRecoversOriginalVoteAfterRestart(t *testing.T) {
	f := newMaterialFixture(t)
	peers := membershipTLSPeers(t, f)
	a, b := peers[0].server.Runtime, peers[1].server.Runtime
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first, err := a.Authority.BeginControlRound(ctx, a.Config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Authority.PrepareControl(ctx, f.configID, first.Round, b.Config)
	if err != nil {
		t.Fatal(err)
	}
	promises := []ControlPromise{first, second}
	proposal := emptyRemoval(f, promises, 1)
	if _, err = a.Authority.VoteControl(ctx, proposal, first.Round, promises, a.Config, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Lose the initiator's entire in-memory authority before a majority forms.
	a.Authority, err = OpenAuthority(a.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	a.Channel.AttachAuthority(a.Authority)
	if err = a.ReconcileControlChanges(ctx, time.Now()); err != nil {
		t.Fatal("durable own vote did not resume through real peer TLS", err)
	}
	proof, err := a.Authority.ControlProof()
	if err != nil || len(proof.Successors) != 1 || proof.Successors[0].Config.Operation != "revoke" || proof.Successors[0].Round.Counter <= first.Round.Counter {
		t.Fatal("retry did not form the intended later-round decision", err)
	}
	before := len(proof.Successors)
	if err = a.ReconcileControlChanges(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	proof, _ = a.Authority.ControlProof()
	if len(proof.Successors) != before {
		t.Fatal("retry replayed a completed decision")
	}
}

func TestControlMemberRetryExpiresBoundTransactionWithoutOrdinaryTermination(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t, func(invite *Invite) {
		invite.DeviceID, invite.Medium = "demo-bound-member", "sh"
		invite.Responsibilities, invite.PolicyIDs = []string{"control"}, []string{}
	})
	if _, err := server.Runtime.Authority.CompleteEnrollment(context.Background(), claim, false, enrollmentTunnel(invite), server.now(), server.Config); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	server.Runtime.Authority = a
	if err = server.Runtime.ReconcileControlChanges(context.Background(), time.UnixMilli(invite.ExpiresAt)); err != nil {
		t.Fatal(err)
	}
	state, err := a.EnrollmentState(invite.ID)
	proof, _ := a.ControlProof()
	if err != nil || state != "expired" || len(proof.Successors) != 1 || proof.Successors[0].Config.Operation != "invalidate_join" {
		t.Fatal("bound expiry bypassed the member certificate", err)
	}
	for _, material := range a.materials {
		if material.Operation == "invite.expire" {
			t.Fatal("bound expiry manufactured ordinary termination")
		}
	}
}
