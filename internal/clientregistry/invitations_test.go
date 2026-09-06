package clientregistry

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewInvitationInvalidatesOldCodeAndPreservesReservation(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Hour} {
		t.Run(delay.String(), func(t *testing.T) {
			now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
			store := testStore(t, &now)
			first, err := store.Create("demo workstation", testAccessIntent("windows-desktop"))
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(delay)
			renewed, err := store.RenewInvitation(first.Client.ID)
			if err != nil {
				t.Fatal(err)
			}
			if renewed.Client.ID != first.Client.ID || renewed.Token == first.Token || renewed.Invite.ID == first.Invite.ID {
				t.Fatal("renewal did not preserve the Device with a fresh invitation")
			}
			clients, _, err := store.List()
			if err != nil || len(clients) != 1 || clients[0].Status != "pending" {
				t.Fatalf("renewed inventory=%+v err=%v", clients, err)
			}
			if _, _, err := store.Artifact(first.Invite.ID); err == nil {
				t.Fatal("old QR remains readable")
			}
			claim := ClaimInput{Token: first.Token, Platform: "windows-desktop", CSRPEM: makeCSR(t, "demo-client"), RequestID: "demo-request"}
			if _, err := store.Claim(claim); err == nil {
				t.Fatal("old token remained valid")
			}
			claim.Token = renewed.Token
			if _, err := store.Claim(claim); err != nil {
				t.Fatal(err)
			}
			if _, err := store.RenewInvitation(first.Client.ID); err == nil {
				t.Fatal("renewal overwrote a claimed identity")
			}
		})
	}
}

func TestReplacementRetiresAccessBeforeIssuingOneNewIdentity(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	first, err := store.Create("demo workstation", EnrollmentIntent{
		Platform: "windows-desktop", Responsibilities: []string{"use_loom"}, DestinationGrants: []string{"demo-policy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claim := ClaimInput{Token: first.Token, Platform: "windows-desktop", CSRPEM: makeCSR(t, "demo-client"), RequestID: "demo-request"}
	claimed, err := store.Claim(claim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkReady(first.Client.ID); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := store.ReplaceWithInvitation(first.Client.ID, func(Client) error { return errors.New("retirement failed") })
	if err == nil || failed.Token != "" {
		t.Fatal("failed retirement issued a replacement")
	}
	after, err := os.ReadFile(store.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed retirement changed registry")
	}
	var retired atomic.Int32
	var workers sync.WaitGroup
	results := make(chan CreateResult, 8)
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			next, err := store.ReplaceWithInvitation(first.Client.ID, func(Client) error { retired.Add(1); return nil })
			if err == nil {
				results <- next
			}
		}()
	}
	workers.Wait()
	close(results)
	if retired.Load() != 1 || len(results) != 1 {
		t.Fatalf("concurrent replacement retired=%d results=%d", retired.Load(), len(results))
	}
	next := <-results
	if next.Client.ID == first.Client.ID || next.Client.Name != first.Client.Name ||
		strings.Join(next.Client.Responsibilities, ",") != strings.Join(first.Client.Responsibilities, ",") ||
		strings.Join(next.Client.DestinationGrants, ",") != strings.Join(first.Client.DestinationGrants, ",") ||
		next.Client.Replaces != first.Client.ID {
		t.Fatalf("replacement=%+v", next.Client)
	}
	if err := store.CheckClaimedIdentity(first.Client.ID, claimed.Client.PublicKey); err == nil {
		t.Fatal("revoked identity may still provision")
	}
	if _, err := store.Claim(claim); err == nil {
		t.Fatal("old claim replay survived replacement")
	}
	claim.Token = next.Token
	if _, err := store.Claim(claim); err == nil {
		t.Fatal("replacement reused old public identity")
	}
	claim.CSRPEM = makeCSR(t, "demo-replacement")
	if _, err := store.Claim(claim); err != nil {
		t.Fatal(err)
	}
	clients, _, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range clients {
		if client.ID == first.Client.ID && (client.Status != "revoked" || client.ReplacedBy != next.Client.ID) {
			t.Fatalf("old identity=%+v", client)
		}
	}
}
