package control

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestAutomaticInviteExpiryPersistsOnceAndReleasesOnlyUnboundID(t *testing.T) {
	server, invite, originalID, claim, _, _ := enrollmentAuthorityFixture(t)
	a := server.Runtime.Authority
	original, _ := a.Invite(invite.ID)
	deadline := time.UnixMilli(invite.ExpiresAt)
	if count, err := a.ExpireUnboundInvites(context.Background(), deadline.Add(-time.Millisecond), server.Config); err != nil || count != 0 {
		t.Fatal("invitation expired before its signed deadline", count, err)
	}
	other := server.Config
	other.ControlID = "demo-other-issuer"
	if count, err := a.ExpireUnboundInvites(context.Background(), deadline, other); err != nil || count != 0 {
		t.Fatal("another issuer terminated an invitation", count, err)
	}
	if count, err := a.ExpireUnboundInvites(context.Background(), deadline, server.Config); err != nil || count != 1 {
		t.Fatal("unclaimed invitation did not terminate", count, err)
	}
	state, err := a.EnrollmentState(invite.ID)
	id, material, requestErr := a.MaterialForRequest(enrollmentRequestID("expire", invite.ID))
	if err != nil || state != "expired" || requestErr != nil || material.Operation != "invite.expire" || !contains(material.Dependencies, originalID) {
		t.Fatal("expiration has no verifiable terminal fact", state, err, requestErr)
	}
	if material.Payload.(EnrollmentTermination).ExpiredAt == nil || *material.Payload.(EnrollmentTermination).ExpiredAt != invite.ExpiresAt {
		t.Fatal("expiration lost the injected deadline observation")
	}
	if unchanged, _ := a.Invite(invite.ID); !reflect.DeepEqual(unchanged, original) {
		t.Fatal("expiry rewrote the original invitation")
	}
	frontier := a.Frontier()
	reopened, err := OpenAuthority(a.root)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := reopened.ExpireUnboundInvites(context.Background(), deadline.Add(time.Hour), server.Config); err != nil || count != 0 || !reflect.DeepEqual(frontier, reopened.Frontier()) {
		t.Fatal("restart generated another expiration fact", count, err)
	}
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code == http.StatusOK || len(a.Snapshot().Bindings) != 0 {
		t.Fatal("expired invitation acquired an identity")
	}
	invite.ID, invite.ExpiresAt = "demo-replacement-invite", deadline.Add(time.Hour).UnixMilli()
	dependencies := sortedUniqueDependencies(append(append([]string{}, original.Dependencies...), id))
	if _, err := a.Submit(context.Background(), Operation{Schema: 3, RequestID: "demo-replacement-request", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: dependencies, Payload: invite}, server.Config); err != nil {
		t.Fatal("signed termination did not release the unbound device ID", err)
	}
}

func TestAutomaticInviteExpiryPreservesDurableBindingAndCompletion(t *testing.T) {
	for _, completed := range []bool{false, true} {
		name := "bound"
		if completed {
			name = "completed"
		}
		t.Run(name, func(t *testing.T) {
			server, invite, id, claim, _, dependencies := enrollmentAuthorityFixture(t)
			if completed {
				if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
					t.Fatal("ordinary join failed")
				}
			} else {
				binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: id, ClaimRequestID: claim.RequestID, DevicePublicKey: claim.DevicePublicKey, Platform: claim.Platform}
				submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: enrollmentRequestID("bind", invite.ID), Operation: "invite.bind", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(append(dependencies, id)), Payload: binding})
			}
			before := server.Runtime.Authority.Frontier()
			if count, err := server.Runtime.Authority.ExpireUnboundInvites(context.Background(), time.UnixMilli(invite.ExpiresAt).Add(time.Hour), server.Config); err != nil || count != 0 || !reflect.DeepEqual(before, server.Runtime.Authority.Frontier()) {
				t.Fatal("automatic expiry changed an existing identity", count, err)
			}
			if state, err := server.Runtime.Authority.EnrollmentState(invite.ID); err != nil || state != name {
				t.Fatal("existing enrollment state was changed", state, err)
			}
		})
	}
}

func TestAutomaticExpiryAndFirstClaimShareTheWriterLock(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	var expired int
	var expiryError, claimError error
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	go func() {
		defer done.Done()
		start.Wait()
		expired, expiryError = server.Runtime.Authority.ExpireUnboundInvites(context.Background(), time.UnixMilli(invite.ExpiresAt), server.Config)
	}()
	go func() {
		defer done.Done()
		start.Wait()
		_, claimError = server.Runtime.Authority.CompleteEnrollment(context.Background(), claim, false, enrollmentTunnel(invite), time.UnixMilli(invite.ExpiresAt).Add(-time.Millisecond), server.Config)
	}()
	start.Done()
	done.Wait()
	state, err := server.Runtime.Authority.EnrollmentState(invite.ID)
	if err != nil || expiryError != nil {
		t.Fatal("concurrent writers damaged the authority", err, expiryError)
	}
	if state == "expired" {
		if expired != 1 || claimError == nil || len(server.Runtime.Authority.Snapshot().Bindings) != 0 {
			t.Fatal("claim bound after durable expiry")
		}
	} else if state != "completed" || expired != 0 || claimError != nil {
		t.Fatal("expiry changed the winning claim", state, expired, claimError)
	}
}

func TestAutomaticExpiryFailureDoesNotReleaseIdentityReservation(t *testing.T) {
	server, invite, _, _, _, _ := enrollmentAuthorityFixture(t)
	key := server.Config.SigningKeyFile
	if err := os.Rename(key, key+".held"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Rename(key+".held", key) })
	before := server.Runtime.Authority.Frontier()
	if count, err := server.Runtime.Authority.ExpireUnboundInvites(context.Background(), time.UnixMilli(invite.ExpiresAt), server.Config); err == nil || count != 0 {
		t.Fatal("missing signing capability produced a terminal result")
	}
	if state, err := server.Runtime.Authority.EnrollmentState(invite.ID); err != nil || state != "open" || !reflect.DeepEqual(before, server.Runtime.Authority.Frontier()) {
		t.Fatal("failed expiration released the reserved identity", state, err)
	}
	if err := os.Rename(key+".held", key); err != nil {
		t.Fatal(err)
	}
	if count, err := server.Runtime.Authority.ExpireUnboundInvites(context.Background(), time.UnixMilli(invite.ExpiresAt).Add(time.Second), server.Config); err != nil || count != 1 {
		t.Fatal("restored signing capability did not resume expiration", count, err)
	}
}

func TestServingControlExpiresUnclaimedInviteWithoutAReadTrigger(t *testing.T) {
	server, invite, _, _, _, _ := enrollmentAuthorityFixture(t)
	server.Now = func() time.Time { return time.UnixMilli(invite.ExpiresAt) }
	server.AdminSocket = filepath.Join(server.Runtime.Authority.root, "admin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	// Read the existing authority directly before making any HTTP request. A
	// page read must not be the event that creates a signed expiration fact.
	deadline := time.Now().Add(10 * time.Second)
	for {
		state, err := server.Runtime.Authority.EnrollmentState(invite.ID)
		if err == nil && state == "expired" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("running daemon did not expire the invitation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", server.AdminSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("http://localhost/api/control/ui/invites/" + invite.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	var value struct {
		State  string `json:"state"`
		Invite string `json:"invite"`
	}
	if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(body, &value) != nil || value.State != "expired" || value.Invite != "" {
		t.Fatal("normal readback did not reflect the terminal fact")
	}
}
