package clientregistry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/model"
)

func testStore(t *testing.T, now *time.Time) Store {
	t.Helper()
	return Store{
		Path: filepath.Join(t.TempDir(), "clients.json"),
		Now:  func() time.Time { return *now },
		TTL:  10 * time.Minute,
	}
}

func testAccessIntent(platform string) EnrollmentIntent {
	return EnrollmentIntent{
		Platform: platform, Responsibilities: []string{"use_loom"},
		DestinationGrants: []string{"best-egress"},
	}
}

func TestInvitationPersistsOnlyHashAndExactClaimReplayIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	created, err := store.Create("build server", testAccessIntent("linux-server"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) == "" || contains(string(body), created.Token) {
		t.Fatal("registry persisted the bearer invitation token")
	}
	artifactToken, artifact, err := store.Artifact(created.Invite.ID)
	if err != nil || artifactToken != created.Token || artifact.ClientID != created.Client.ID {
		t.Fatalf("artifact token=%q artifact=%+v err=%v", artifactToken, artifact, err)
	}
	info, err := os.Stat(store.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("registry mode=%v err=%v", info.Mode(), err)
	}

	csr := makeCSR(t, "install-1")
	claim := ClaimInput{
		Token: created.Token, Platform: "linux-server",
		CSRPEM: csr, RequestID: "install-1",
	}
	first, err := store.Claim(claim)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replay || first.Client.Status != "provisioning" || first.Client.Platform != "linux-server" ||
		first.Client.EnrolledAt == "" || first.Client.KeyFingerprint == "" {
		t.Fatalf("first claim=%+v", first)
	}
	if _, _, err := store.Artifact(created.Invite.ID); err == nil {
		t.Fatal("consumed invitation artifact remained retrievable")
	}
	ready, err := store.MarkReady(first.Client.ID)
	if err != nil || ready.Status != "ready" || ready.ReadyAt != now.Format(time.RFC3339) {
		t.Fatalf("mark ready=%+v err=%v", ready, err)
	}
	readyAgain, err := store.MarkReady(first.Client.ID)
	if err != nil || readyAgain.Status != "ready" {
		t.Fatalf("idempotent mark ready=%+v err=%v", readyAgain, err)
	}

	// A successful response can be lost. The same identity gets the same result
	// while the original invitation TTL is still open.
	now = now.Add(9 * time.Minute)
	replayed, err := store.Claim(claim)
	if err != nil || !replayed.Replay || replayed.Client.ID != first.Client.ID ||
		replayed.Client.EnrolledAt != first.Client.EnrolledAt {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}

	claim.CSRPEM = makeCSR(t, "other")
	_, err = store.Claim(claim)
	var protocolErr *Error
	if !errors.As(err, &protocolErr) || protocolErr.Code != CodeConflict {
		t.Fatalf("different identity error=%v", err)
	}

	// The original bearer TTL limits first use. After consumption, the exact
	// Device identity/request tuple gets a separate bounded recovery window so a
	// pending or lost ready response does not strand the pre-created Device.
	now = now.Add(2 * time.Minute)
	claim.CSRPEM = csr
	replayed, err = store.Claim(claim)
	if err != nil || !replayed.Replay || replayed.Client.ID != first.Client.ID {
		t.Fatalf("post-expiry exact recovery=%+v err=%v", replayed, err)
	}

	// The recovery token remains bounded; the static CSR is not a fresh
	// proof-of-possession credential and must not become a permanent bootstrap.
	now = now.Add(DefaultClaimRecoveryTTL)
	_, err = store.Claim(claim)
	if !errors.As(err, &protocolErr) || protocolErr.Code != CodeExpired {
		t.Fatalf("expired recovery replay error=%v", err)
	}
}

func TestReportingIdentityRequiresExactReadyEnrollmentKey(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	created, err := store.Create("Windows workstation", testAccessIntent("windows-desktop"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.Claim(ClaimInput{
		Token: created.Token, Platform: string(model.WindowsDesktop),
		CSRPEM: makeCSR(t, "reporting-device"), RequestID: "reporting-device",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReportingIdentity(claimed.Client.ID, claimed.Client.PublicKey); err == nil {
		t.Fatal("provisioning identity was authorized to report")
	}
	if _, err := store.MarkReady(claimed.Client.ID); err != nil {
		t.Fatal(err)
	}
	got, err := store.ReportingIdentity(claimed.Client.ID, claimed.Client.PublicKey)
	if err != nil || got.ID != claimed.Client.ID {
		t.Fatalf("ready reporting identity = %+v, %v", got, err)
	}
	if _, err := store.ReportingIdentity(claimed.Client.ID, "not-canonical-spki"); err == nil {
		t.Fatal("wrong reporting key was authorized")
	}
	if _, err := store.Revoke(claimed.Client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReportingIdentity(claimed.Client.ID, claimed.Client.PublicKey); err == nil {
		t.Fatal("revoked reporting identity was authorized")
	}
}

func TestProvisioningClaimRecoveryRequiresExactTupleAndExpires(t *testing.T) {
	started := time.Date(2026, 9, 3, 14, 0, 0, 0, time.UTC)
	now := started
	store := testStore(t, &now)
	store.RecoveryTTL = 30 * time.Minute
	created, err := store.Create("recovering Device", testAccessIntent("linux-server"))
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claim := ClaimInput{
		Token: created.Token, Platform: "linux-server",
		CSRPEM: makeCSRWithKey(t, "recovering-install", key), RequestID: "recovering-install",
	}
	first, err := store.Claim(claim)
	if err != nil || first.Replay || first.Client.Status != "provisioning" || first.Client.ReadyAt != "" {
		t.Fatalf("first provisioning claim=%+v err=%v", first, err)
	}

	// The invitation itself has expired, but an exact retry can still recover a
	// lost provisioning response during the separate, bounded recovery window.
	now = started.Add(store.TTL + time.Second)
	replay, err := store.Claim(claim)
	if err != nil || !replay.Replay || replay.Client.ID != first.Client.ID ||
		replay.Client.Status != "provisioning" || replay.Client.EnrolledAt != first.Client.EnrolledAt {
		t.Fatalf("post-invite-expiry provisioning replay=%+v err=%v", replay, err)
	}

	changedCSR := claim
	changedCSR.CSRPEM = makeCSRWithKey(t, "changed-csr", key)
	changedRequest := claim
	changedRequest.RequestID = "changed-request"
	changedPlatform := claim
	changedPlatform.Platform = "windows-desktop"
	for name, changed := range map[string]ClaimInput{
		"csr":        changedCSR,
		"request_id": changedRequest,
		"platform":   changedPlatform,
	} {
		t.Run("reject changed "+name, func(t *testing.T) {
			_, claimErr := store.Claim(changed)
			var protocolErr *Error
			if !errors.As(claimErr, &protocolErr) || protocolErr.Code != CodeConflict {
				t.Fatalf("changed %s replay error=%v", name, claimErr)
			}
		})
	}

	// Recovery is half-open: the exact deadline is already expired.
	now = started.Add(store.RecoveryTTL)
	_, err = store.Claim(claim)
	var protocolErr *Error
	if !errors.As(err, &protocolErr) || protocolErr.Code != CodeExpired {
		t.Fatalf("expired provisioning recovery error=%v", err)
	}
}

func TestRevokeErasesInvitationMaterialAndIsIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 1, 21, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	created, err := store.Create("Disposable canary", testAccessIntent("windows-desktop"))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.Revoke(created.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != "revoked" || revoked.RevokedAt != now.Format(time.RFC3339) {
		t.Fatalf("revoked Device = %+v", revoked)
	}
	if _, _, err := store.Artifact(created.Invite.ID); err == nil {
		t.Fatal("revoked Device invitation bearer remained recoverable")
	}
	now = now.Add(time.Hour)
	repeated, err := store.Revoke(created.Client.ID)
	if err != nil || repeated.RevokedAt != revoked.RevokedAt {
		t.Fatalf("repeat revoke = %+v err=%v", repeated, err)
	}
}

func TestPurgeRevokedRemovesOnlyClosedIdentityAndInvites(t *testing.T) {
	now := time.Date(2026, 9, 1, 21, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	purged, err := store.Create("Disposable canary", testAccessIntent("windows-desktop"))
	if err != nil {
		t.Fatal(err)
	}
	kept, err := store.Create("Kept identity", testAccessIntent("windows-desktop"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PurgeRevoked(purged.Client.ID); err == nil {
		t.Fatal("pending Device was purged")
	}
	if _, err := store.Revoke(purged.Client.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.PurgeRevoked(purged.Client.ID); err != nil {
		t.Fatal(err)
	}
	clients, invites, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ID != kept.Client.ID || len(invites) != 1 || invites[0].ClientID != kept.Client.ID {
		t.Fatalf("after purge clients=%+v invites=%+v", clients, invites)
	}
	if err := store.PurgeRevoked(purged.Client.ID); err == nil {
		t.Fatal("missing revoked Device purge unexpectedly succeeded")
	}
}

func TestDiscardPendingRemovesOnlyUnclaimedIdentityAndInvites(t *testing.T) {
	now := time.Date(2026, 9, 1, 21, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	discarded, err := store.Create("Discarded test", testAccessIntent("linux-server"))
	if err != nil {
		t.Fatal(err)
	}
	kept, err := store.Create("Claimed Device", testAccessIntent("linux-server"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ClaimInput{
		Token: kept.Token, Platform: "linux-server", CSRPEM: makeCSR(t, "claimed"), RequestID: "claimed",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardPending(kept.Client.ID); err == nil {
		t.Fatal("claimed Device was discarded")
	}
	if err := store.DiscardPending(discarded.Client.ID); err != nil {
		t.Fatal(err)
	}
	clients, invites, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ID != kept.Client.ID || len(invites) != 1 || invites[0].ClientID != kept.Client.ID {
		t.Fatalf("after discard clients=%+v invites=%+v", clients, invites)
	}
}

func TestImportManagedIdentityIsCanonicalUniqueAndIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 1, 21, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	input := ManagedIdentity{
		ID: "edge01", Name: "Existing edge", Platform: "linux-server",
		PublicKey:     base64.RawStdEncoding.EncodeToString(spki),
		CertificateAt: now.Add(-time.Hour).Format(time.RFC3339),
	}
	first, err := store.ImportManaged(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "managed" || first.IdentitySource != "managed-certificate" || first.KeyFingerprint == "" {
		t.Fatalf("managed identity = %+v", first)
	}
	repeated, err := store.ImportManaged(input)
	if err != nil || repeated.KeyFingerprint != first.KeyFingerprint {
		t.Fatalf("repeat import = %+v err=%v", repeated, err)
	}
	input.ID = "other01"
	if _, err := store.ImportManaged(input); err == nil {
		t.Fatal("one managed public key was bound to a second Device")
	}
}

func TestInvitationPinsImmutableEnrollmentIntent(t *testing.T) {
	now := time.Date(2026, 9, 1, 19, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	intent := EnrollmentIntent{
		Platform:          "linux-server",
		Responsibilities:  []string{"use_loom"},
		DestinationGrants: []string{"best-egress", "sg-fixed"},
	}
	created, err := store.Create("access Device", intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.DestinationGrants[0] = "mutated-after-create"
	clients, invites, err := store.List()
	if err != nil || len(clients) != 1 || len(invites) != 1 {
		t.Fatalf("list clients=%+v invites=%+v err=%v", clients, invites, err)
	}
	if strings.Join(clients[0].DestinationGrants, ",") != "best-egress,sg-fixed" ||
		strings.Join(created.Client.DestinationGrants, ",") != "best-egress,sg-fixed" {
		t.Fatalf("pinned assignment was not durably copied: client=%+v invite=%+v", clients[0], invites[0])
	}
	if len(clients[0].ID) > 12 || !strings.HasPrefix(clients[0].ID, "d-") {
		t.Fatalf("new unified Device id %q cannot safely become a WireGuard peer", clients[0].ID)
	}
}

func TestEnrollmentIntentRejectsUnsupportedCombinations(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	cases := map[string]EnrollmentIntent{
		"no responsibilities":       {Platform: "linux-server"},
		"unknown platform":          {Platform: "android", Responsibilities: []string{"use_loom"}, DestinationGrants: []string{"best-egress"}},
		"unknown responsibility":    {Platform: "linux-server", Responsibilities: []string{"control"}},
		"egress without forward":    {Platform: "linux-server", Responsibilities: []string{"internet_egress"}},
		"use without grants":        {Platform: "linux-server", Responsibilities: []string{"use_loom"}},
		"grants without use":        {Platform: "linux-server", Responsibilities: []string{"forward"}, DestinationGrants: []string{"best-egress"}, Direction: "bidirectional"},
		"forward without direction": {Platform: "linux-server", Responsibilities: []string{"forward"}},
		"direction without forward": {Platform: "linux-server", Responsibilities: []string{"use_loom"}, DestinationGrants: []string{"best-egress"}, Direction: "bidirectional"},
		"Windows forwarding":        {Platform: "windows-desktop", Responsibilities: []string{"forward"}, Direction: "bidirectional"},
	}
	for name, intent := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := store.Create("invalid intent", intent); err == nil {
				t.Fatalf("accepted %+v", intent)
			}
		})
	}
	if _, err := store.Create("reverse access and egress", EnrollmentIntent{
		Platform: "linux-server", Responsibilities: []string{"internet_egress", "use_loom", "forward"},
		DestinationGrants: []string{"best-egress"}, Direction: "reverse_only",
	}); err != nil {
		t.Fatalf("valid combined Linux responsibilities were rejected: %v", err)
	}
}

func TestServerClaimMustMatchPinnedResponsibilitiesAndExactReplay(t *testing.T) {
	now := time.Date(2026, 9, 1, 19, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	created, err := store.Create("egress Device", EnrollmentIntent{
		Platform: "linux-server", Responsibilities: []string{"forward", "internet_egress"}, Direction: "bidirectional",
	})
	if err != nil {
		t.Fatal(err)
	}
	claim := ClaimInput{
		Token: created.Token, Platform: "linux-server", CSRPEM: makeCSR(t, "server-install"), RequestID: "server-install",
	}
	if _, err := store.Claim(claim); err == nil {
		t.Fatal("server invitation was consumed without server facts")
	}
	claim.Server = &ServerEnrollment{
		PublicEndpoint: "edge.example.net", InboundPort: 61698, Direction: "reverse_only",
		WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Country: "CN", City: "Beijing",
	}
	if _, err := store.Claim(claim); err == nil {
		t.Fatal("server claim accepted a direction different from the invitation")
	}
	claim.Server.Direction = "bidirectional"
	first, err := store.Claim(claim)
	if err != nil || first.Replay || first.Client.Server == nil || first.Client.Server.PublicEndpoint != "edge.example.net" {
		t.Fatalf("server claim=%+v err=%v", first, err)
	}
	replay, err := store.Claim(claim)
	if err != nil || !replay.Replay {
		t.Fatalf("exact server replay=%+v err=%v", replay, err)
	}
	changed := *claim.Server
	changed.InboundPort++
	claim.Server = &changed
	if _, err := store.Claim(claim); err == nil {
		t.Fatal("server claim replay accepted changed public facts")
	}
}

func TestSchemaOneMigrationDropsOldInvitationsAndKeepsJoinedIdentity(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	body := `{
  "schema": 1,
  "clients": [
    {"id":"d-ready0001","name":"joined","platform":"windows-desktop","identity_source":"enrollment","public_key":"opaque","status":"ready","created_at":"2026-09-01T00:00:00Z","profile_version":"access-v1","profile_digest":"old","responsibilities":["use_loom"],"destination_grants":["best-egress"]},
    {"id":"d-pending01","name":"pending","status":"pending","created_at":"2026-09-01T00:00:00Z","profile_version":"access-v1","profile_digest":"old","responsibilities":["use_loom"],"destination_grants":["best-egress"]}
  ],
  "invites": [
    {"id":"old-invite","client_id":"d-pending01","token_sha256":"old","created_at":"2026-09-01T00:00:00Z","expires_at":"2026-09-01T00:15:00Z","profile_version":"access-v1","profile_digest":"old"}
  ]
}`
	if err := os.WriteFile(store.Path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	clients, invites, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ID != "d-ready0001" || len(invites) != 0 {
		t.Fatalf("migrated clients=%+v invites=%+v", clients, invites)
	}
	if err := ValidateEnrollment(clients[0]); err != nil {
		t.Fatalf("joined identity lost its concrete enrollment intent: %v", err)
	}
	persisted, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(persisted), `"schema": 2`) || contains(string(persisted), "profile_") || contains(string(persisted), "old-invite") {
		t.Fatalf("schema-one invitation survived migration: %s", persisted)
	}
}

func TestConcurrentInvitationsCannotBindOneCanonicalSPKITwice(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	firstInvite, err := store.Create("first device record", testAccessIntent("linux-server"))
	if err != nil {
		t.Fatal(err)
	}
	secondInvite, err := store.Create("second device record", testAccessIntent("linux-server"))
	if err != nil {
		t.Fatal(err)
	}
	csr := makeCSR(t, "same-device-key")
	claims := []ClaimInput{
		{Token: firstInvite.Token, Platform: "linux-server", CSRPEM: csr, RequestID: "request-first"},
		{Token: secondInvite.Token, Platform: "linux-server", CSRPEM: csr, RequestID: "request-second"},
	}
	type outcome struct {
		result ClaimResult
		err    error
	}
	outcomes := make([]outcome, len(claims))
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := range claims {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			outcomes[index].result, outcomes[index].err = store.Claim(claims[index])
		}(i)
	}
	close(start)
	workers.Wait()

	winner, loser := -1, -1
	for i, outcome := range outcomes {
		if outcome.err == nil {
			if winner != -1 {
				t.Fatalf("同一 SPKI 绑定成功两次: outcomes=%+v", outcomes)
			}
			winner = i
			continue
		}
		var protocolErr *Error
		if !errors.As(outcome.err, &protocolErr) || protocolErr.Code != CodeConflict {
			t.Fatalf("第二张邀请没有返回 identity conflict: outcomes=%+v", outcomes)
		}
		loser = i
	}
	if winner == -1 || loser == -1 {
		t.Fatalf("并发 claim 结果不完整: outcomes=%+v", outcomes)
	}

	// 成功邀请仍保持原有精确重试语义。
	replay, err := store.Claim(claims[winner])
	if err != nil || !replay.Replay || replay.Client.ID != outcomes[winner].result.Client.ID {
		t.Fatalf("winner exact replay=%+v err=%v", replay, err)
	}

	// 冲突邀请没有被消费，也没有被同一个 SPKI 部分绑定；它仍可交给
	// 另一台真正的设备使用，因此不会留下无法恢复的 client/orphan。
	invites := []CreateResult{firstInvite, secondInvite}
	token, pendingInvite, err := store.Artifact(invites[loser].Invite.ID)
	if err != nil || token != invites[loser].Token || pendingInvite.ConsumedAt != "" {
		t.Fatalf("losing invite was consumed: token_match=%v invite=%+v err=%v", token == invites[loser].Token, pendingInvite, err)
	}
	differentClaim := claims[loser]
	differentClaim.CSRPEM = makeCSR(t, "different-device-key")
	different, err := store.Claim(differentClaim)
	if err != nil || different.Replay || different.Client.ID != invites[loser].Client.ID {
		t.Fatalf("losing invite could not enroll another device: result=%+v err=%v", different, err)
	}

	// 重新打开磁盘 registry 后仍只有两个不同的 canonical SPKI；唯一性
	// 不是进程内缓存效果。
	reloaded := Store{Path: store.Path, Now: store.Now, TTL: store.TTL}
	clients, _, err := reloaded.List()
	if err != nil || len(clients) != 2 || clients[0].PublicKey == "" || clients[1].PublicKey == "" || clients[0].PublicKey == clients[1].PublicKey {
		t.Fatalf("persisted client identities=%+v err=%v", clients, err)
	}
}

func TestExpiredInvitationDoesNotPartiallyBindClient(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	created, err := store.Create("expired device", testAccessIntent("linux-server"))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	_, err = store.Claim(ClaimInput{
		Token: created.Token, Platform: "linux-server",
		CSRPEM: makeCSR(t, "install-2"), RequestID: "install-2",
	})
	var protocolErr *Error
	if !errors.As(err, &protocolErr) || protocolErr.Code != CodeExpired {
		t.Fatalf("claim error=%v", err)
	}
	clients, _, err := store.List()
	if err != nil || len(clients) != 1 || clients[0].Status != "invite_expired" ||
		clients[0].PublicKey != "" || clients[0].EnrolledAt != "" {
		t.Fatalf("clients=%+v err=%v", clients, err)
	}
	body, err := os.ReadFile(store.Path)
	if err != nil || contains(string(body), `"sealed_token"`) {
		t.Fatalf("expired registry retained decryptable invitation material: err=%v body=%s", err, body)
	}
}

func TestClaimRejectsUnknownPlatformAndMalformedKey(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	created, err := store.Create("device", testAccessIntent("linux-server"))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []ClaimInput{
		{Token: created.Token, Platform: "ios", CSRPEM: makeCSR(t, "ios"), RequestID: "r1"},
		{Token: created.Token, Platform: "android", CSRPEM: makeCSR(t, "android"), RequestID: "r1"},
		{Token: created.Token, Platform: "linux-server", CSRPEM: "x", RequestID: "r1"},
		{Token: created.Token, Platform: "linux-server", CSRPEM: makeCSR(t, "missing-request")},
	} {
		_, err := store.Claim(input)
		var protocolErr *Error
		if !errors.As(err, &protocolErr) || protocolErr.Code != CodeInvalid {
			t.Errorf("input=%+v error=%v", input, err)
		}
	}
	if _, err := store.Claim(ClaimInput{
		Token: created.Token, Platform: "linux-server",
		CSRPEM: makeCSR(t, "linux"), RequestID: "valid-after-rejects",
	}); err != nil {
		t.Fatalf("invalid platform consumed the invitation: %v", err)
	}
}

func TestClaimAcceptsWindowsDesktopAccessIdentityAndReplay(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	created, err := store.Create("Windows laptop", testAccessIntent("windows-desktop"))
	if err != nil {
		t.Fatal(err)
	}
	claim := ClaimInput{
		Token: created.Token, Platform: "windows-desktop",
		CSRPEM: makeCSR(t, "windows-access"), RequestID: "windows-access",
	}
	first, err := store.Claim(claim)
	if err != nil || first.Replay || first.Client.Platform != "windows-desktop" || first.Client.Status != "provisioning" {
		t.Fatalf("first Windows claim=%+v err=%v", first, err)
	}
	replay, err := store.Claim(claim)
	if err != nil || !replay.Replay || replay.Client.PublicKey != first.Client.PublicKey {
		t.Fatalf("Windows replay=%+v err=%v", replay, err)
	}
}

func TestClaimRejectsPlatformThatDoesNotMatchForwardInvitation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	created, err := store.Create("server Device", EnrollmentIntent{
		Platform: "linux-server", Responsibilities: []string{"forward"}, Direction: "bidirectional",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(ClaimInput{
		Token: created.Token, Platform: "windows-desktop",
		CSRPEM: makeCSR(t, "windows-server"), RequestID: "windows-server",
	}); err == nil {
		t.Fatal("Windows consumed a forward-capable invitation")
	}
	linux := ClaimInput{
		Token: created.Token, Platform: "linux-server",
		CSRPEM: makeCSR(t, "linux-server"), RequestID: "linux-server",
		Server: &ServerEnrollment{
			PublicEndpoint: "edge.example.net", InboundPort: 61698, Direction: "bidirectional",
			WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
	}
	if _, err := store.Claim(linux); err != nil {
		t.Fatalf("Windows rejection consumed the invitation: %v", err)
	}
}

func TestGeneratedClientIDsAlwaysUseCanonicalNodeGrammar(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := testStore(t, &now)
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		created, err := store.Create("device", testAccessIntent("windows-desktop"))
		if err != nil {
			t.Fatal(err)
		}
		if !model.ValidNodeID(created.Client.ID) || created.Client.ID != strings.ToLower(created.Client.ID) {
			t.Fatalf("generated invalid client id %q", created.Client.ID)
		}
		if seen[created.Client.ID] {
			t.Fatalf("generated duplicate client id %q", created.Client.ID)
		}
		seen[created.Client.ID] = true
	}
}

func makeCSR(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return makeCSRWithKey(t, commonName, key)
}

func makeCSRWithKey(t *testing.T, commonName string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestStoreRejectsSymlinkRegistryAndUnsafeDirectory(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(`{"schema":1,"clients":[],"invites":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "clients.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	store := Store{Path: link, Now: func() time.Time { return now }}
	if _, _, err := store.List(); err == nil {
		t.Fatal("symlink registry was accepted")
	}

	unsafe := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	store.Path = filepath.Join(unsafe, "clients.json")
	if _, _, err := store.List(); err == nil {
		t.Fatal("world-writable registry directory was accepted")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
