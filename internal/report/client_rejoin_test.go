package report

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"loom/internal/clientregistry"
	"loom/internal/model"
)

func recoveryInviteToken(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	var payload clientInvitePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Token
}

func TestLostWindowsDeviceReplacementRemovesOldAccessAndRejectsQueuedClaim(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	control.ClientRegistryPath = filepath.Join(filepath.Dir(control.SSOTPath), "registry.json")
	control.ClientEnrollmentURL = "https://control.example/api/client/enroll"
	if err := os.WriteFile(paths.platformPublic, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	deps := newClientControlDeps(control, nil)
	first, err := deps.CreateInvite(accessInviteInput("demo workstation", "windows-desktop"))
	if err != nil {
		t.Fatal(err)
	}
	store := clientregistry.Store{Path: control.ClientRegistryPath}
	csr, _ := clientProvisionCSR(t)
	claimed, err := store.Claim(clientregistry.ClaimInput{Token: recoveryInviteToken(t, first.InviteURI), Platform: "windows-desktop", CSRPEM: csr, RequestID: "demo-original"})
	if err != nil {
		t.Fatal(err)
	}
	var saveMu sync.Mutex
	p := newClientProvisioner(control, &saveMu)
	p.install = func(context.Context, string, []byte) error { return nil }
	if result, err := p.provision(claimed.Client, csr); err != nil || result.Ready {
		t.Fatalf("initial provision ready=%v err=%v", result.Ready, err)
	}
	if _, err := store.MarkReady(first.ClientID); err != nil {
		t.Fatal(err)
	}
	before, err := model.LoadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	oldCredentials := append([]string(nil), before.NodeByID()[first.ClientID].Access.Credentials...)
	next, err := deps.ReplaceDevice(first.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if next.ClientID == first.ClientID || next.ClientName != first.ClientName || next.Platform != first.Platform ||
		strings.Join(next.Responsibilities, ",") != strings.Join(first.Responsibilities, ",") || next.Replaces != first.ClientID {
		t.Fatalf("replacement=%+v", next)
	}
	retired, err := model.LoadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	if retired.NodeByID()[first.ClientID] != nil || retired.NodeByID()[next.ClientID] != nil {
		t.Fatal("old membership survived, or unclaimed replacement joined early")
	}
	for _, id := range oldCredentials {
		if retired.CredentialByID()[id] != nil {
			t.Fatalf("old credential %s survived", id)
		}
	}
	if _, err := p.provision(claimed.Client, csr); err == nil {
		t.Fatal("queued old claim recreated retired membership")
	}
	artifact, err := deps.InviteArtifact(next.InviteID)
	if err != nil || artifact.Replaces != first.ClientID {
		t.Fatalf("replacement artifact=%+v err=%v", artifact, err)
	}
	csr, _ = clientProvisionCSR(t)
	newClaim, err := store.Claim(clientregistry.ClaimInput{Token: recoveryInviteToken(t, next.InviteURI), Platform: "windows-desktop", CSRPEM: csr, RequestID: "demo-replacement"})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := p.provision(newClaim.Client, csr); err != nil || result.Ready {
		t.Fatalf("replacement provision ready=%v err=%v", result.Ready, err)
	}
	current, err := model.LoadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	if current.NodeByID()[first.ClientID] != nil || current.NodeByID()[next.ClientID] == nil {
		t.Fatal("replacement membership is incorrect")
	}
	for _, id := range oldCredentials {
		if current.CredentialByID()[id] != nil {
			t.Fatalf("replacement reused old credential %s", id)
		}
	}
}

func TestJoinedAccessDeviceRemovalRevokesIdentityAndDesiredCredentials(t *testing.T) {
	control, paths := clientProvisionFixture(t)
	control.ClientRegistryPath = filepath.Join(filepath.Dir(control.SSOTPath), "registry.json")
	control.ClientEnrollmentURL = "https://control.example/api/client/enroll"
	if err := os.WriteFile(paths.platformPublic, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	deps := newClientControlDeps(control, nil)
	created, err := deps.CreateInvite(accessInviteInput("retired workstation", "windows-desktop"))
	if err != nil {
		t.Fatal(err)
	}
	store := clientregistry.Store{Path: control.ClientRegistryPath}
	csr, _ := clientProvisionCSR(t)
	claimed, err := store.Claim(clientregistry.ClaimInput{
		Token: recoveryInviteToken(t, created.InviteURI), Platform: "windows-desktop",
		CSRPEM: csr, RequestID: "remove-original",
	})
	if err != nil {
		t.Fatal(err)
	}
	var saveMu sync.Mutex
	p := newClientProvisioner(control, &saveMu)
	p.install = func(context.Context, string, []byte) error { return nil }
	if result, err := p.provision(claimed.Client, csr); err != nil || result.Ready {
		t.Fatalf("initial provision ready=%v err=%v", result.Ready, err)
	}
	if _, err := store.MarkReady(created.ClientID); err != nil {
		t.Fatal(err)
	}
	before, err := model.LoadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	credentialIDs := append([]string(nil), before.NodeByID()[created.ClientID].Access.Credentials...)
	if err := deps.DeleteDevice(created.ClientID); err != nil {
		t.Fatal(err)
	}
	after, err := model.LoadFile(control.SSOTPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.NodeByID()[created.ClientID] != nil {
		t.Fatal("removed Device remains in SSOT")
	}
	for _, id := range credentialIDs {
		if after.CredentialByID()[id] != nil {
			t.Fatalf("removed Device credential %s remains accepted", id)
		}
	}
	clients, _, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].Status != "revoked" || clients[0].RevokedAt == "" {
		t.Fatalf("removed Device identity was not revoked: %+v", clients)
	}
	if err := deps.DeleteDevice(created.ClientID); err != nil {
		t.Fatalf("idempotent removal retry failed: %v", err)
	}
	if _, err := p.provision(claimed.Client, csr); err == nil {
		t.Fatal("revoked Device recreated desired membership")
	}
}
