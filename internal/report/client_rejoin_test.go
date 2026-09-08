package report

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/webui"
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
	// Keep the old applied inventory and observation after deletion, as a
	// running reporter does until its next pull and gossip expiry.
	assertLiveMembership := func(wantPresent bool) {
		t.Helper()
		current, err := model.LoadFile(control.SSOTPath)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		cfg := expectedConfigFromSSOT(before)
		cfg.Node = before.Nodes[0].ID
		view := buildView(cfg, &Status{
			Node: cfg.Node, TS: now.Format(time.RFC3339),
			Learned: []Observation{{Node: created.ClientID, TS: now.Format(time.RFC3339)}},
		}, now)
		enrichControlView(&view, current, cfg.Node)
		retained := false
		for _, node := range view.Nodes {
			if node.ID == created.ClientID {
				retained = true
			}
		}
		if !retained {
			t.Fatal("test lost the retained observation before page projection")
		}
		handler := webui.Handler(webui.Deps{
			Node: cfg.Node, Now: func() time.Time { return now },
			Snapshot: func() webui.View { return view },
		})
		for _, path := range []string{"/", "/topology"} {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest("GET", path, nil))
			if recorder.Code != 200 || strings.Contains(recorder.Body.String(), created.ClientID) != wantPresent {
				t.Errorf("%s status=%d, device presence should be %v", path, recorder.Code, wantPresent)
			}
		}
	}
	assertLiveMembership(true)
	for _, paused := range []bool{true, true, false, false} {
		if err := deps.SetDevicePaused(created.ClientID, paused); err != nil {
			t.Fatal(err)
		}
		current, err := model.LoadFile(control.SSOTPath)
		if err != nil || current.NodeByID()[created.ClientID].Paused != paused {
			t.Fatalf("pause state was not persisted: %v", err)
		}
		clients, _, err := store.List()
		if err != nil || len(clients) != 1 || clients[0].Status != "ready" || clients[0].ID != created.ClientID {
			t.Fatalf("pause changed the enrolled identity: %v", err)
		}
		inventory, err := deps.List()
		if err != nil {
			t.Fatal(err)
		}
		for _, device := range inventory.Clients {
			if device.ID == created.ClientID && (device.Membership == "paused") != paused {
				t.Fatalf("inventory membership did not follow SSOT: %+v", device)
			}
		}
		assertLiveMembership(!paused)
	}
	for _, id := range []string{"cn-bj", "cn-hz", "demo-missing"} {
		if err := deps.SetDevicePaused(id, true); err == nil {
			t.Fatalf("pause accepted a control/server/missing device %s", id)
		}
	}
	if err := deps.PurgeRevoked(created.ClientID); err == nil {
		t.Fatal("Device still present in SSOT was purged")
	}
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
	if err := deps.SetDevicePaused(created.ClientID, false); err == nil {
		t.Fatal("resume resurrected a removed device")
	}
	assertLiveMembership(false)
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
	inventory, err := deps.List()
	archivedOK := false
	for i := range inventory.Clients {
		if inventory.Clients[i].ID == created.ClientID {
			archivedOK = inventory.Clients[i].DataPlaneStatus == "not applicable" && inventory.Clients[i].ConfigState == "not applicable"
			break
		}
	}
	if err != nil || !archivedOK {
		t.Fatalf("revoked Device runtime semantics = %+v err=%v", inventory.Clients, err)
	}
	if err := deps.DeleteDevice(created.ClientID); err != nil {
		t.Fatalf("idempotent removal retry failed: %v", err)
	}
	if _, err := p.provision(claimed.Client, csr); err == nil {
		t.Fatal("revoked Device recreated desired membership")
	}
	if err := deps.PurgeRevoked(created.ClientID); err != nil {
		t.Fatal(err)
	}
	clients, _, err = store.List()
	if err != nil || len(clients) != 0 {
		t.Fatalf("purged Device remains in registry: clients=%+v err=%v", clients, err)
	}
	assertLiveMembership(false)
}
