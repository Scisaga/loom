//go:build windows

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unsafe"

	"loom/internal/clientsecret"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func windowsMemberReviewEnvelope(t *testing.T, store *deviceclient.ProtectedStore) control.DeviceViewEnvelope {
	t.Helper()
	invite, makeEnvelope := windowsFixture(t)
	base := invite.ControlProof.Genesis.Payload.(control.Genesis).ControlConfig
	baseID, _ := control.ConfigID(base)
	keys := []ed25519.PrivateKey{}
	for _, suffix := range []string{"a", "b"} {
		seed := sha256.Sum256([]byte("demo-device-control-" + suffix))
		keys = append(keys, ed25519.NewKeyFromSeed(seed[:]))
	}
	sign := func(domain string, value any, key ed25519.PrivateKey) string {
		body, err := control.CanonicalEncode(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(domain), body...)))
	}
	retained, _ := control.KeyID(base.Members[0].PublicKey)
	retired, _ := control.KeyID(base.Members[1].PublicKey)
	inviteID, _ := control.MaterialID(invite.Material)
	seal := control.ControlSealedKey{KeyID: retired, Sequence: 1, TipMaterialID: inviteID}
	round := control.ControlRound{Counter: 1, ProposerControlID: base.Members[0].ControlID}
	promises := []control.ControlPromise{}
	for i, member := range base.Members {
		p := control.ControlPromise{Schema: 3, NetworkID: base.NetworkID, BaseConfigID: baseID, Round: round, ResponderControlID: member.ControlID, Votes: []control.ControlVoteHistoryItem{}, Prefixes: []control.ControlSealedKey{{KeyID: retained, TipMaterialID: control.EmptyMaterialChainID()}, seal}}
		sort.Slice(p.Prefixes, func(i, j int) bool { return p.Prefixes[i].KeyID < p.Prefixes[j].KeyID })
		p.Signature = sign("loom-control-promise-v3\x00", map[string]any{"schema": p.Schema, "network_id": p.NetworkID, "base_config_id": p.BaseConfigID, "round": p.Round, "responder_control_id": p.ResponderControlID, "votes": p.Votes, "prefixes": p.Prefixes}, keys[i])
		promises = append(promises, p)
	}
	config := control.ControlConfig{Schema: 3, NetworkID: base.NetworkID, PreviousConfigID: baseID, Operation: "revoke", TargetNodeID: base.Members[1].NodeID, Members: []control.Member{base.Members[0]}, SealedKeys: []control.ControlSealedKey{seal}, OriginPromises: promises}
	configID, _ := control.ConfigID(config)
	cert := control.ControlCertificate{Config: config, Round: round, Promises: promises, Votes: []control.ControlVote{}}
	for i, member := range base.Members {
		v := control.ControlVote{Schema: 3, NetworkID: base.NetworkID, BaseConfigID: baseID, Round: round, ProposalID: configID, VoterControlID: member.ControlID}
		v.Signature = sign("loom-control-vote-v3\x00", map[string]any{"schema": v.Schema, "network_id": v.NetworkID, "base_config_id": v.BaseConfigID, "round": v.Round, "proposal_id": v.ProposalID, "voter_control_id": v.VoterControlID}, keys[i])
		cert.Votes = append(cert.Votes, v)
	}
	next := makeEnvelope(store.PublicKey(), 9)
	next.ControlProof = control.ControlProof{Genesis: invite.ControlProof.Genesis, Successors: []control.ControlCertificate{cert}}
	next.FactFrontier = []control.FactFrontier{{KeyID: retained, TipMaterialID: control.EmptyMaterialChainID()}, seal}
	sort.Slice(next.FactFrontier, func(i, j int) bool { return next.FactFrontier[i].KeyID < next.FactFrontier[j].KeyID })
	next.IssuerControlID, next.IssuerKeyID = base.Members[0].ControlID, retained
	next.View.Endpoints = []control.EndpointGeneration{}
	next, err := control.SignDeviceViewEnvelope(next, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestWindowsMemberWarningFromDPAPIAndNativeReadback(t *testing.T) {
	for _, edition := range []clientEdition{editionPortableMixed, editionPortableTUN, editionInstalled} {
		t.Run(string(edition), func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			app := &portableGUI{edition: edition, root: t.TempDir(), ctx: ctx, cancel: cancel, state: guiStopped, joined: true, routeSelected: -1}
			var protector clientsecret.Protector = clientsecret.UserProtector{}
			if edition == editionInstalled {
				protector = clientsecret.MachineProtector{}
			}
			// A new test identity is generated and retained only inside guest DPAPI.
			store, err := deviceclient.OpenProtected(windowsProfileStatePath(app.root), brokerTestInvite(t), protector)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.SaveLKG(windowsCertifiedTestView(t, store, 9, true)); err != nil {
				t.Fatal(err)
			}
			app.loadOfflineProfileRoutes()
			if strings.Contains(app.snapshot().detail, "可能恢复部分权限") {
				t.Fatal("warning appeared without a certified member seal")
			}
			if err = store.SaveLKG(windowsMemberReviewEnvelope(t, store)); err != nil {
				t.Fatal(err)
			}
			reopened, err := deviceclient.LoadProtected(windowsProfileStatePath(app.root), protector)
			if err != nil || !reopened.PossiblePermissionRestoration() || reopened.PublicKey() != store.PublicKey() {
				t.Fatal("DPAPI reload lost original identity or warning")
			}
			app.loadOfflineProfileRoutes()
			app.deviceID = reopened.LKG().View.DeviceID
			if !strings.Contains(app.snapshot().detail, "可能恢复部分权限") || !strings.Contains(app.brokerSnapshot().Detail, "可能恢复部分权限") {
				t.Fatal("offline UI or installed broker omitted derived warning")
			}
			hwnd, err := createPortableWindow(app)
			if err != nil {
				t.Fatal(err)
			}
			app.hwnd = hwnd
			portableGUIWindows.Store(hwnd, app)
			defer func() {
				procDestroyWindow.Call(hwnd)
				app.deleteFonts()
				app.deleteIcons()
				portableGUIWindows.Delete(hwnd)
				var message portableMSG
				portableUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x0012, 0x0012, 1)
			}()
			if err = app.createControls(); err != nil {
				t.Fatal(err)
			}
			app.renderControls()
			showPortableWindow(hwnd)
			if !strings.Contains(profileGUIText(app.controls.message), "可能恢复部分权限") {
				t.Fatal("actual native message control omitted member warning")
			}
			if output := os.Getenv("LOOM_UI_CAPTURE_DIR"); output != "" {
				captureProfileGUITestWindow(t, app, filepath.Join(output, "demo-member-"+string(edition)+".png"))
			}
			app.update(guiNeedsJoin, false, "", "")
			if strings.Contains(app.snapshot().detail, "可能恢复部分权限") {
				t.Fatal("removed identity retained previous profile warning")
			}
		})
	}
}
