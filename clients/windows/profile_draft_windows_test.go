//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/clientenroll"
	"loom/internal/clientupdate"
)

func profileDraftInvite() *clientenroll.Invite {
	return &clientenroll.Invite{Endpoint: "https://control.example/loom-client/enroll",
		Token:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x26}, 32)),
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
}

func writeProfileDraftConfig(t *testing.T, root string) {
	t.Helper()
	config := clientupdate.Config{Schema: 1, NodeID: "demo-draft", DistributionURLs: []string{"https://distribution.example/loom"}}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config", "client.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func completeProfileDraftFixture(t *testing.T, child *portableGUI, invite *clientenroll.Invite) (windowsJoinResult, error) {
	t.Helper()
	if invite != nil {
		identity, err := loadOrCreateWindowsIdentity(child.root, *invite, child.protector(), rand.Reader)
		if err != nil {
			return windowsJoinResult{}, err
		}
		clearPreparedIdentity(&identity)
	}
	writeProfileDraftConfig(t, child.root)
	if err := clearWindowsPendingInvite(child.root, child.protector()); err != nil {
		return windowsJoinResult{}, err
	}
	return windowsJoinResult{NodeID: "demo-draft"}, nil
}

func TestWindowsProfileDraftCommitsJoinedIdentityWithoutSwitchingActive(t *testing.T) {
	m := newProfileManagerFixture(t)
	active := m.children[legacyConnectionProfile]
	canceled, _ := startProfileFixture(active, nil)
	before := m.store.Snapshot()
	var starts atomic.Int32
	m.start = func(*portableGUI) { starts.Add(1) }
	m.joinDraft = func(child *portableGUI, invite *clientenroll.Invite) (windowsJoinResult, error) {
		if !reflect.DeepEqual(before, m.store.Snapshot()) {
			t.Error("draft appeared in the formal index before join completed")
		}
		return completeProfileDraftFixture(t, child, invite)
	}
	if err := m.dispatch(brokerRequest{Operation: "add_profile", Name: "demo-new-network"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, m.store.Snapshot()) {
		t.Fatal("opening the panel changed profiles")
	}
	if err := m.dispatch(brokerRequest{Operation: "join_profile", Invite: profileDraftInvite()}); err != nil {
		t.Fatal(err)
	}
	m.workers.Wait()
	after := m.store.Snapshot()
	s := m.snapshot()
	if len(after.Profiles) != 2 || after.Selected == legacyConnectionProfile || after.LastConnected != legacyConnectionProfile || s.activeProfile != legacyConnectionProfile {
		t.Fatalf("adding a joined profile changed the active connection: %+v %+v", after, s)
	}
	child := m.children[after.Selected]
	if child == nil || !child.snapshot().joined || child.snapshot().state != guiStopped || child.runCancel != nil || child.ctx.Err() != nil || starts.Load() != 0 || s.profileDraft != nil {
		t.Fatal("new profile was not committed as a usable disconnected identity")
	}
	select {
	case <-canceled:
		t.Fatal("new join canceled the current profile")
	default:
	}
}

func TestWindowsProfileDraftCancelRetainsProtectedRecoveryAcrossRestart(t *testing.T) {
	m := newProfileManagerFixture(t)
	canceled, _ := startProfileFixture(m.children[legacyConnectionProfile], nil)
	before := m.store.Snapshot()
	entered := make(chan struct{})
	var protected []byte
	var identityPath string
	m.joinDraft = func(child *portableGUI, invite *clientenroll.Invite) (windowsJoinResult, error) {
		identity, err := loadOrCreateWindowsIdentity(child.root, *invite, child.protector(), rand.Reader)
		if err != nil {
			return windowsJoinResult{}, err
		}
		clearPreparedIdentity(&identity)
		identityPath = windowsJoinIdentityPath(child.root)
		protected, err = os.ReadFile(identityPath)
		if err != nil {
			return windowsJoinResult{}, err
		}
		close(entered)
		<-child.ctx.Done()
		return windowsJoinResult{}, child.ctx.Err()
	}
	if err := m.dispatch(brokerRequest{Operation: "add_profile", Name: "demo-recovery"}); err != nil {
		t.Fatal(err)
	}
	if err := m.dispatch(brokerRequest{Operation: "join_profile", Invite: profileDraftInvite()}); err != nil {
		t.Fatal(err)
	}
	waitProfileSignal(t, entered)
	if err := m.dispatch(brokerRequest{Operation: "cancel_add_profile"}); err != nil {
		t.Fatal(err)
	}
	m.workers.Wait()
	if !reflect.DeepEqual(before, m.store.Snapshot()) || m.snapshot().profileDraft != nil {
		t.Fatal("cancel committed an unfinished identity or left the panel open")
	}
	body, err := os.ReadFile(identityPath)
	if err != nil || !bytes.Equal(body, protected) {
		t.Fatal("cancel discarded protected join recovery", err)
	}
	select {
	case <-canceled:
		t.Fatal("canceling the join draft canceled the current connection")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	owner := &portableGUI{root: m.owner.root, edition: m.owner.edition, ctx: ctx, cancel: cancel}
	restarted, err := newWindowsProfileManager(owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); restarted.close() })
	view := restarted.snapshot().profileDraft
	if view == nil || !view.Recoverable || view.Busy {
		t.Fatalf("restart lost recoverable join: %+v", view)
	}
	draft, err := restarted.store.Draft()
	if err != nil || draft == nil {
		t.Fatal("draft metadata missing", err)
	}
	root, _ := restarted.store.ResolveDraftRoot(draft.ID)
	original, err := readWindowsJoinIdentity(root, owner.protector())
	if err != nil {
		t.Fatal(err)
	}
	defer clearPreparedIdentity(&original)
	restarted.joinDraft = func(child *portableGUI, invite *clientenroll.Invite) (windowsJoinResult, error) {
		if invite != nil {
			t.Error("recovery submitted another invitation")
		}
		return completeProfileDraftFixture(t, child, nil)
	}
	if err := restarted.dispatch(brokerRequest{Operation: "join_profile"}); err != nil {
		t.Fatal(err)
	}
	restarted.workers.Wait()
	retained, err := readWindowsJoinIdentity(root, owner.protector())
	if err != nil {
		t.Fatal(err)
	}
	defer clearPreparedIdentity(&retained)
	if original.RequestID != retained.RequestID || !bytes.Equal(original.PrivateKeyPEM, retained.PrivateKeyPEM) || len(restarted.store.Snapshot().Profiles) != 2 {
		t.Fatal("recovery changed identity or did not commit the completed profile")
	}
}

func TestWindowsProfileDraftReadyIndexFailureRetriesWithoutAnotherClaim(t *testing.T) {
	m := newProfileManagerFixture(t)
	var claims atomic.Int32
	m.joinDraft = func(child *portableGUI, invite *clientenroll.Invite) (windowsJoinResult, error) {
		if invite != nil {
			claims.Add(1)
		}
		return completeProfileDraftFixture(t, child, invite)
	}
	write := m.store.writeFile
	m.store.writeFile = func(path string, body []byte) error {
		if path == m.store.indexPath() {
			return errors.New("demo profile index write failure")
		}
		return write(path, body)
	}
	if err := m.command(brokerRequest{Operation: "add_profile", Name: "demo-retry"}); err != nil {
		t.Fatal(err)
	}
	if err := m.command(brokerRequest{Operation: "join_profile", Invite: profileDraftInvite()}); err == nil {
		t.Fatal("failed formal index commit reported success")
	}
	view := m.snapshot().profileDraft
	if len(m.store.Snapshot().Profiles) != 1 || view == nil || !view.Recoverable || view.Busy {
		t.Fatal("failed formal commit lost ready recovery or added a blank profile")
	}
	if err := m.command(brokerRequest{Operation: "join_profile", Invite: profileDraftInvite()}); err == nil || claims.Load() != 1 {
		t.Fatal("ready recovery accepted a second invite claim")
	}
	m.store.writeFile = write
	if err := m.command(brokerRequest{Operation: "join_profile"}); err != nil {
		t.Fatal(err)
	}
	if claims.Load() != 1 || len(m.store.Snapshot().Profiles) != 2 || m.snapshot().profileDraft != nil {
		t.Fatal("ready recovery repeated a claim or failed to finish the profile")
	}
}

func TestWindowsProfileDraftCancelInvalidatesQueuedJoinEvenAfterReopen(t *testing.T) {
	m := newProfileManagerFixture(t)
	if err := m.openProfileDraft("demo-delayed"); err != nil {
		t.Fatal(err)
	}
	draft, epoch := m.draft, m.draft.epoch
	m.cancelProfileDraft()
	if err := m.openProfileDraft("demo-new-panel"); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	m.joinDraft = func(*portableGUI, *clientenroll.Invite) (windowsJoinResult, error) {
		calls.Add(1)
		return windowsJoinResult{}, nil
	}
	if err := m.joinProfileDraftFor(brokerRequest{Operation: "join_profile", Invite: profileDraftInvite()}, draft, epoch); !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatal("a queued canceled join was resurrected by another panel", err)
	}
	if _, err := os.Stat(m.store.draftPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a queued canceled join allocated identity storage", err)
	}
}

func TestWindowsProfileDraftCancelAfterReadyDoesNotCommit(t *testing.T) {
	m := newProfileManagerFixture(t)
	entered := make(chan struct{})
	m.joinDraft = func(child *portableGUI, invite *clientenroll.Invite) (windowsJoinResult, error) {
		close(entered)
		<-child.ctx.Done()
		// §13.5：模拟取消与已返回的 ready 落盘竞态；正式索引仍不得越过取消屏障。
		return completeProfileDraftFixture(t, child, invite)
	}
	if err := m.dispatch(brokerRequest{Operation: "add_profile", Name: "demo-canceled-ready"}); err != nil {
		t.Fatal(err)
	}
	if err := m.dispatch(brokerRequest{Operation: "join_profile", Invite: profileDraftInvite()}); err != nil {
		t.Fatal(err)
	}
	waitProfileSignal(t, entered)
	if err := m.dispatch(brokerRequest{Operation: "cancel_add_profile"}); err != nil {
		t.Fatal(err)
	}
	m.workers.Wait()
	if len(m.store.Snapshot().Profiles) != 1 || m.snapshot().profileDraft != nil {
		t.Fatal("late ready completion committed after cancel")
	}
	draft, err := m.store.Draft()
	if err != nil || draft == nil {
		t.Fatal("late ready completion lost protected recovery", err)
	}
	if err := m.openProfileDraft(""); err != nil || !m.snapshot().profileDraft.Recoverable {
		t.Fatal("late ready completion could not be resumed", err)
	}
}

func TestWindowsProfileDraftRejectsInvalidInviteWithoutAllocating(t *testing.T) {
	m := newProfileManagerFixture(t)
	if err := m.openProfileDraft("demo-input"); err != nil {
		t.Fatal(err)
	}
	for _, invite := range []*clientenroll.Invite{nil, {Endpoint: "https://control.example/loom-client/enroll"}} {
		if err := m.command(brokerRequest{Operation: "join_profile", Invite: invite}); err == nil {
			t.Fatal("invalid invite reached a join transaction")
		}
	}
	if draft, err := m.store.Draft(); err != nil || draft != nil || len(m.store.Snapshot().Profiles) != 1 {
		t.Fatal("invalid invite allocated an identity or a formal profile", err)
	}
}

func TestWindowsProfileDraftSurvivesLegacyProfileDeletion(t *testing.T) {
	m := newProfileManagerFixture(t)
	draft, err := m.store.BeginDraft("demo-pending")
	if err != nil {
		t.Fatal(err)
	}
	root, _ := m.store.ResolveDraftRoot(draft.ID)
	identity, err := loadOrCreateWindowsIdentity(root, *profileDraftInvite(), m.owner.protector(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearPreparedIdentity(&identity)
	if err := m.command(brokerRequest{Operation: "delete", ProfileID: legacyConnectionProfile}); err != nil {
		t.Fatal(err)
	}
	reopened, err := loadConnectionProfiles(m.owner.root, writeWindowsJoinFile, checkWindowsProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := reopened.Draft()
	if err != nil || retained == nil || retained.ID != draft.ID || len(reopened.Snapshot().Profiles) != 0 {
		t.Fatal("legacy deletion lost the pending join or rebuilt legacy", err)
	}
	if _, err := os.Stat(windowsJoinIdentityPath(root)); err != nil {
		t.Fatal("legacy deletion erased another pending identity", err)
	}
}
