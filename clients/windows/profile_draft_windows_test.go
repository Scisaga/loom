//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"loom/internal/windowsv2"
)

func profileDraftInvite() string {
	return `{"schema":2,"cluster_id":"demo-cluster","invite_id":"demo-invite"}`
}

func completeProfileDraftFixture(t *testing.T, child *portableGUI, carrier string) (windowsJoinResult, error) {
	t.Helper()
	identity, err := windowsv2.OpenOrCreateIdentity(windowsV2IdentityPath(child.root), child.protector(), rand.Reader)
	if err != nil {
		return windowsJoinResult{}, err
	}
	identity.Close()
	marker := filepath.Join(child.root, "state", "demo-joined")
	if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
		return windowsJoinResult{}, err
	}
	if err := os.WriteFile(marker, []byte("demo-draft"), 0600); err != nil {
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
	m.joinDraftV2 = func(child *portableGUI, invite string) (windowsJoinResult, error) {
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
	if err := m.dispatch(brokerRequest{Operation: "join_profile", V2Carrier: profileDraftInvite()}); err != nil {
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
	m.joinDraftV2 = func(child *portableGUI, invite string) (windowsJoinResult, error) {
		identity, err := windowsv2.OpenOrCreateIdentity(windowsV2IdentityPath(child.root), child.protector(), rand.Reader)
		if err != nil {
			return windowsJoinResult{}, err
		}
		identity.Close()
		identityPath = windowsV2IdentityPath(child.root)
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
	if err := m.dispatch(brokerRequest{Operation: "join_profile", V2Carrier: profileDraftInvite()}); err != nil {
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
	restarted.readJoined = readProfileFixtureIdentity
	view := restarted.snapshot().profileDraft
	if view == nil || !view.Recoverable || view.Busy {
		t.Fatalf("restart lost recoverable join: %+v", view)
	}
	draft, err := restarted.store.Draft()
	if err != nil || draft == nil {
		t.Fatal("draft metadata missing", err)
	}
	root, _ := restarted.store.ResolveDraftRoot(draft.ID)
	original, err := windowsv2.LoadIdentity(windowsV2IdentityPath(root), owner.protector())
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	restarted.joinDraftV2 = func(child *portableGUI, invite string) (windowsJoinResult, error) {
		if invite != "" {
			t.Error("recovery submitted another invitation")
		}
		return completeProfileDraftFixture(t, child, "")
	}
	if err := restarted.dispatch(brokerRequest{Operation: "join_profile"}); err != nil {
		t.Fatal(err)
	}
	restarted.workers.Wait()
	retained, err := windowsv2.LoadIdentity(windowsV2IdentityPath(root), owner.protector())
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	if !bytes.Equal(original.IdentitySPKIDER(), retained.IdentitySPKIDER()) || len(restarted.store.Snapshot().Profiles) != 2 {
		t.Fatal("recovery changed identity or did not commit the completed profile")
	}
}

func TestWindowsProfileDraftReadyIndexFailureRetriesWithoutAnotherClaim(t *testing.T) {
	m := newProfileManagerFixture(t)
	var claims atomic.Int32
	m.joinDraftV2 = func(child *portableGUI, invite string) (windowsJoinResult, error) {
		if invite != "" {
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
	if err := m.command(brokerRequest{Operation: "join_profile", V2Carrier: profileDraftInvite()}); err == nil {
		t.Fatal("failed formal index commit reported success")
	}
	view := m.snapshot().profileDraft
	if len(m.store.Snapshot().Profiles) != 1 || view == nil || !view.Recoverable || view.Busy {
		t.Fatal("failed formal commit lost ready recovery or added a blank profile")
	}
	if err := m.command(brokerRequest{Operation: "join_profile", V2Carrier: profileDraftInvite()}); err == nil || claims.Load() != 1 {
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
	m.joinDraftV2 = func(*portableGUI, string) (windowsJoinResult, error) {
		calls.Add(1)
		return windowsJoinResult{}, nil
	}
	if err := m.joinProfileDraftFor(brokerRequest{Operation: "join_profile", V2Carrier: profileDraftInvite()}, draft, epoch); !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatal("a queued canceled join was resurrected by another panel", err)
	}
	if _, err := os.Stat(m.store.draftPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a queued canceled join allocated identity storage", err)
	}
}

func TestWindowsProfileDraftCancelAfterReadyDoesNotCommit(t *testing.T) {
	m := newProfileManagerFixture(t)
	entered := make(chan struct{})
	m.joinDraftV2 = func(child *portableGUI, invite string) (windowsJoinResult, error) {
		close(entered)
		<-child.ctx.Done()
		// 模拟取消与已返回的 ready 落盘竞态；正式索引仍不得越过取消屏障。
		return completeProfileDraftFixture(t, child, invite)
	}
	if err := m.dispatch(brokerRequest{Operation: "add_profile", Name: "demo-canceled-ready"}); err != nil {
		t.Fatal(err)
	}
	if err := m.dispatch(brokerRequest{Operation: "join_profile", V2Carrier: profileDraftInvite()}); err != nil {
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
	for _, invite := range []string{"", `{"schema":1,"endpoint":"https://control.example/loom-client/enroll"}`} {
		if err := m.command(brokerRequest{Operation: "join_profile", V2Carrier: invite}); err == nil {
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
	identity, err := windowsv2.OpenOrCreateIdentity(windowsV2IdentityPath(root), m.owner.protector(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity.Close()
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
	if _, err := os.Stat(windowsV2IdentityPath(root)); err != nil {
		t.Fatal("legacy deletion erased another pending identity", err)
	}
}
