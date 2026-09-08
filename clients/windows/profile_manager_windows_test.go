//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/clientcore"
	"loom/internal/clientenroll"
	"loom/internal/clientsecret"
)

func newProfileManagerFixture(t *testing.T) *windowsProfileManager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	owner := &portableGUI{root: t.TempDir(), edition: editionPortableMixed, ctx: ctx, cancel: cancel, hostname: "demo-client"}
	writeProfileFixtureIdentity(t, owner.root)
	m, err := newWindowsProfileManager(owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); m.close() })
	return m
}

func writeProfileFixtureIdentity(t *testing.T, root string) {
	t.Helper()
	for name, data := range map[string][]byte{
		"config/client.json":       []byte(`{"schema":1,"node_id":"demo-client","distribution_urls":["https://distribution.example/loom"]}`),
		"join/identity.json.dpapi": []byte("demo-protected-identity"),
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func addProfileFixture(t *testing.T, m *windowsProfileManager) string {
	t.Helper()
	p, err := m.store.Add("demo-second")
	if err != nil {
		t.Fatal(err)
	}
	id := p.ID
	root, err := m.store.ResolveRoot(id)
	if err != nil {
		t.Fatal(err)
	}
	writeProfileFixtureIdentity(t, root)
	child, err := m.makeChild(id)
	if err != nil {
		t.Fatal(err)
	}
	m.children[id] = child
	return id
}

func startProfileFixture(child *portableGUI, release <-chan struct{}) (<-chan struct{}, <-chan struct{}) {
	ctx, cancel := context.WithCancel(child.ctx)
	canceled, done := make(chan struct{}), make(chan struct{})
	child.mu.Lock()
	child.runCancel, child.runDone = cancel, done
	child.state, child.stopRequested = guiConnected, false
	child.mu.Unlock()
	child.workers.Add(1)
	go func() {
		defer child.workers.Done()
		<-ctx.Done()
		close(canceled)
		if release != nil {
			<-release
		}
		child.mu.Lock()
		child.runCancel, child.runDone = nil, nil
		child.state, child.stopRequested = guiStopped, false
		child.mu.Unlock()
		close(done)
	}()
	return canceled, done
}

func waitProfileSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("profile operation did not complete")
	}
}

func TestWindowsProfilesSwitchWaitsForFullExit(t *testing.T) {
	m := newProfileManagerFixture(t)
	id := addProfileFixture(t, m)
	first := m.children[legacyConnectionProfile]
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	canceled, done := startProfileFixture(first, release)
	started := make(chan struct{})
	var overlap atomic.Bool
	m.start = func(child *portableGUI) {
		select {
		case <-done:
		default:
			overlap.Store(true)
		}
		startProfileFixture(child, nil)
		close(started)
	}
	if err := m.dispatch(brokerRequest{Operation: "connect", ProfileID: id}); err != nil {
		t.Fatal(err)
	}
	waitProfileSignal(t, canceled)
	selected := make(chan struct{})
	go func() {
		if err := m.command(brokerRequest{Operation: "select_profile", ProfileID: legacyConnectionProfile}); err != nil {
			t.Error(err)
		}
		close(selected)
	}()
	waitProfileSignal(t, selected)
	if s := m.snapshot(); s.selectedProfile != legacyConnectionProfile || s.activeProfile != legacyConnectionProfile {
		t.Fatal("view selection was blocked by switch or altered active host")
	}
	select {
	case <-started:
		t.Fatal("next profile started before old host exited")
	default:
	}
	once.Do(func() { close(release) })
	waitProfileSignal(t, started)
	if overlap.Load() {
		t.Fatal("two profile hosts overlapped")
	}
	m.workers.Wait()
	if s := m.snapshot(); s.activeProfile != id || s.selectedProfile != legacyConnectionProfile {
		t.Fatalf("wrong active profile: %+v", s)
	}
}

func TestWindowsProfilesCancelPendingConnectBeforeWorkerStarts(t *testing.T) {
	m := newProfileManagerFixture(t)
	id := addProfileFixture(t, m)
	var starts atomic.Int32
	m.start = func(*portableGUI) { starts.Add(1) }
	m.transitionMu.Lock()
	connectErr := m.dispatch(brokerRequest{Operation: "connect", ProfileID: id})
	disconnectErr := m.dispatch(brokerRequest{Operation: "disconnect", ProfileID: id})
	m.transitionMu.Unlock()
	if connectErr != nil || disconnectErr != nil {
		t.Fatal(connectErr, disconnectErr)
	}
	m.workers.Wait()
	if starts.Load() != 0 || m.snapshot().state == guiStarting {
		t.Fatal("canceled pending request started a host")
	}
}

func TestWindowsProfilesInitialConnectCanBeCanceledWhenPublished(t *testing.T) {
	m := newProfileManagerFixture(t)
	var starts atomic.Int32
	m.start = func(*portableGUI) { starts.Add(1) }
	m.mu.Lock()
	initial, err := m.prepareConnectLocked(legacyConnectionProfile)
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	m.owner.mu.Lock()
	m.owner.profiles = m
	m.owner.mu.Unlock()
	if s := m.owner.snapshot(); s.state != guiStarting {
		t.Fatal("initial intent was not published before UI interaction")
	}
	m.owner.stopRuntime()
	if err := m.runConnect(initial); !errors.Is(err, context.Canceled) {
		t.Fatalf("initial connect after UI cancel: %v", err)
	}
	m.workers.Wait()
	if starts.Load() != 0 {
		t.Fatal("initial connection started after cancellation")
	}
}

func TestWindowsProfilesCancelWhileOldHostExits(t *testing.T) {
	m := newProfileManagerFixture(t)
	id := addProfileFixture(t, m)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	canceled, _ := startProfileFixture(m.children[legacyConnectionProfile], release)
	var starts atomic.Int32
	m.start = func(*portableGUI) { starts.Add(1) }
	if err := m.dispatch(brokerRequest{Operation: "connect", ProfileID: id}); err != nil {
		t.Fatal(err)
	}
	waitProfileSignal(t, canceled)
	if err := m.dispatch(brokerRequest{Operation: "disconnect", ProfileID: id}); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	m.workers.Wait()
	if starts.Load() != 0 || m.store.Snapshot().LastConnected != "" {
		t.Fatal("canceled switch retained a future connection")
	}
}

func TestWindowsProfilesReconnectWaitsForSameHost(t *testing.T) {
	m := newProfileManagerFixture(t)
	child := m.children[legacyConnectionProfile]
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	canceled, done := startProfileFixture(child, release)
	child.stopRuntime()
	waitProfileSignal(t, canceled)
	started := make(chan struct{})
	var overlap atomic.Bool
	m.start = func(child *portableGUI) {
		select {
		case <-done:
		default:
			overlap.Store(true)
		}
		startProfileFixture(child, nil)
		close(started)
	}
	if err := m.dispatch(brokerRequest{Operation: "connect", ProfileID: legacyConnectionProfile}); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(release) })
	waitProfileSignal(t, started)
	m.workers.Wait()
	if overlap.Load() {
		t.Fatal("same profile restarted before old host exited")
	}
}

func TestWindowsProfilesLateDisconnectDoesNotStopNewConnect(t *testing.T) {
	m := newProfileManagerFixture(t)
	id := legacyConnectionProfile
	var canceled <-chan struct{}
	m.start = func(child *portableGUI) { canceled, _ = startProfileFixture(child, nil) }
	m.mu.Lock()
	old, err1 := m.prepareConnectLocked(id)
	stop, err2 := m.prepareDisconnectLocked(id)
	latest, err3 := m.prepareConnectLocked(id)
	m.mu.Unlock()
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatal(err1, err2, err3)
	}
	if err := m.runConnect(latest); err != nil {
		t.Fatal(err)
	}
	if err := m.runDisconnect(stop); err != nil {
		t.Fatal(err)
	}
	if err := m.runConnect(old); !errors.Is(err, context.Canceled) {
		t.Fatalf("old request: %v", err)
	}
	select {
	case <-canceled:
		t.Fatal("late disconnect canceled the newer host")
	default:
	}
	if m.store.Snapshot().LastConnected != id {
		t.Fatal("late disconnect erased the newer connection intent")
	}
}

func TestWindowsProfilesSelectionAndLegacyDeletionAreIsolated(t *testing.T) {
	m := newProfileManagerFixture(t)
	id := addProfileFixture(t, m)
	second := m.children[id]
	canceled, _ := startProfileFixture(second, nil)
	if err := m.store.SetLastConnected(id); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(second.root, "join", "identity.json.dpapi")
	before, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.command(brokerRequest{Operation: "select_profile", ProfileID: legacyConnectionProfile}); err != nil {
		t.Fatal(err)
	}
	if s := m.snapshot(); s.selectedProfile != legacyConnectionProfile || s.activeProfile != id {
		t.Fatalf("selection changed connection: %+v", s)
	}
	if err := m.command(brokerRequest{Operation: "delete", ProfileID: legacyConnectionProfile}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(identityPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("deleting legacy removed another identity", err)
	}
	select {
	case <-canceled:
		t.Fatal("deleting idle legacy stopped another profile")
	default:
	}
	index := m.store.Snapshot()
	if len(index.Profiles) != 1 || index.Profiles[0].ID != id || index.LastConnected != id {
		t.Fatalf("wrong index after legacy deletion: %+v", index)
	}
	if _, err := os.Stat(filepath.Join(m.owner.root, "join", "identity.json.dpapi")); !os.IsNotExist(err) {
		t.Fatal("deleted legacy identity remains", err)
	}
}

func TestWindowsProfilesDeleteIndexFailureRestoresIdentityAndHost(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		t.Run(map[bool]string{true: "legacy", false: "independent"}[legacy], func(t *testing.T) {
			m := newProfileManagerFixture(t)
			id := legacyConnectionProfile
			if !legacy {
				id = addProfileFixture(t, m)
			}
			old := m.children[id]
			identityPath := filepath.Join(old.root, "join", "identity.json.dpapi")
			identity, _ := os.ReadFile(identityPath)
			indexBefore, _ := os.ReadFile(m.store.indexPath())
			write := m.store.writeFile
			m.store.writeFile = func(string, []byte) error { return errors.New("demo index write failure") }
			if err := m.command(brokerRequest{Operation: "delete", ProfileID: id}); err == nil {
				t.Fatal("accepted failed index commit")
			}
			m.store.writeFile = write
			after, err := os.ReadFile(identityPath)
			if err != nil || !bytes.Equal(identity, after) {
				t.Fatal("identity was not rolled back", err)
			}
			indexAfter, _ := os.ReadFile(m.store.indexPath())
			if !bytes.Equal(indexBefore, indexAfter) {
				t.Fatal("failed deletion changed index")
			}
			child := m.children[id]
			if child == nil || child == old || child.ctx.Err() != nil || !child.snapshot().joined {
				t.Fatal("rollback retained a canceled or unjoined child")
			}
			m.start = func(child *portableGUI) { startProfileFixture(child, nil) }
			if err := m.connect(id); err != nil {
				t.Fatal("rolled back profile cannot reconnect", err)
			}
		})
	}
}

func TestWindowsProfilesOpeningAddDoesNotInitializeAnEmptyProfile(t *testing.T) {
	m := newProfileManagerFixture(t)
	writes := 0
	m.store.writeFile = func(string, []byte) error {
		writes++
		return errors.New("demo index writes disabled")
	}
	before := m.store.Snapshot()
	if err := m.dispatch(brokerRequest{Operation: "add_profile", Name: "demo-second"}); err != nil {
		t.Fatal(err)
	}
	if writes != 0 || len(m.snapshot().profiles) != len(before.Profiles) || m.snapshot().selectedProfile != before.Selected || m.snapshot().profileDraft == nil {
		t.Fatal("opening add created or selected an empty formal profile")
	}
	if err := m.dispatch(brokerRequest{Operation: "cancel_add_profile"}); err != nil {
		t.Fatal(err)
	}
	if m.snapshot().profileDraft != nil || writes != 0 {
		t.Fatal("canceling an empty panel retained a draft or wrote state")
	}
}

func TestWindowsProfilesFreshRootHasNoFormalProfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	owner := &portableGUI{root: t.TempDir(), edition: editionPortableMixed, ctx: ctx, cancel: cancel}
	m, err := newWindowsProfileManager(owner)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); m.close() })
	assertEmpty := func() {
		t.Helper()
		snapshot := m.snapshot()
		if !snapshot.profilesReady || len(snapshot.profiles) != 0 || snapshot.selectedProfile != "" || snapshot.activeProfile != "" || snapshot.joined || len(m.children) != 0 {
			t.Fatalf("fresh root created a formal profile or host: %+v", snapshot)
		}
		if m.store.Snapshot().LastConnected != "" {
			t.Fatal("fresh root acquired an auto-connect intent")
		}
	}
	assertEmpty()
	if err := m.dispatch(brokerRequest{Operation: "add_profile"}); err != nil {
		t.Fatal(err)
	}
	assertEmpty()
	if err := m.dispatch(brokerRequest{Operation: "cancel_add_profile"}); err != nil {
		t.Fatal(err)
	}
	assertEmpty()
	if _, err := os.Stat(filepath.Join(owner.root, "join")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty panel allocated an identity: %v", err)
	}
}

func TestWindowsProfilesPreferenceDoesNotBlockSnapshotOrCancel(t *testing.T) {
	m := newProfileManagerFixture(t)
	child := m.children[legacyConnectionProfile]
	canceled, _ := startProfileFixture(child, nil)
	pref := clientcore.Preference{Schema: clientcore.PreferenceSchema, Mode: clientcore.Auto}
	child.mu.Lock()
	child.routeOptions = []portableRouteOption{{Label: "demo-auto", Preference: pref}}
	child.mu.Unlock()
	control := &routeControl{requests: make(chan routeRequest), done: make(chan struct{})}
	routeControls.Store(child.root, control)
	t.Cleanup(func() { routeControls.Delete(child.root) })
	received := make(chan routeRequest, 1)
	go func() { received <- <-control.requests }()
	if err := m.dispatch(brokerRequest{Operation: "preference", ProfileID: legacyConnectionProfile, Preference: &pref}); err != nil {
		t.Fatal(err)
	}
	var request routeRequest
	select {
	case request = <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("preference did not enter activation")
	}
	defer func() {
		select {
		case request.done <- nil:
		default:
		}
	}()
	snapshotDone := make(chan struct{})
	go func() { m.snapshot(); close(snapshotDone) }()
	waitProfileSignal(t, snapshotDone)
	if err := m.dispatch(brokerRequest{Operation: "disconnect", ProfileID: legacyConnectionProfile}); err != nil {
		t.Fatal(err)
	}
	waitProfileSignal(t, canceled)
	request.done <- nil
	m.workers.Wait()
}

func TestWindowsProfilesResumeOnlyExistingProtectedJoin(t *testing.T) {
	for _, kind := range []string{"pending", "ready", "draft", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			owner := &portableGUI{root: t.TempDir(), edition: editionPortableMixed, ctx: ctx, cancel: cancel}
			// §7.2：旧版本已登记的未加入条目保留原恢复行为；全新根不再生成 legacy。
			if err := os.Mkdir(filepath.Join(owner.root, "state"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := writeWindowsJoinFile(filepath.Join(owner.root, "state", "profiles.json"), []byte(`{"schema":1,"profiles":[{"id":"legacy","name":"Loom 网络"}],"selected":"legacy","last_connected":"legacy"}`)); err != nil {
				t.Fatal(err)
			}
			m, err := newWindowsProfileManager(owner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cancel(); m.close() })
			child := m.children[legacyConnectionProfile]
			switch kind {
			case "pending":
				invite := clientenroll.Invite{Endpoint: "https://control.example/api/client/enroll", Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x23}, 32)), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
				identity, err := loadOrCreateWindowsIdentity(child.root, invite, child.protector(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				clearPreparedIdentity(&identity)
			case "ready":
				if err := clientsecret.WriteJSONProtected(windowsJoinReadyPath(child.root), windowsJoinReadyPurpose, map[string]string{"configuration": "ready"}, child.protector()); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.MkdirAll(filepath.Dir(windowsJoinIdentityPath(child.root)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(windowsJoinIdentityPath(child.root), []byte("demo-invalid-protected-material"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var resumed, starts atomic.Int32
			m.resume = func(got *portableGUI) (windowsJoinResult, error) {
				resumed.Add(1)
				if got != child {
					return windowsJoinResult{}, errors.New("wrong recovery profile")
				}
				return windowsJoinResult{NodeID: "demo-client"}, nil
			}
			m.start = func(*portableGUI) { starts.Add(1) }
			m.resumePendingProfiles()
			child.workers.Wait()
			if starts.Load() != 0 {
				t.Fatal("join recovery automatically started a host")
			}
			s := child.snapshot()
			if kind == "pending" || kind == "ready" {
				if resumed.Load() != 1 || !s.joined || s.state != guiStopped {
					t.Fatalf("protected join was not resumed into stopped state: %+v", s)
				}
			} else if resumed.Load() != 0 || s.joined || (kind == "corrupt" && s.state != guiError) {
				t.Fatalf("draft or corrupt material entered recovery: %+v", s)
			}
		})
	}
}

func TestWindowsProfilesCompletedJoinScrubsBearerKeepsIdentity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	owner := &portableGUI{root: t.TempDir(), edition: editionPortableMixed, ctx: ctx, cancel: cancel}
	writeProfileFixtureIdentity(t, owner.root)
	if err := os.Remove(windowsJoinIdentityPath(owner.root)); err != nil {
		t.Fatal(err)
	}
	invite := clientenroll.Invite{Endpoint: "https://control.example/api/client/enroll", Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x35}, 32)), ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	identity, err := loadOrCreateWindowsIdentity(owner.root, invite, owner.protector(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearPreparedIdentity(&identity)
	m, err := newWindowsProfileManager(owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); m.close() })
	m.resume = func(*portableGUI) (windowsJoinResult, error) {
		t.Error("completed join attempted network recovery")
		return windowsJoinResult{}, nil
	}
	m.resumePendingProfiles()
	if _, err := readWindowsPendingInvite(owner.root, owner.protector()); !os.IsNotExist(err) {
		t.Fatal("pending bearer remained", err)
	}
	after, err := readWindowsJoinIdentity(owner.root, owner.protector())
	if err != nil {
		t.Fatal(err)
	}
	defer clearPreparedIdentity(&after)
	if identity.RequestID != after.RequestID || !bytes.Equal(identity.PrivateKeyPEM, after.PrivateKeyPEM) {
		t.Fatal("completed join cleanup changed identity")
	}
	if !m.children[legacyConnectionProfile].snapshot().joined {
		t.Fatal("completed join cleanup lost joined state")
	}
}

func TestWindowsProfilesCorruptIndexDoesNotFallbackToLegacyHost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &portableGUI{root: t.TempDir(), edition: editionPortableMixed, ctx: ctx, cancel: cancel, profileHost: true}
	writeProfileFixtureIdentity(t, owner.root)
	indexPath := filepath.Join(owner.root, "state", "profiles.json")
	if err := os.MkdirAll(filepath.Dir(indexPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, []byte(`{"schema":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	owner.initializeProfiles()
	owner.startRuntime()
	if s := owner.snapshot(); s.state != guiError || s.joined || owner.profileManager() != nil || owner.runCancel != nil {
		t.Fatalf("corrupt index fell back to legacy runtime: %+v", s)
	}
	if body, err := os.ReadFile(windowsJoinIdentityPath(owner.root)); err != nil || string(body) != "demo-protected-identity" {
		t.Fatal("corrupt index changed legacy identity", err)
	}
}
