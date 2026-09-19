//go:build windows

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"loom/internal/clientmodel"
)

func setSyntheticUIRoutePreference(child *portableGUI, preference clientmodel.Preference) error {
	child.routeMu.Lock()
	defer child.routeMu.Unlock()
	child.mu.Lock()
	defer child.mu.Unlock()
	index := routeOptionIndex(child.routeOptions, preference)
	if index < 0 {
		return errors.New("preference is not authorized by the displayed LKG projection")
	}
	child.routeSelected = index
	return nil
}

// These fixtures exercise the established native profile interactions without
// inventing a second identity authority. Joined state is synthetic UI input;
// DPAPI persistence is covered independently by the protected-store tests.
func newProfileManagerFixture(t *testing.T) *windowsProfileManager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	owner := &portableGUI{root: t.TempDir(), edition: editionPortableMixed, ctx: ctx, cancel: cancel, hostname: "demo-client"}
	m, err := newWindowsProfileManager(owner)
	if err != nil {
		t.Fatal(err)
	}
	m.setPreference = setSyntheticUIRoutePreference
	index := connectionProfileIndex{Schema: connectionProfileSchema,
		Profiles: []connectionProfile{{ID: legacyConnectionProfile, Name: "演示网络甲"}},
		Selected: legacyConnectionProfile, LastConnected: legacyConnectionProfile}
	if err := m.store.save(index); err != nil {
		t.Fatal(err)
	}
	child, err := m.makeChild(legacyConnectionProfile)
	if err != nil {
		t.Fatal(err)
	}
	child.joined, child.deviceID, child.state = true, "demo-device-a", guiStopped
	m.children[legacyConnectionProfile] = child
	t.Cleanup(func() { cancel(); m.close() })
	return m
}

func addProfileFixture(t *testing.T, m *windowsProfileManager) string {
	t.Helper()
	profile, err := m.store.Add("演示网络乙")
	if err != nil {
		t.Fatal(err)
	}
	child, err := m.makeChild(profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	child.joined, child.deviceID, child.state = true, "demo-device-b", guiStopped
	m.children[profile.ID] = child
	return profile.ID
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
