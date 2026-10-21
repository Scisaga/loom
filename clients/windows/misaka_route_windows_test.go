//go:build windows

package main

import (
	"sync"
	"testing"

	"loom/internal/clientmodel"
)

func lockMisakaRouteWorker(t *testing.T, child *portableGUI) func() {
	t.Helper()
	child.routeMu.Lock()
	var once sync.Once
	release := func() { once.Do(child.routeMu.Unlock) }
	t.Cleanup(release)
	return release
}

func newMisakaRouteGUITestWindow(t *testing.T) (*portableGUI, *windowsProfileManager, *portableGUI) {
	t.Helper()
	app := newProfileGUITestWindow(t)
	m := newProfileManagerFixture(t)
	app.brokerClient, app.profiles = false, m
	m.owner = app
	child := m.children[legacyConnectionProfile]
	child.mu.Lock()
	child.joined, child.state, child.routeSelected = true, guiStopped, 0
	child.routeOptions = []portableRouteOption{}
	for _, id := range []string{"demo-policy-a", "demo-policy-b", "demo-policy-c"} {
		preference := clientmodel.Preference{Schema: 3, Services: []clientmodel.ServicePreference{{ServiceID: "demo-a", PolicyID: id}, {ServiceID: "demo-b", PolicyID: "demo-unchanged-policy"}}}
		child.routeOptions = append(child.routeOptions, portableRouteOption{Label: "Demo service / " + id, ServiceID: "demo-a", PolicyID: id, Preference: preference})
	}

	child.mu.Unlock()
	app.renderControls()
	return app, m, child
}

func assertMisakaRoutePickerVisible(t *testing.T, app *portableGUI, want bool) {
	t.Helper()
	if visible := profileGUIStyle(app.controls.routeCombo)&portableWSVisible != 0; visible != want {
		t.Fatalf("policy picker visibility=%v, wanted=%v", visible, want)
	}
}

func finishMisakaRouteTestRequest(t *testing.T, app *portableGUI, m *windowsProfileManager) {
	t.Helper()
	sequence := app.skin.route.sequence
	m.workers.Wait()
	// §7.2：通过实际窗口消息交付完成通知，不把 worker 入队当成偏好提交。
	procSendMessage.Call(app.hwnd, misakaWMRouteAcknowledged, sequence, 0)
	app.renderControls()
	if app.skin.route.pending != nil {
		t.Fatal("[§7.2] worker 完成后界面仍停留在待确认状态")
	}
}

func TestGUIMisakaServicePolicyNavigationRequiresConfirmation(t *testing.T) {
	app, m, child := newMisakaRouteGUITestWindow(t)
	assertMisakaRoutePickerVisible(t, app, true)
	if len(app.routeVisible) != 3 {
		t.Fatal("service policies missing from native picker")
	}
	procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, 1, 0)
	procSendMessage.Call(app.hwnd, portableWMCommand, portableControlRoute|portableCBNSelChange<<16, app.controls.routeCombo)
	app.cancelMisakaRoutePicker()
	if child.snapshot().routeSelected != 0 || app.skin.route.pending != nil {
		t.Fatal("navigation persisted an unconfirmed policy")
	}
	procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, 1, 0)
	procSendMessage.Call(app.hwnd, portableWMCommand, portableControlRoute|portableCBNSelEndOK<<16, app.controls.routeCombo)
	finishMisakaRouteTestRequest(t, app, m)
	snapshot := child.snapshot()
	if snapshot.routeSelected != 1 || snapshot.routeOptions[1].Preference.Policy("demo-b") != "demo-unchanged-policy" {
		t.Fatal("Service choice changed another Service")
	}
}
