//go:build windows

package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"loom/internal/clientcore"
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
	child.routeOptions = []portableRouteOption{
		{Label: "自动", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.Auto}},
		{Label: "固定出口 · demo-exit", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-exit"}},
		{Label: "直连", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.Direct}},
	}
	child.mu.Unlock()
	app.renderControls()
	return app, m, child
}

func assertMisakaRoutePickerVisible(t *testing.T, app *portableGUI, want bool) {
	t.Helper()
	if visible := profileGUIStyle(app.controls.routeCombo)&portableWSVisible != 0; visible != want {
		t.Fatalf("[§7.2] 出口选择可见=%v，预期=%v；实际模式=%s", visible, want, misakaSelectedMode(app.snapshot()))
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

func TestGUIMisakaRouteFixedNavigationAndEscapeDoNotPersist(t *testing.T) {
	app, m, child := newMisakaRouteGUITestWindow(t)
	procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlFixed, app.controls.modeFixed)
	assertMisakaRoutePickerVisible(t, app, true)
	if len(app.routeVisible) != 1 || app.snapshot().routeOptions[app.routeVisible[0]].Preference.Mode != clientcore.FixedExit {
		t.Fatal("[§7.2] Fixed 下拉混入了非签名出口选项")
	}
	procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, 0, 0)
	procSendMessage.Call(app.hwnd, portableWMCommand, portableControlRoute|portableCBNSelChange<<16, app.controls.routeCombo)
	m.workers.Wait()
	if _, err := os.Stat(filepath.Join(child.root, "state", "preference.json")); !os.IsNotExist(err) {
		t.Fatal("[§7.2] 导航候选提前写入了偏好")
	}
	if !handlePortableRouteFilter(portableMSG{hwnd: app.controls.routeCombo, msg: portableWMKeyDown, wParam: portableVKEscape}) {
		t.Fatal("[§7.2] 未输入过滤文字时 Esc 没有取消 Fixed 编辑")
	}
	assertMisakaRoutePickerVisible(t, app, false)
	if app.skin.route.pending != nil || misakaSelectedMode(app.snapshot()) != clientcore.Auto {
		t.Fatal("[§7.2] 取消 Fixed 改变了实际偏好")
	}
}

func TestGUIMisakaRouteFixedDirectAutoHasOneCommitAndStablePolling(t *testing.T) {
	app, m, child := newMisakaRouteGUITestWindow(t)
	for cycle := 0; cycle < 3; cycle++ {
		procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlFixed, app.controls.modeFixed)
		procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, 0, 0)
		procSendMessage.Call(app.hwnd, portableWMCommand, portableControlRoute|portableCBNSelEndOK<<16, app.controls.routeCombo)
		sequence := app.skin.route.sequence
		procSendMessage.Call(app.hwnd, portableWMCommand, portableControlRoute|portableCBNSelEndOK<<16, app.controls.routeCombo)
		if app.skin.route.sequence != sequence {
			t.Fatal("[§7.2] 同一候选的重复通知提交了第二次写入")
		}
		finishMisakaRouteTestRequest(t, app, m)
		assertMisakaRoutePickerVisible(t, app, true)
		if misakaSelectedMode(app.snapshot()) != clientcore.FixedExit {
			t.Fatal("[§7.2] Fixed 的真实偏好未保存")
		}
		release := lockMisakaRouteWorker(t, child)
		procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlDirect, app.controls.modeDirect)
		assertMisakaRoutePickerVisible(t, app, false)
		// §7.2：后台写入被阻塞时，GUI 仍可完成快照、布局和焦点通知处理。
		app.renderControls()
		procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlFixed|7<<16, app.controls.modeFixed)
		assertMisakaRoutePickerVisible(t, app, false)
		sequence = app.skin.route.sequence
		procSendMessage.Call(app.hwnd, misakaWMRouteAcknowledged, sequence, 0)
		if app.skin.route.pending == nil || !app.snapshot().routeBusy {
			t.Fatal("[§7.2] 后台仍忙时异步 ACK 被当成完成")
		}
		release()
		finishMisakaRouteTestRequest(t, app, m)
		assertMisakaRoutePickerVisible(t, app, false)
		if misakaSelectedMode(app.snapshot()) != clientcore.Direct {
			t.Fatal("[§7.2] Direct 的真实偏好未保存")
		}
		procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlAuto, app.controls.modeAuto)
		finishMisakaRouteTestRequest(t, app, m)
		assertMisakaRoutePickerVisible(t, app, false)
		if misakaSelectedMode(app.snapshot()) != clientcore.Auto {
			t.Fatal("[§7.2] Auto 的真实偏好未保存")
		}
	}
	writes := recordProfileGUIWrites(t, app)
	for poll := 0; poll < 20; poll++ {
		app.renderControls()
	}
	if len(*writes) != 0 {
		t.Fatalf("[§7.2] 稳定轮询仍产生 %d 次无关原生写入", len(*writes))
	}
}

func TestGUIMisakaRouteFailedSaveRestoresActualSelection(t *testing.T) {
	app, m, child := newMisakaRouteGUITestWindow(t)
	if err := os.MkdirAll(filepath.Join(child.root, "state", "preference.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlDirect, app.controls.modeDirect)
	finishMisakaRouteTestRequest(t, app, m)
	assertMisakaRoutePickerVisible(t, app, false)
	if misakaSelectedMode(app.snapshot()) != clientcore.Auto || app.snapshot().detail == "" {
		t.Fatal("[§7.2] 写入失败被显示为已选 Direct，或缺少失败原因")
	}
	for _, control := range []uintptr{app.controls.modeAuto, app.controls.modeFixed, app.controls.modeDirect} {
		if enabled, _, _ := procIsWindowEnabled.Call(control); enabled == 0 {
			t.Fatal("[§7.2] 写入失败后模式按钮仍被锁住")
		}
	}
}

func TestGUIMisakaRouteFocusLossRestoresUnconfirmedExit(t *testing.T) {
	app, m, child := newMisakaRouteGUITestWindow(t)
	child.mu.Lock()
	child.routeOptions = append(child.routeOptions, portableRouteOption{
		Label: "固定出口 · demo-other", Preference: clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-other"},
	})
	child.routeSelected = 1
	child.mu.Unlock()
	app.renderControls()
	procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, 1, 0)
	procSendMessage.Call(app.hwnd, portableWMCommand, portableControlRoute|portableCBNSelChange<<16, app.controls.routeCombo)
	procSendMessage.Call(app.hwnd, portableWMCommand, portableControlRoute|4<<16, app.controls.routeCombo)
	m.workers.Wait()
	selection, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
	if selection != 0 || app.snapshot().routeSelected != 1 || app.skin.route.pending != nil {
		t.Fatal("[§7.2] 离开下拉后保留了未确认的候选，或将导航误保存")
	}
	assertMisakaRoutePickerVisible(t, app, true)
}

func TestGUIMisakaRouteLateCompletionCannotModifyAnotherProfile(t *testing.T) {
	app, m, child := newMisakaRouteGUITestWindow(t)
	otherID := addProfileFixture(t, m)
	other := m.children[otherID]
	other.joined, other.state, other.routeSelected = true, guiStopped, 0
	other.routeOptions = append([]portableRouteOption(nil), child.routeOptions...)
	if err := m.store.Select(legacyConnectionProfile); err != nil {
		t.Fatal(err)
	}
	app.renderControls()
	release := lockMisakaRouteWorker(t, child)
	procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlDirect, app.controls.modeDirect)
	oldSequence := app.skin.route.sequence
	if err := m.command(brokerRequest{Operation: "select_profile", ProfileID: otherID}); err != nil {
		t.Fatal(err)
	}
	app.renderControls()
	if app.skin.route.pending != nil || app.skin.route.sequence == oldSequence {
		t.Fatal("[§7.2] 查看另一配置仍继承旧请求代次")
	}
	release()
	m.workers.Wait()
	procSendMessage.Call(app.hwnd, misakaWMRouteAcknowledged, oldSequence, 0)
	app.renderControls()
	if snapshot := app.snapshot(); snapshot.selectedProfile != otherID || misakaSelectedMode(snapshot) != clientcore.Auto || app.skin.route.pending != nil {
		t.Fatal("[§7.2] 迟到完成通知改变了另一份配置")
	}
	assertMisakaRoutePickerVisible(t, app, false)
}

func TestGUIMisakaRouteRevokedFixedOptionsCloseTheEditor(t *testing.T) {
	app, _, child := newMisakaRouteGUITestWindow(t)
	procSendMessage.Call(app.hwnd, portableWMCommand, misakaControlFixed, app.controls.modeFixed)
	assertMisakaRoutePickerVisible(t, app, true)
	child.mu.Lock()
	child.routeOptions = []portableRouteOption{child.routeOptions[0], child.routeOptions[2]}
	child.mu.Unlock()
	app.renderControls()
	assertMisakaRoutePickerVisible(t, app, false)
	if app.skin.route.picker || len(app.routeVisible) != 0 {
		t.Fatal("[§7.2] 授权候选变化后仍显示已撤销出口")
	}
	if enabled, _, _ := procIsWindowEnabled.Call(app.controls.modeFixed); enabled != 0 {
		t.Fatal("[§7.2] 当前签名配置没有 Fixed 候选却仍允许编辑")
	}
}

func TestWindowsProfilePreferenceBusyCoversTheWholeWorker(t *testing.T) {
	m := newProfileManagerFixture(t)
	child := m.children[legacyConnectionProfile]
	preference := clientcore.Preference{Schema: 1, Mode: clientcore.Direct}
	child.joined, child.state = true, guiStopped
	child.routeOptions = []portableRouteOption{{Label: "直连", Preference: preference}}
	child.routeSelected = -1
	release := lockMisakaRouteWorker(t, child)
	done := make(chan struct{})
	request := brokerRequest{Operation: "preference", ProfileID: legacyConnectionProfile, Preference: &preference}
	if err := m.dispatchWithCompletion(request, func() { close(done) }); err != nil {
		t.Fatal(err)
	}
	if !m.snapshot().routeBusy {
		t.Fatal("[§7.2] broker 接收请求时没有同步发布 routeBusy")
	}
	// §7.2：激活中途的 routeReady 不能让最终持久化或回滚前的状态被当作完成。
	child.mu.Lock()
	child.routeBusy = false
	child.mu.Unlock()
	if !m.snapshot().routeBusy {
		t.Fatal("[§7.2] 中间 readback 清掉了整个偏好事务的忙状态")
	}
	if err := m.dispatch(request); err == nil {
		t.Fatal("[§7.2] 同一配置的未完成偏好请求允许重复入队")
	}
	select {
	case <-done:
		t.Fatal("[§7.2] worker 尚未执行就发出了完成通知")
	default:
	}
	release()
	waitProfileSignal(t, done)
	m.workers.Wait()
	if snapshot := m.snapshot(); snapshot.routeBusy || misakaSelectedMode(snapshot) != clientcore.Direct {
		t.Fatal("[§7.2] 最终完成没有发布真实偏好并清除忙状态")
	}
}

func TestGUIMisakaRouteUnchangedGeometryDoesNotRelayoutOnClickOrAck(t *testing.T) {
	app, manager, child := newMisakaRouteGUITestWindow(t)
	writes := recordProfileGUIWrites(t, app)
	for click := 0; click < 5; click++ {
		app.misakaRouteCommand(misakaControlAuto)
	}
	if len(*writes) != 0 {
		t.Fatal("[§7.2] 点击已经确认的模式仍重新布局或改写控件")
	}
	release := lockMisakaRouteWorker(t, child)
	app.misakaRouteCommand(misakaControlDirect)
	app.renderControls()
	release()
	finishMisakaRouteTestRequest(t, app, manager)
	for _, write := range *writes {
		if write.message == 0x0046 {
			t.Fatal("[§7.2] Auto 到 Direct 的等待或 ACK 在几何不变时仍移动了控件")
		}
	}
	if misakaSelectedMode(app.snapshot()) != clientcore.Direct {
		t.Fatal("[§7.2] 减少重绘丢失了实际模式确认")
	}
}
