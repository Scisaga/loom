//go:build windows

package main

import (
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"loom/internal/clientcore"
)

const misakaWMRouteAcknowledged = 0x8005

// §7.2：这只是编辑器状态；按钮高亮与实际选路始终来自宿主确认的快照。
type misakaRouteUI struct {
	list         uintptr
	profileID    string
	sequence     uintptr
	picker       bool
	pending      *clientcore.Preference
	acknowledged bool
	options      []portableRouteOption
}

type misakaComboInfo struct {
	size              uint32
	item, button      portableRect
	state             uint32
	combo, edit, list uintptr
}

// §7.2：焦点可留在出口框，滚轮归属仍按鼠标位置判断；导航不能提交偏好。
func (app *portableGUI) misakaRouteWheel(hwnd, wParam, lParam uintptr) (uintptr, bool) {
	parent, _, _ := portableUser32.NewProc("GetParent").Call(hwnd)
	combo, list := app.controls.routeCombo, app.skin.route.list
	if hwnd != app.skin.pane && hwnd != combo && hwnd != list && parent != app.skin.pane {
		return 0, false
	}
	x, y := int32(int16(lParam)), int32(int16(lParam>>16))
	inside := func(window uintptr) bool {
		var r portableRect
		procMisakaGetWindowRect.Call(window, uintptr(unsafe.Pointer(&r)))
		return x >= r.left && x < r.right && y >= r.top && y < r.bottom
	}
	dropped, _, _ := procSendMessage.Call(combo, 0x0157, 0, 0)
	if dropped != 0 && list != 0 && inside(list) {
		if hwnd == combo || hwnd == list {
			return 0, false
		}
		result, _, _ := procSendMessage.Call(list, 0x020A, wParam, lParam)
		return result, true
	}
	if !inside(app.skin.pane) {
		return 0, hwnd == combo || hwnd == list
	}
	if dropped != 0 || app.skin.route.picker || app.routeFiltering {
		app.cancelMisakaRoutePicker()
	}
	if hwnd != app.skin.pane {
		result, _, _ := procSendMessage.Call(app.skin.pane, 0x020A, wParam, lParam)
		return result, true
	}
	return 0, false
}

func (app *portableGUI) misakaRouteVisible(snapshot portableGUISnapshot) bool {
	if app.skin == nil || !snapshot.joined || snapshot.profileDraft != nil {
		return false
	}
	route := &app.skin.route
	if route.pending != nil {
		return route.pending.Mode == clientcore.FixedExit
	}
	return route.picker || misakaSelectedMode(snapshot) == clientcore.FixedExit
}

func (app *portableGUI) misakaRouteSelectable(snapshot portableGUISnapshot) bool {
	return snapshot.joined && snapshot.profileDraft == nil && portableRouteSelectable(snapshot) && app.skin.route.pending == nil
}

func (app *portableGUI) misakaRouteLayoutChanged(snapshot portableGUISnapshot) bool {
	if app.skin == nil || app.controls.routeCombo == 0 {
		return false
	}
	style, _, _ := procMisakaGetWindowLong.Call(app.controls.routeCombo, ^uintptr(15)) // GWL_STYLE
	visible := style&portableWSVisible != 0
	return visible != app.misakaRouteVisible(snapshot)
}

// §7.2：偏好等待与确认只更新局部状态；没有可见性变化时不得重排整个右侧面板。
func (app *portableGUI) syncMisakaRouteLayout(snapshot portableGUISnapshot) {
	if app.misakaRouteLayoutChanged(snapshot) {
		app.layoutControls()
	}
}

// §7.2：必须在布局和快照相等短路之前收敛，避免拿旧编辑状态布局新偏好。
func (app *portableGUI) reconcileMisakaRoute(snapshot portableGUISnapshot) bool {
	if app.skin == nil {
		return false
	}
	route := &app.skin.route
	visible := app.misakaRouteVisible(snapshot)
	changed := false
	if route.profileID != snapshot.selectedProfile {
		route.profileID = snapshot.selectedProfile
		route.sequence++
		route.picker, route.pending, route.acknowledged = false, nil, false
		app.closeMisakaRouteDropDown()
		changed = true
	}
	if route.pending != nil && route.acknowledged && !snapshot.routeBusy {
		route.pending, route.acknowledged, route.picker = nil, false, false
		changed = true
	}
	hasFixed := slices.ContainsFunc(snapshot.routeOptions, func(option portableRouteOption) bool { return option.Preference.Mode == clientcore.FixedExit })
	if route.picker && (!app.misakaRouteSelectable(snapshot) || !hasFixed) {
		route.picker = false
		app.closeMisakaRouteDropDown()
		changed = true
	}
	return changed || visible != app.misakaRouteVisible(snapshot)
}

func (app *portableGUI) closeMisakaRouteDropDown() {
	updating := app.routeUpdating
	app.routeUpdating = true
	procSendMessage.Call(app.controls.routeCombo, portableCBShowDropDown, 0, 0)
	app.routeUpdating = updating
	app.routeFiltering, app.routeFilter = false, ""
}

func (app *portableGUI) cancelMisakaRoutePicker() {
	if app.skin == nil || app.routeUpdating {
		return
	}
	snapshot := app.snapshot()
	app.skin.route.picker = false
	app.closeMisakaRouteDropDown()
	app.renderRouteCombo(snapshot)
	app.syncMisakaRouteLayout(snapshot)
}

func (app *portableGUI) misakaRouteFilterKey(message portableMSG) bool {
	if message.msg != portableWMKeyDown {
		return false
	}
	switch message.wParam {
	case portableVKEscape:
		app.cancelMisakaRoutePicker()
		return true
	case portableVKReturn:
		if app.routeFiltering {
			selection, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
			if selection == ^uintptr(0) && len(app.routeVisible) == 1 {
				procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, 0, 0)
			}
		}
		app.commitMisakaRouteSelection()
		return true
	}
	return false
}

func (app *portableGUI) misakaRouteCommand(id uint16) bool {
	if id != misakaControlAuto && id != misakaControlFixed && id != misakaControlDirect {
		return false
	}
	snapshot := app.snapshot()
	if !app.misakaRouteSelectable(snapshot) {
		return true
	}
	mode := clientcore.Auto
	if id == misakaControlFixed {
		mode = clientcore.FixedExit
	} else if id == misakaControlDirect {
		mode = clientcore.Direct
	}
	index := slices.IndexFunc(snapshot.routeOptions, func(option portableRouteOption) bool { return option.Preference.Mode == mode })
	if index < 0 {
		return true
	}
	app.closeMisakaRouteDropDown()
	if mode == clientcore.FixedExit {
		app.skin.route.picker = true
		app.renderRouteCombo(snapshot)
		app.syncMisakaRouteLayout(snapshot)
		procMisakaSetFocus.Call(app.controls.routeCombo)
		procSendMessage.Call(app.controls.routeCombo, portableCBShowDropDown, 1, 0)
		return true
	}
	app.skin.route.picker = false
	app.submitMisakaRoutePreference(snapshot, snapshot.routeOptions[index].Preference)
	return true
}

// §7.2：导航候选不是确认；Esc 必须能撤销整个 Fixed 编辑而不触发任何偏好写入。
func (app *portableGUI) misakaRouteNotification(notification uint16) {
	if app.routeUpdating {
		return
	}
	switch notification {
	case portableCBNSelEndOK:
		app.commitMisakaRouteSelection()
	case portableCBNSelEndCancel, 4: // CBN_KILLFOCUS：离开编辑时恢复未经确认的键盘导航。
		app.cancelMisakaRoutePicker()
	}
}

func (app *portableGUI) commitMisakaRouteSelection() {
	snapshot := app.snapshot()
	if !app.misakaRouteSelectable(snapshot) || !app.misakaRouteVisible(snapshot) || !slices.Equal(app.skin.route.options, snapshot.routeOptions) {
		return
	}
	selection, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
	if selection == ^uintptr(0) || int(selection) >= len(app.routeVisible) {
		app.cancelMisakaRoutePicker()
		return
	}
	index := app.routeVisible[selection]
	if index < 0 || index >= len(snapshot.routeOptions) || snapshot.routeOptions[index].Preference.Mode != clientcore.FixedExit {
		return
	}
	app.submitMisakaRoutePreference(snapshot, snapshot.routeOptions[index].Preference)
}

func (app *portableGUI) submitMisakaRoutePreference(snapshot portableGUISnapshot, preference clientcore.Preference) {
	if !app.misakaRouteSelectable(snapshot) || routeOptionIndex(snapshot.routeOptions, preference) < 0 {
		return
	}
	app.closeMisakaRouteDropDown()
	route := &app.skin.route
	route.picker = false
	if snapshot.routeSelected == routeOptionIndex(snapshot.routeOptions, preference) {
		app.renderRouteCombo(snapshot)
		app.syncMisakaRouteLayout(snapshot)
		return
	}
	route.sequence++
	route.profileID, route.pending, route.acknowledged = snapshot.selectedProfile, &preference, false
	sequence := route.sequence
	app.renderRouteCombo(snapshot)
	app.syncMisakaRouteLayout(snapshot)
	app.renderMisakaRoutes(snapshot, &snapshot)
	req := brokerRequest{Operation: "preference", ProfileID: snapshot.selectedProfile, Preference: &preference}
	app.dispatchMisakaRoutePreference(req, sequence)
}

func (app *portableGUI) dispatchMisakaRoutePreference(req brokerRequest, sequence uintptr) {
	if app.brokerClient {
		app.workers.Add(1)
		go func() {
			defer app.workers.Done()
			app.exchangeInstalledBroker(req)
			postPortableMessage(app.hwnd, misakaWMRouteAcknowledged, sequence, 0)
		}()
		return
	}
	complete := func() { postPortableMessage(app.hwnd, misakaWMRouteAcknowledged, sequence, 0) }
	m := app.profileManager()
	if m == nil {
		complete()
		return
	}
	if err := m.dispatchWithCompletion(req, complete); err != nil {
		app.profileError(err)
		complete()
	}
}

func (app *portableGUI) acknowledgeMisakaRoute(sequence uintptr) {
	if app.skin == nil || app.skin.route.sequence != sequence || app.skin.route.profileID != app.snapshot().selectedProfile || app.skin.route.pending == nil {
		return
	}
	app.skin.route.acknowledged = true
	app.renderControls()
}

func (app *portableGUI) renderMisakaRoutes(snapshot portableGUISnapshot, previous *portableGUISnapshot) {
	selectable := app.misakaRouteSelectable(snapshot)
	if !selectable && app.routeFiltering {
		app.closeMisakaRouteDropDown()
	}
	if previous == nil || previous.routeSelected != snapshot.routeSelected || !slices.Equal(previous.routeOptions, snapshot.routeOptions) {
		app.renderRouteCombo(snapshot)
	}
	for _, pair := range []struct {
		hwnd uintptr
		mode clientcore.Mode
	}{{app.controls.modeAuto, clientcore.Auto}, {app.controls.modeFixed, clientcore.FixedExit}, {app.controls.modeDirect, clientcore.Direct}} {
		available := slices.ContainsFunc(snapshot.routeOptions, func(option portableRouteOption) bool { return option.Preference.Mode == pair.mode })
		enablePortableControl(pair.hwnd, selectable && available)
		if previous == nil || previous.routeSelected != snapshot.routeSelected || previous.routeBusy != snapshot.routeBusy {
			procInvalidateRect.Call(pair.hwnd, 0, 0)
		}
	}
	enablePortableControl(app.controls.routeCombo, selectable)
}

// §7.2：用完整已授权选项构造索引；仅选择变化不重建下拉，避免原生弹出层反复销毁。
func (app *portableGUI) renderMisakaRouteCombo(snapshot portableGUISnapshot) {
	app.routeUpdating = true
	defer func() { app.routeUpdating = false }()
	var visible []int
	query := strings.ToLower(app.routeFilter)
	for index, option := range snapshot.routeOptions {
		if option.Preference.Mode == clientcore.FixedExit && (!app.routeFiltering || strings.Contains(strings.ToLower(option.Label), query)) {
			visible = append(visible, index)
		}
	}
	if !slices.Equal(app.skin.route.options, snapshot.routeOptions) || !slices.Equal(app.routeVisible, visible) {
		procSendMessage.Call(app.controls.routeCombo, portableCBResetContent, 0, 0)
		for _, index := range visible {
			label, _ := windows.UTF16PtrFromString(snapshot.routeOptions[index].Label)
			procSendMessage.Call(app.controls.routeCombo, portableCBAddString, 0, uintptr(unsafe.Pointer(label)))
			runtime.KeepAlive(label)
		}
		app.routeVisible = visible
		app.skin.route.options = slices.Clone(snapshot.routeOptions)
	}
	selected := -1
	if !app.routeFiltering {
		index := snapshot.routeSelected
		if pending := app.skin.route.pending; pending != nil {
			index = routeOptionIndex(snapshot.routeOptions, *pending)
		}
		selected = slices.Index(app.routeVisible, index)
	}
	current, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
	if int(current) != selected {
		procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, uintptr(selected), 0)
	}
}
