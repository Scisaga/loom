//go:build windows

package main

import (
	"slices"
	"unsafe"
)

const (
	misakaProfileStart uintptr = 1 + iota
	misakaProfileRename
	misakaProfileDelete
)

type misakaProfileAction struct {
	command uintptr
	label   string
	enabled bool
}

func misakaProfileActions(profile windowsProfileDisplay) []misakaProfileAction {
	primary := misakaProfileAction{misakaProfileStart, "启动", profile.DeviceID != ""}
	switch profile.State {
	case guiConnected:
		primary.label = "断开"
	case guiStarting:
		primary.label = "取消连接"
	case guiNeedsElevation:
		primary.label = "管理员启动"
	case guiLoading, guiJoining, guiStopping:
		primary.label, primary.enabled = "正在处理…", false
	}
	return []misakaProfileAction{primary, {misakaProfileRename, "重命名\tF2", true}, {misakaProfileDelete, "删除配置…", misakaProfileDeletable(profile.State)}}
}

func misakaProfileDeletable(state portableGUIState) bool {
	return state == guiStopped || state == guiError || state == guiNeedsElevation || state == guiNeedsJoin
}

func (app *portableGUI) misakaProfile(id string) (windowsProfileDisplay, bool) {
	profiles := app.snapshot().profiles
	index := slices.IndexFunc(profiles, func(p windowsProfileDisplay) bool { return p.ID == id })
	if index < 0 {
		return windowsProfileDisplay{}, false
	}
	return profiles[index], true
}

// §7.2：鼠标和键盘共用原生菜单；操作绑定点击时的配置 ID，不借用异步 broker 的旧选中项。
func (app *portableGUI) misakaProfileMenuTarget(lParam uintptr) (string, portablePoint) {
	var point portablePoint
	var index uintptr
	if int32(lParam) == -1 {
		index, _, _ = procSendMessage.Call(app.controls.networkList, portableLBGetCurSel, 0, 0)
		var rect portableRect
		if result, _, _ := procSendMessage.Call(app.controls.networkList, 0x0198, index, uintptr(unsafe.Pointer(&rect))); result == ^uintptr(0) {
			return "", point
		}
		point = portablePoint{rect.left + app.scale(20), rect.bottom}
		procMisakaMapPoints.Call(app.controls.networkList, 0, uintptr(unsafe.Pointer(&point)), 1)
	} else {
		point = portablePoint{int32(int16(lParam & 0xffff)), int32(int16((lParam >> 16) & 0xffff))}
		local := point
		procMisakaMapPoints.Call(0, app.controls.networkList, uintptr(unsafe.Pointer(&local)), 1)
		result, _, _ := procSendMessage.Call(app.controls.networkList, 0x01A9, 0, uintptr(uint32(uint16(local.x))|uint32(uint16(local.y))<<16))
		if result>>16 != 0 {
			return "", point
		}
		index = result & 0xffff
		var row portableRect
		if result, _, _ := procSendMessage.Call(app.controls.networkList, 0x0198, index, uintptr(unsafe.Pointer(&row))); result == ^uintptr(0) || local.y < row.top || local.y >= row.bottom {
			return "", point
		}
	}
	profiles := app.snapshot().profiles
	if index >= uintptr(len(profiles)) {
		return "", point
	}
	return profiles[index].ID, point
}

func (app *portableGUI) createMisakaProfileMenu(id string) uintptr {
	profile, ok := app.misakaProfile(id)
	if !ok {
		return 0
	}
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return 0
	}
	for _, action := range misakaProfileActions(profile) {
		if action.command == misakaProfileDelete {
			procAppendMenu.Call(menu, portableMFSeparator, 0, 0)
		}
		flags := uintptr(portableMFString)
		if !action.enabled {
			flags |= portableMFGrayED
		}
		appendPortableMenuText(menu, flags, action.command, action.label)
	}
	return menu
}

func (app *portableGUI) showMisakaListContextMenu(lParam uintptr) {
	if app.snapshot().profileDraft != nil || app.isElevationPending() {
		return
	}
	app.finishMisakaRename(false)
	id, point := app.misakaProfileMenuTarget(lParam)
	menu := app.createMisakaProfileMenu(id)
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	profiles := app.snapshot().profiles
	index := slices.IndexFunc(profiles, func(p windowsProfileDisplay) bool { return p.ID == id })
	if index >= 0 {
		procSendMessage.Call(app.controls.networkList, portableLBSetCurSel, uintptr(index), 0)
	}
	app.profileCommand(brokerRequest{Operation: "select_profile", ProfileID: id})
	procSetForegroundWindow.Call(app.hwnd)
	command, _, _ := procTrackPopupMenu.Call(menu, portableTPMRightButton|portableTPMReturnCmd, uintptr(point.x), uintptr(point.y), 0, app.hwnd, 0)
	app.misakaProfileAction(id, command)
	postPortableMessage(app.hwnd, portableWMNull, 0, 0)
}

func (app *portableGUI) misakaProfileAction(id string, command uintptr) {
	profile, ok := app.misakaProfile(id)
	if !ok || app.snapshot().profileDraft != nil || app.isElevationPending() {
		return
	}
	actions := misakaProfileActions(profile)
	index := slices.IndexFunc(actions, func(action misakaProfileAction) bool { return action.command == command })
	if index < 0 || !actions[index].enabled {
		return
	}
	switch command {
	case misakaProfileStart:
		if profile.State == guiConnected || profile.State == guiStarting {
			app.profileCommand(brokerRequest{Operation: "disconnect", ProfileID: id})
		} else if profile.State == guiNeedsElevation {
			app.restartElevatedFor(id)
		} else {
			app.profileCommand(brokerRequest{Operation: "connect", ProfileID: id})
		}
	case misakaProfileRename:
		app.beginMisakaRenameFor(id)
	case misakaProfileDelete:
		app.deleteLocalDevice(id)
	}
}

func (app *portableGUI) beginMisakaRenameFor(id string) {
	profile, ok := app.misakaProfile(id)
	if !ok || app.snapshot().profileDraft != nil || app.isElevationPending() {
		return
	}
	app.skin.rename, app.skin.renameID = true, profile.ID
	setPortableControlText(app.controls.profileNameEdit, profile.Name)
	app.layoutControls()
	procMisakaSetFocus.Call(app.controls.profileNameEdit)
	procSendMessage.Call(app.controls.profileNameEdit, 0x00B1, 0, ^uintptr(0))
}
