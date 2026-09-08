//go:build windows

package main

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"loom/internal/clientcore"
	"loom/internal/clientenroll"
	"loom/internal/clientjoin"
)

const (
	misakaControlAuto = 4201 + iota
	misakaControlFixed
	misakaControlDirect
	misakaControlMenu
	misakaControlDraftName
	misakaControlDraftImport
	misakaControlDraftPaste
	misakaControlDraftSubmit
	misakaControlDraftCancel
)

const (
	misakaBackground = 0xFCFCFB
	misakaSidebar    = 0xF7F8F7
	misakaWhite      = 0xFFFFFF
	misakaText       = 0x181B1A
	misakaMuted      = 0x717674
	misakaBorder     = 0xE4E7E5
	misakaGreen      = 0x239B68
	misakaGreenLight = 0xEEF8F3
	misakaAmber      = 0xA66A14
	misakaRed        = 0xC04444
)

type misakaUI struct {
	canvas         *misakaCanvas
	brushes        map[uint32]uintptr
	width, height  int32
	rename         bool
	renameID       string
	menu           bool
	menuProfileID  string
	fixedPicker    bool
	draftInvite    *clientenroll.Invite
	draftError     string
	inviteLabel    string
	hoverCaption   int
	pressedCaption int
	paintFailures  int
	paintError     string
	lastPaths      []windowsPathDisplay
	pathsText      string
	closed         bool
}

var (
	misakaDWM                 = windows.NewLazySystemDLL("dwmapi.dll")
	misakaComctl              = windows.NewLazySystemDLL("comctl32.dll")
	procMisakaSetSubclass     = misakaComctl.NewProc("SetWindowSubclass")
	procMisakaDefSubclass     = misakaComctl.NewProc("DefSubclassProc")
	procMisakaRemoveSubclass  = misakaComctl.NewProc("RemoveWindowSubclass")
	misakaSubclassCallback    uintptr
	procMisakaBeginPaint      = portableUser32.NewProc("BeginPaint")
	procMisakaEndPaint        = portableUser32.NewProc("EndPaint")
	procMisakaGetWindowRect   = portableUser32.NewProc("GetWindowRect")
	procMisakaMapPoints       = portableUser32.NewProc("MapWindowPoints")
	procMisakaSetFocus        = portableUser32.NewProc("SetFocus")
	procMisakaIsZoomed        = portableUser32.NewProc("IsZoomed")
	procMisakaIsDialogMessage = portableUser32.NewProc("IsDialogMessageW")
	procMisakaGetWindowLong   = portableUser32.NewProc("GetWindowLongPtrW")
)

func init() { misakaSubclassCallback = windows.NewCallback(misakaControlProc) }

func configureMisakaFrame(hwnd uintptr) {
	// §7.2：仅替换可见边框；窗口仍参与系统移动、缩放、任务栏与贴靠布局。
	if proc := misakaDWM.NewProc("DwmSetWindowAttribute"); proc.Find() == nil {
		preference := uint32(2)
		proc.Call(hwnd, 33, uintptr(unsafe.Pointer(&preference)), unsafe.Sizeof(preference))
	}
	procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, 0x0027) // FRAMECHANGED | NOMOVE | NOSIZE | NOZORDER
}

func (app *portableGUI) initializeMisaka() error {
	canvas, err := newMisakaCanvas()
	if err != nil {
		return err
	}
	app.skin.canvas = canvas
	app.skin.brushes = make(map[uint32]uintptr)
	for _, hwnd := range []uintptr{app.controls.networkList, app.controls.pathsValue, app.controls.profileNameEdit, app.controls.draftName, app.controls.routeCombo} {
		if result, _, err := procMisakaSetSubclass.Call(hwnd, misakaSubclassCallback, 1, app.hwnd); result == 0 {
			app.closeMisaka()
			return fmt.Errorf("[§7.2] 初始化自绘输入控件: %w", err)
		}
	}
	procSendMessage.Call(app.controls.profileNameEdit, 0x00C5, 128, 0) // EM_SETLIMITTEXT：最终按字符数校验。
	procSendMessage.Call(app.controls.draftName, 0x00C5, 128, 0)
	return nil
}

func (app *portableGUI) closeMisaka() {
	if app.skin == nil || app.skin.closed {
		return
	}
	app.skin.closed = true
	if app.skin.canvas != nil {
		app.skin.canvas.Close()
	}
	for _, brush := range app.skin.brushes {
		procDeleteObject.Call(brush)
	}
	app.skin.brushes = nil
	app.skin.draftInvite = nil
}

func (app *portableGUI) misakaBrush(color uint32) uintptr {
	if brush := app.skin.brushes[color]; brush != 0 {
		return brush
	}
	brush, _, _ := procCreateSolidBrush.Call(uintptr(misakaColorRef(color)))
	app.skin.brushes[color] = brush
	return brush
}

func misakaColorRef(rgb uint32) uint32 { return rgb>>16 | rgb&0xFF00 | (rgb&0xFF)<<16 }

func misakaRect(x, y, w, h int32) portableRect { return portableRect{x, y, x + w, y + h} }

func (app *portableGUI) layoutMisaka(snapshot portableGUISnapshot, width, height int32) {
	if app.skin == nil {
		return
	}
	app.skin.width, app.skin.height = width, height
	s := app.scale
	visible := make(map[uintptr]bool)
	defer func() {
		for _, control := range app.controls.all() {
			setPortableControlVisible(control, visible[control])
		}
	}()
	move := func(control uintptr, x, y, w, h int32) {
		procMoveWindow.Call(control, uintptr(x), uintptr(y), uintptr(max(1, w)), uintptr(max(1, h)), 0)
		visible[control] = true
	}
	side, main, end := s(176), s(196), width-s(20)
	move(app.controls.addProfileButton, side-s(42), s(112), s(28), s(28))
	move(app.controls.networkList, s(12), s(150), side-s(24), height-s(242))
	move(app.controls.profileMenu, s(16), height-s(80), side-s(32), s(28))
	move(app.controls.stateIcon, main+s(18), s(134), s(20), s(20))
	move(app.controls.stateValue, main+s(47), s(129), end-main-s(179), s(30))
	move(app.controls.primaryButton, end-s(118), s(130), s(100), s(32))
	move(app.controls.message, main, height-s(32), end-main, s(22))
	if snapshot.joined {
		modeWidth := min(s(82), (end-main-s(212))/3)
		move(app.controls.modeAuto, main+s(20), s(190), modeWidth, s(31))
		move(app.controls.modeFixed, main+s(20)+modeWidth, s(190), modeWidth, s(31))
		move(app.controls.modeDirect, main+s(20)+modeWidth*2, s(190), modeWidth, s(31))
		if misakaSelectedMode(snapshot) == clientcore.FixedExit || app.skin.fixedPicker {
			move(app.controls.routeCombo, main+s(36)+modeWidth*3, s(190), end-main-s(56)-modeWidth*3, s(220))
		}
		move(app.controls.pathsValue, main, s(272), end-main, height-s(320))
		move(app.controls.pathsDetailsButton, end-s(86), s(240), s(86), s(26))
	}
	if app.skin.menu && snapshot.selectedProfile != "" {
		move(app.controls.renameProfileButton, s(20), height-s(158), side-s(40), s(32))
		move(app.controls.deleteButton, s(20), height-s(121), side-s(40), s(32))
	}
	if app.skin.rename {
		visible[app.controls.profileNameEdit] = true
		app.positionMisakaRename()
	}
	if draft := snapshot.profileDraft; draft != nil {
		clear(visible)
		visible[app.controls.networkList] = true
		visible[app.controls.addProfileButton] = true
		x, y, w := app.misakaDraftBounds()
		move(app.controls.draftName, x+s(25), y+s(116), w-s(50), s(25))
		move(app.controls.draftImport, x+s(24), y+s(197), s(144), s(34))
		move(app.controls.draftPaste, x+s(178), y+s(197), s(144), s(34))
		move(app.controls.draftSubmit, x+w-s(150), y+s(338), s(126), s(34))
		move(app.controls.draftCancel, x+s(24), y+s(338), s(86), s(34))
	}
	enablePortableControl(app.controls.networkList, snapshot.profileDraft == nil)
	enablePortableControl(app.controls.profileMenu, app.misakaMenuSelectionConfirmed(snapshot))
}

func (app *portableGUI) misakaDraftBounds() (int32, int32, int32) {
	x := app.scale(196)
	w := min(app.scale(500), app.skin.width-x-app.scale(20))
	return x, app.scale(52), w
}

func misakaSelectedMode(snapshot portableGUISnapshot) clientcore.Mode {
	if snapshot.routeSelected >= 0 && snapshot.routeSelected < len(snapshot.routeOptions) {
		return snapshot.routeOptions[snapshot.routeSelected].Preference.Mode
	}
	return ""
}

func (app *portableGUI) misakaMenuSelectionConfirmed(snapshot portableGUISnapshot) bool {
	if snapshot.selectedProfile == "" || (app.skin.menuProfileID != "" && app.skin.menuProfileID != snapshot.selectedProfile) {
		return false
	}
	index, _, _ := procSendMessage.Call(app.controls.networkList, portableLBGetCurSel, 0, 0)
	return int(index) >= 0 && int(index) < len(snapshot.profiles) && snapshot.profiles[index].ID == snapshot.selectedProfile
}

func (app *portableGUI) misakaMenuActionReady() bool {
	return app.skin != nil && app.skin.menu && app.misakaMenuSelectionConfirmed(app.snapshot())
}

func (app *portableGUI) renderMisaka(snapshot portableGUISnapshot, previous *portableGUISnapshot) {
	if app.skin == nil {
		return
	}
	if previous != nil && previous.selectedProfile != snapshot.selectedProfile {
		if app.skin.renameID != snapshot.selectedProfile {
			app.finishMisakaRename(false)
		}
		app.skin.menu = app.skin.menuProfileID != "" && app.skin.menuProfileID == snapshot.selectedProfile
		if !app.skin.menu {
			app.skin.menuProfileID = ""
		}
		app.skin.fixedPicker = false
		app.layoutControls()
	}
	if previous != nil && previous.routeSelected != snapshot.routeSelected {
		app.skin.fixedPicker = false
	}
	if previous == nil || (previous.profileDraft == nil) != (snapshot.profileDraft == nil) {
		app.skin.draftInvite = nil
		app.skin.inviteLabel, app.skin.draftError = "", ""
		if snapshot.profileDraft != nil {
			setPortableControlText(app.controls.draftName, snapshot.profileDraft.Name)
			procMisakaSetFocus.Call(app.controls.draftName)
		}
	}
	setPortableControlText(app.controls.renameProfileButton, "重命名   F2")
	setPortableControlText(app.controls.deleteButton, "删除配置…")
	enablePortableControl(app.controls.profileMenu, app.misakaMenuSelectionConfirmed(snapshot))
	enablePortableControl(app.controls.addProfileButton, snapshot.profilesReady)
	if snapshot.profilesReady && snapshot.selectedProfile == "" {
		setPortableControlText(app.controls.primaryButton, "添加配置")
	}
	if snapshot.activeProfile != "" && snapshot.activeProfile != snapshot.selectedProfile && snapshot.joined &&
		(snapshot.state == guiStopped || snapshot.state == guiError) {
		setPortableControlText(app.controls.primaryButton, "切换连接")
	}
	for _, pair := range []struct {
		hwnd uintptr
		mode clientcore.Mode
	}{{app.controls.modeAuto, clientcore.Auto}, {app.controls.modeFixed, clientcore.FixedExit}, {app.controls.modeDirect, clientcore.Direct}} {
		available := slices.ContainsFunc(snapshot.routeOptions, func(option portableRouteOption) bool { return option.Preference.Mode == pair.mode })
		enablePortableControl(pair.hwnd, portableRouteSelectable(snapshot) && available)
		if previous == nil || previous.routeSelected != snapshot.routeSelected || previous.routeBusy != snapshot.routeBusy {
			procInvalidateRect.Call(pair.hwnd, 0, 0)
		}
	}
	if draft := snapshot.profileDraft; draft != nil {
		enablePortableControl(app.controls.draftName, !draft.Busy)
		enablePortableControl(app.controls.draftImport, !draft.Busy && !draft.Recoverable)
		enablePortableControl(app.controls.draftPaste, !draft.Busy && !draft.Recoverable)
		enablePortableControl(app.controls.draftSubmit, !draft.Busy && (draft.Recoverable || app.skin.draftInvite != nil))
		label := "加入并保存"
		if draft.Busy {
			label = "正在加入…"
		} else if draft.Recoverable {
			label = "继续加入"
		}
		setPortableControlText(app.controls.draftSubmit, label)
		if draft.Busy || draft.Recoverable {
			setPortableControlText(app.controls.draftCancel, "稍后继续")
		} else {
			setPortableControlText(app.controls.draftCancel, "取消")
		}
	}
	app.updateMisakaPaths(snapshot, previous == nil || previous.state != snapshot.state)
	// §7.2：观测变化只使对应卡片失效，定时轮询没有任何绘制副作用。
	if previous == nil || !equalProfileDraft(snapshot.profileDraft, previous.profileDraft) ||
		previous.state != snapshot.state || previous.profileName != snapshot.profileName || previous.routeSelected != snapshot.routeSelected ||
		previous.joined != snapshot.joined || previous.activeProfileName != snapshot.activeProfileName {
		procInvalidateRect.Call(app.hwnd, 0, 0)
	}
}

func (app *portableGUI) misakaPathHeight() int32 {
	rows := 1
	if app.skin != nil {
		for _, path := range app.skin.lastPaths {
			rows = max(rows, (len(strings.Split(path.Chain, " → "))+3)/4)
		}
	}
	height := int32(128 + (rows-1)*64)
	if app.pathsExpanded {
		height += 146
	}
	return height
}

func (app *portableGUI) updateMisakaPaths(snapshot portableGUISnapshot, force bool) {
	rows := snapshot.paths
	if snapshot.state != guiConnected {
		rows = nil
	}
	text := formatWindowsPaths(rows, app.pathsExpanded)
	if !force && slices.Equal(app.skin.lastPaths, rows) && text == app.skin.pathsText {
		return
	}
	app.skin.lastPaths, app.skin.pathsText = slices.Clone(rows), text
	top, _, _ := procSendMessage.Call(app.controls.pathsValue, 0x018E, 0, 0)
	style, _, _ := procMisakaGetWindowLong.Call(app.controls.pathsValue, ^uintptr(15))
	visible := style&portableWSVisible != 0
	if visible {
		procSendMessage.Call(app.controls.pathsValue, 0x000B, 0, 0)
	}
	procSendMessage.Call(app.controls.pathsValue, portableLBResetContent, 0, 0)
	procSendMessage.Call(app.controls.pathsValue, portableLBSetItemHeight, 0, uintptr(app.scale(app.misakaPathHeight())))
	for _, row := range rows {
		label, _ := windows.UTF16PtrFromString(formatWindowsPaths([]windowsPathDisplay{row}, true))
		procSendMessage.Call(app.controls.pathsValue, portableLBAddString, 0, uintptr(unsafe.Pointer(label)))
		runtime.KeepAlive(label)
	}
	if len(rows) == 0 {
		message := "未连接；连接成功后显示各服务的实际路径。"
		if snapshot.state == guiConnected {
			message = "当前选路未知，正在读取本机实际状态。"
		}
		label, _ := windows.UTF16PtrFromString(message)
		procSendMessage.Call(app.controls.pathsValue, portableLBAddString, 0, uintptr(unsafe.Pointer(label)))
		runtime.KeepAlive(label)
	}
	if len(rows) > 0 {
		procSendMessage.Call(app.controls.pathsValue, 0x0197, min(top, uintptr(len(rows)-1)), 0)
	}
	if visible {
		procSendMessage.Call(app.controls.pathsValue, 0x000B, 1, 0)
	}
	procInvalidateRect.Call(app.controls.pathsValue, 0, 0)
}

func (app *portableGUI) openMisakaDraft() {
	app.finishMisakaRename(false)
	app.skin.menu, app.skin.menuProfileID = false, ""
	app.profileCommand(brokerRequest{Operation: "add_profile"})
}

func (app *portableGUI) beginMisakaRename() {
	snapshot := app.snapshot()
	if snapshot.selectedProfile == "" || snapshot.profileDraft != nil {
		return
	}
	index, _, _ := procSendMessage.Call(app.controls.networkList, portableLBGetCurSel, 0, 0)
	if int(index) >= len(snapshot.profiles) {
		return
	}
	profile := snapshot.profiles[index]
	app.skin.menu, app.skin.menuProfileID = false, ""
	app.skin.rename, app.skin.renameID = true, profile.ID
	setPortableControlText(app.controls.profileNameEdit, profile.Name)
	app.layoutControls()
	procMisakaSetFocus.Call(app.controls.profileNameEdit)
	procSendMessage.Call(app.controls.profileNameEdit, 0x00B1, 0, ^uintptr(0))
}

func (app *portableGUI) positionMisakaRename() {
	snapshot := app.snapshot()
	index := slices.IndexFunc(snapshot.profiles, func(p windowsProfileDisplay) bool { return p.ID == app.skin.renameID })
	if index < 0 {
		app.skin.rename = false
		return
	}
	var rect portableRect
	procSendMessage.Call(app.controls.networkList, 0x0198, uintptr(index), uintptr(unsafe.Pointer(&rect)))
	procMisakaMapPoints.Call(app.controls.networkList, app.hwnd, uintptr(unsafe.Pointer(&rect)), 2)
	rect.left += app.scale(30)
	rect.right -= app.scale(6)
	rect.top += app.scale(7)
	rect.bottom = rect.top + app.scale(24)
	procMoveWindow.Call(app.controls.profileNameEdit, uintptr(rect.left), uintptr(rect.top), uintptr(rect.right-rect.left), uintptr(rect.bottom-rect.top), 0)
	setPortableControlVisible(app.controls.profileNameEdit, true)
}

func misakaControlText(hwnd uintptr) string {
	length, _, _ := procGetWindowTextLength.Call(hwnd)
	buffer := make([]uint16, length+1)
	procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	return windows.UTF16ToString(buffer)
}

func (app *portableGUI) finishMisakaRename(save bool) bool {
	if app.skin == nil || !app.skin.rename {
		return true
	}
	id, name := app.skin.renameID, strings.TrimSpace(misakaControlText(app.controls.profileNameEdit))
	if save {
		if err := validateConnectionProfileName(name); err != nil {
			app.profileError(err)
			return false
		}
		for _, p := range app.snapshot().profiles {
			if p.ID != id && strings.EqualFold(p.Name, name) {
				app.profileError(errors.New("[§7.2] 此配置名称已存在"))
				return false
			}
		}
	}
	app.skin.rename, app.skin.renameID = false, ""
	setPortableControlVisible(app.controls.profileNameEdit, false)
	if save {
		app.profileCommand(brokerRequest{Operation: "rename_profile", ProfileID: id, Name: name})
	}
	procInvalidateRect.Call(app.controls.networkList, 0, 0)
	return true
}

func (app *portableGUI) chooseMisakaInvite(paste bool) {
	var invite clientenroll.Invite
	var err error
	if paste {
		invite, err = readWindowsClipboardInvite(app.hwnd)
	} else {
		var source string
		source, err = openJoinArtifact(app.hwnd)
		if err == nil && source == "" {
			return
		}
		if err == nil {
			invite, err = clientjoin.Read(source, nil)
		}
	}
	app.acceptMisakaInvite(invite, err)
}

func (app *portableGUI) acceptMisakaInvite(invite clientenroll.Invite, err error) {
	draft := app.snapshot().profileDraft
	if draft == nil || draft.Busy || draft.Recoverable {
		return
	}
	app.skin.draftError = ""
	if err != nil {
		app.skin.draftError = err.Error()
	} else {
		app.skin.draftInvite = &invite
		app.skin.inviteLabel = "邀请已读取；加入时验证中控信任与身份绑定。"
		if strings.TrimSpace(misakaControlText(app.controls.draftName)) == "" {
			setPortableControlText(app.controls.draftName, "Loom 网络")
		}
	}
	app.renderMisaka(app.snapshot(), app.rendered)
	procInvalidateRect.Call(app.hwnd, 0, 0)
}

func (app *portableGUI) misakaCommand(id uint16) bool {
	snapshot := app.snapshot()
	switch id {
	case misakaControlAuto, misakaControlDirect, misakaControlFixed:
		if !portableRouteSelectable(snapshot) {
			return true
		}
		mode := clientcore.Auto
		if id == misakaControlDirect {
			mode = clientcore.Direct
		}
		if id == misakaControlFixed {
			app.skin.fixedPicker = true
			app.layoutControls()
			procSendMessage.Call(app.controls.routeCombo, portableCBShowDropDown, 1, 0)
			procMisakaSetFocus.Call(app.controls.routeCombo)
			return true
		}
		for _, option := range snapshot.routeOptions {
			if option.Preference.Mode == mode {
				app.skin.fixedPicker = false
				app.layoutControls()
				if misakaSelectedMode(snapshot) == mode {
					return true
				}
				preference := option.Preference
				app.profileCommand(brokerRequest{Operation: "preference", ProfileID: snapshot.selectedProfile, Preference: &preference})
				break
			}
		}
		return true
	case misakaControlMenu:
		// §7.2：列表已指向新配置但 broker 尚未确认时，不能重新打开旧配置菜单。
		if !app.misakaMenuSelectionConfirmed(snapshot) {
			return true
		}
		app.skin.menu = !app.skin.menu
		app.skin.menuProfileID = ""
		if app.skin.menu {
			app.skin.menuProfileID = snapshot.selectedProfile
		}
		app.layoutControls()
		return true
	case misakaControlDraftImport:
		app.chooseMisakaInvite(false)
		return true
	case misakaControlDraftPaste:
		app.chooseMisakaInvite(true)
		return true
	case misakaControlDraftSubmit:
		if snapshot.profileDraft == nil || snapshot.profileDraft.Busy {
			return true
		}
		name := strings.TrimSpace(misakaControlText(app.controls.draftName))
		if err := validateConnectionProfileName(name); err != nil {
			app.skin.draftError = err.Error()
			procInvalidateRect.Call(app.hwnd, 0, 0)
			return true
		}
		app.skin.draftError = ""
		invite := app.skin.draftInvite
		if snapshot.profileDraft.Recoverable {
			invite = nil
		}
		app.profileCommand(brokerRequest{Operation: "join_profile", Name: name, Invite: invite})
		return true
	case misakaControlDraftCancel:
		app.skin.draftInvite = nil
		app.profileCommand(brokerRequest{Operation: "cancel_add_profile"})
		return true
	}
	return false
}

func handleMisakaKeyboard(message portableMSG) bool {
	root, _, _ := procGetAncestor.Call(message.hwnd, portableGARoot)
	value, ok := portableGUIWindows.Load(root)
	app, _ := value.(*portableGUI)
	if !ok || app.skin == nil {
		return false
	}
	if message.msg != portableWMKeyDown {
		return false
	}
	if message.hwnd == app.controls.profileNameEdit {
		if message.wParam == portableVKReturn {
			app.finishMisakaRename(true)
			return true
		}
		if message.wParam == portableVKEscape {
			app.finishMisakaRename(false)
			procMisakaSetFocus.Call(app.controls.networkList)
			return true
		}
		return false
	}
	if message.wParam == 0x71 && app.snapshot().profileDraft == nil {
		app.beginMisakaRename()
		return true
	}
	if message.wParam == portableVKEscape {
		if app.snapshot().profileDraft != nil {
			app.misakaCommand(misakaControlDraftCancel)
			return true
		}
		if app.skin.menu || app.skin.menuProfileID != "" {
			app.skin.menu, app.skin.menuProfileID = false, ""
			app.layoutControls()
			return true
		}
	}
	if app.snapshot().profileDraft != nil && message.wParam == portableVKV {
		control, _, _ := procGetKeyState.Call(portableVKControl)
		if control&0x8000 != 0 && message.hwnd != app.controls.draftName {
			app.chooseMisakaInvite(true)
			return true
		}
	}
	return false
}

func misakaDialogMessage(message portableMSG) bool {
	if message.msg != portableWMKeyDown || message.wParam != 0x09 {
		return false
	}
	root, _, _ := procGetAncestor.Call(message.hwnd, portableGARoot)
	if _, ok := portableGUIWindows.Load(root); !ok {
		return false
	}
	result, _, _ := procMisakaIsDialogMessage.Call(root, uintptr(unsafe.Pointer(&message)))
	return result != 0
}

func misakaControlProc(hwnd uintptr, message uint32, wParam, lParam, subclass, owner uintptr) uintptr {
	value, found := portableGUIWindows.Load(owner)
	app, _ := value.(*portableGUI)
	if found && app.skin != nil && !app.skin.closed {
		switch message {
		case 0x0082:
			procMisakaRemoveSubclass.Call(hwnd, misakaSubclassCallback, subclass)
		case 0x0008:
			if hwnd == app.controls.profileNameEdit {
				app.finishMisakaRename(true)
			}
		case 0x0201: // WM_LBUTTONDOWN：新点击也取消尚未得到 broker 确认的菜单。
			if hwnd == app.controls.networkList && app.skin.menuProfileID != "" {
				app.skin.menu, app.skin.menuProfileID = false, ""
				app.layoutControls()
			}
		case portableWMRButtonUp:
			if hwnd == app.controls.networkList {
				index, _, _ := procSendMessage.Call(hwnd, 0x01A9, 0, lParam)
				snapshot := app.snapshot()
				if index>>16 != 0 || int(index) >= len(snapshot.profiles) {
					app.skin.menu, app.skin.menuProfileID = false, ""
					app.layoutControls()
					return 0
				}
				profileID := snapshot.profiles[index].ID
				app.skin.menuProfileID = profileID
				app.skin.menu = profileID == snapshot.selectedProfile
				procSendMessage.Call(hwnd, portableLBSetCurSel, index, 0)
				if !app.skin.menu {
					app.selectProfileFromList()
				}
				// §7.2：等待 broker 确认查看对象后才显示其菜单，不能删除上一份配置。
				app.layoutControls()
				return 0
			}
		case portableWMKeyDown:
			if handleMisakaKeyboard(portableMSG{hwnd: hwnd, msg: message, wParam: wParam, lParam: lParam}) {
				return 0
			}
		case 0x0014:
			if hwnd == app.controls.networkList || hwnd == app.controls.pathsValue {
				var rect portableRect
				procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rect)))
				color := uint32(misakaBackground)
				if hwnd == app.controls.networkList {
					color = misakaSidebar
				}
				procFillRect.Call(wParam, uintptr(unsafe.Pointer(&rect)), app.misakaBrush(color))
				return 1
			}
		}
	}
	result, _, _ := procMisakaDefSubclass.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}

func misakaWindowMessage(app *portableGUI, hwnd uintptr, message uint32, wParam, lParam uintptr) (uintptr, bool) {
	if message == 0x0083 && wParam != 0 { // WM_NCCALCSIZE
		if zoomed, _, _ := procMisakaIsZoomed.Call(hwnd); zoomed != 0 {
			// §7.2：最大化服从当前显示器工作区，不能盖住任务栏。
			monitor, _, _ := portableUser32.NewProc("MonitorFromWindow").Call(hwnd, 2)
			info := struct {
				size          uint32
				monitor, work portableRect
				flags         uint32
			}{size: 40}
			if ok, _, _ := portableUser32.NewProc("GetMonitorInfoW").Call(monitor, uintptr(unsafe.Pointer(&info))); ok != 0 {
				*(*portableRect)(unsafe.Pointer(lParam)) = info.work
			}
		}
		return 0, true
	}
	if app == nil || app.skin == nil || app.skin.closed {
		return 0, false
	}
	if result, handled := misakaCaptionMessage(app, hwnd, message, wParam, lParam); handled {
		return result, true
	}
	s := app.scale
	switch message {
	case 0x0113:
		if wParam == misakaRetryPaintTimer {
			procKillTimer.Call(hwnd, misakaRetryPaintTimer)
			procRedrawWindow.Call(hwnd, 0, 0, portableRDWInvalidate|portableRDWAllChildren)
			return 0, true
		}
	case 0x0202:
		if app.skin.menu || app.skin.menuProfileID != "" {
			app.skin.menu, app.skin.menuProfileID = false, ""
			app.layoutControls()
		}
	case 0x0085:
		return 0, true // WM_NCPAINT：默认边框不再绘制。
	case 0x0086:
		result, _, _ := procDefWindowProc.Call(hwnd, uintptr(message), wParam, ^uintptr(0))
		return result, true
	case 0x0317:
		procDefWindowProc.Call(hwnd, uintptr(message), wParam, (lParam&^0x000A)|0x0004)
		return 0, true
	case 0x0014:
		return 1, true // WM_ERASEBKGND：每个绘制目标一次提交。
	case 0x000F:
		var paint struct {
			dc              uintptr
			erase           int32
			rect            portableRect
			restore, update int32
			reserved        [32]byte
		}
		dc, _, _ := procMisakaBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		app.paintMisaka(dc)
		procMisakaEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		return 0, true
	case 0x0318:
		app.paintMisaka(wParam)
		return 0, true // WM_PRINTCLIENT
	case portableWMCommand:
		if app.misakaCommand(uint16(wParam & 0xffff)) {
			return 0, true
		}
	case portableWMCtlColorStatic, 0x0133, 0x0134:
		color := uint32(misakaWhite)
		if lParam == app.controls.message {
			color = misakaBackground
		}
		procSetBkMode.Call(wParam, portableTransparent)
		procSetTextColor.Call(wParam, uintptr(misakaColorRef(misakaText)))
		if lParam == app.controls.message {
			procSetTextColor.Call(wParam, uintptr(misakaColorRef(misakaMuted)))
		}
		return app.misakaBrush(color), true
	case 0x0084: // WM_NCHITTEST
		var rect portableRect
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rect)))
		point := misakaCaptionPoint(hwnd, lParam, true)
		x, y := point.x, point.y
		w, h := rect.right-rect.left, rect.bottom-rect.top
		zoomed, _, _ := procMisakaIsZoomed.Call(hwnd)
		if zoomed == 0 {
			edge := s(6)
			if y < edge {
				if x < edge {
					return 13, true
				}
				if x >= w-edge {
					return 14, true
				}
				return 12, true
			}
			if y >= h-edge {
				if x < edge {
					return 16, true
				}
				if x >= w-edge {
					return 17, true
				}
				return 15, true
			}
			if x < edge {
				return 10, true
			}
			if x >= w-edge {
				return 11, true
			}
		}
		if y < s(40) {
			if x >= w-s(84) && x < w-s(42) {
				return 9, true
			} // HTMAXBUTTON：Windows 11 Snap。
			if x < w-s(126) {
				return 2, true
			}
		}
		return 1, true
	case portableWMDestroy:
		app.closeMisaka()
	}
	return 0, false
}

func toggleMisakaMaximize(hwnd uintptr) {
	command := uintptr(3)
	if zoomed, _, _ := procMisakaIsZoomed.Call(hwnd); zoomed != 0 {
		command = portableSWRestore
	}
	procShowWindow.Call(hwnd, command)
}
