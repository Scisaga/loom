//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"loom/internal/clientenroll"
	"loom/internal/clientsecret"
)

type portableGUIState uint8

const (
	guiLoading portableGUIState = iota
	guiNeedsJoin
	guiJoining
	guiNeedsElevation
	guiStarting
	guiConnected
	guiStopping
	guiStopped
	guiError
)

type portableGUISnapshot struct {
	state         portableGUIState
	joined        bool
	deviceID      string
	detail        string
	hostname      string
	routeOptions  []portableRouteOption
	routeSelected int
	routeBusy     bool
	routeDetail   string
}

type portableGUI struct {
	edition           clientEdition
	root              string
	hwnd              uintptr
	windowDPI         int32
	controls          portableGUIControls
	fonts             []uintptr
	statusIcon        uintptr
	trayConnectedIcon uintptr
	trayAdded         bool
	routeFiltering    bool
	routeFilter       string
	routeVisible      []int
	routeUpdating     bool

	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.RWMutex
	state         portableGUIState
	joined        bool
	deviceID      string
	detail        string
	hostname      string
	runCancel     context.CancelFunc
	runDone       chan struct{}
	stopRequested bool
	runSequence   uint64
	routeOptions  []portableRouteOption
	routeSelected int
	routeBusy     bool
	routeDetail   string

	lockMu sync.Mutex
	lock   *windowsNamedLock

	workers sync.WaitGroup
}

func runWindowsGUI(edition clientEdition) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, err := windowsGUIStateRoot(edition)
	if err != nil {
		return err
	}
	lock, err := acquireWindowsClientUILock()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	hostname, _ := os.Hostname()
	app := &portableGUI{
		edition:       edition,
		root:          root,
		ctx:           ctx,
		cancel:        cancel,
		state:         guiLoading,
		hostname:      hostname,
		lock:          lock,
		routeSelected: -1,
	}
	defer app.releasePortableLock()

	hwnd, err := createPortableWindow(app)
	if err != nil {
		cancel()
		return err
	}
	app.hwnd = hwnd
	portableGUIWindows.Store(hwnd, app)
	if err := app.createControls(); err != nil {
		portableGUIWindows.Delete(hwnd)
		procDestroyWindow.Call(hwnd)
		app.deleteFonts()
		app.deleteIcons()
		cancel()
		return err
	}
	if err := app.addTrayIcon(); err != nil {
		portableGUIWindows.Delete(hwnd)
		procDestroyWindow.Call(hwnd)
		app.deleteFonts()
		cancel()
		return err
	}
	dragAcceptFiles(hwnd, true)
	app.renderControls()
	showPortableWindow(hwnd)

	app.workers.Add(1)
	go func() {
		defer app.workers.Done()
		app.initialize()
	}()

	err = runPortableMessageLoop()
	app.shutdown()
	app.deleteFonts()
	app.deleteIcons()
	return err
}

func (app *portableGUI) initialize() {
	if app.edition == editionInstalled && !windows.GetCurrentProcessToken().IsElevated() {
		app.update(guiNeedsElevation, false, "", "Installed 版使用机器范围凭据和 ProgramData 状态；请以管理员身份启动。")
		return
	}
	result, err := ensureWindowsJoined(app.ctx, app.root, app.protector(), "")
	if errors.Is(err, errWindowsJoinInputRequired) {
		app.update(guiNeedsJoin, false, "", "")
		return
	}
	if err != nil {
		app.update(guiError, false, "", err.Error())
		return
	}
	app.afterJoin(result.NodeID)
}

func (app *portableGUI) afterJoin(deviceID string) {
	app.mu.Lock()
	app.joined = true
	app.deviceID = deviceID
	app.detail = ""
	app.mu.Unlock()
	if windowsEditionRequiresElevation(app.edition) && !windows.GetCurrentProcessToken().IsElevated() {
		app.update(guiNeedsElevation, true, deviceID, app.elevationDetail(true))
		return
	}
	app.startRuntime()
}

func (app *portableGUI) importJoinArtifact(source string) {
	app.beginJoin(func() (windowsJoinResult, error) {
		return ensureWindowsJoined(app.ctx, app.root, app.protector(), source)
	})
}

func (app *portableGUI) importJoinInvite(invite clientenroll.Invite) {
	app.beginJoin(func() (windowsJoinResult, error) {
		return ensureWindowsJoinedInvite(app.ctx, app.root, app.protector(), invite)
	})
}

func (app *portableGUI) beginJoin(join func() (windowsJoinResult, error)) {
	app.mu.Lock()
	if app.joined || app.state == guiJoining || app.state == guiLoading {
		app.mu.Unlock()
		return
	}
	app.state = guiJoining
	app.detail = "正在验证二维码、设备身份和签名数据面…"
	app.mu.Unlock()
	app.repaint()

	app.workers.Add(1)
	go func() {
		defer app.workers.Done()
		result, err := join()
		if err != nil {
			if app.ctx.Err() == nil {
				app.update(guiError, false, "", err.Error())
			}
			return
		}
		app.afterJoin(result.NodeID)
	}()
}

func (app *portableGUI) startRuntime() {
	if windowsEditionRequiresElevation(app.edition) && !windows.GetCurrentProcessToken().IsElevated() {
		app.update(guiNeedsElevation, true, app.snapshot().deviceID, app.elevationDetail(false))
		return
	}
	app.mu.Lock()
	if app.runCancel != nil || !app.joined || app.ctx.Err() != nil {
		app.mu.Unlock()
		return
	}
	runCtx, runCancel := context.WithCancel(app.ctx)
	app.runSequence++
	sequence := app.runSequence
	done := make(chan struct{})
	app.runCancel = runCancel
	app.runDone = done
	app.stopRequested = false
	app.state = guiStarting
	app.detail = "正在拉取并验证最新配置…"
	app.mu.Unlock()
	app.repaint()

	app.workers.Add(1)
	go func() {
		defer app.workers.Done()
		defer close(done)
		workload, err := prepareClientAt(app.root, app.protector(), app.edition)
		if err != nil {
			runCancel()
			app.finishRuntime(sequence, runCtx, err)
			return
		}
		watchDone := make(chan struct{})
		routeDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			if waitForPortableRuntime(runCtx, app.root) {
				app.runtimeReady(sequence)
			}
		}()
		go func() {
			defer close(routeDone)
			app.watchRoutePreference(runCtx, sequence)
		}()
		err = workload(runCtx)
		runCancel()
		<-watchDone
		<-routeDone
		app.finishRuntime(sequence, runCtx, err)
	}()
}

func waitForPortableRuntime(ctx context.Context, root string) bool {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var firstSeen time.Time
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			active := false
			entries, err := os.ReadDir(filepath.Join(root, "runtime"))
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() && strings.HasPrefix(entry.Name(), ".sing-box-active-") {
						active = true
						break
					}
				}
			}
			if !active {
				firstSeen = time.Time{}
				continue
			}
			if firstSeen.IsZero() {
				firstSeen = time.Now()
				continue
			}
			if time.Since(firstSeen) >= dataPlaneStartupGrace {
				return true
			}
		}
	}
}

func (app *portableGUI) runtimeReady(sequence uint64) {
	app.mu.Lock()
	if sequence == app.runSequence && app.runCancel != nil && !app.stopRequested {
		app.state = guiConnected
		if app.edition == editionPortableMixed {
			app.detail = "本地 HTTP/SOCKS 代理：127.0.0.1:1080。"
		} else {
			app.detail = "系统 TUN 已启用；本地 HTTP/SOCKS 代理：127.0.0.1:1080。"
		}
	}
	app.mu.Unlock()
	app.repaint()
}

func (app *portableGUI) finishRuntime(sequence uint64, runCtx context.Context, runErr error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if sequence != app.runSequence {
		return
	}
	stopped := app.stopRequested || app.ctx.Err() != nil || errors.Is(runCtx.Err(), context.Canceled)
	app.runCancel = nil
	app.runDone = nil
	app.stopRequested = false
	if app.ctx.Err() != nil {
		return
	}
	if stopped && runErr == nil {
		app.state = guiStopped
		app.detail = "数据面已停止；Device 加入状态仍保留在本机。"
	} else if runErr != nil {
		app.state = guiError
		app.detail = runErr.Error()
	} else {
		app.state = guiError
		app.detail = "数据面意外停止。"
	}
	app.repaintLocked()
}

func (app *portableGUI) stopRuntime() {
	app.mu.Lock()
	if app.runCancel == nil {
		app.mu.Unlock()
		return
	}
	app.stopRequested = true
	app.state = guiStopping
	app.detail = "正在停止数据面并清理临时运行状态…"
	cancel := app.runCancel
	app.mu.Unlock()
	cancel()
	app.repaint()
}

func (app *portableGUI) deleteLocalDevice() {
	snapshot := app.snapshot()
	if !snapshot.joined || (snapshot.state != guiStopped && snapshot.state != guiError && snapshot.state != guiNeedsElevation) {
		messageBox(app.hwnd, "删除本机 Device", "请先断开 Loom 网络，再删除本机身份和配置。", portableMBOK|portableMBIconWarning)
		return
	}
	answer := messageBoxResult(app.hwnd, "删除本机 Device",
		"此操作只删除这台电脑上的 Loom 身份、配置和运行状态，无法恢复。\n\n中控中的 Device 仍需由管理员下线并吊销。是否继续？",
		portableMBYesNo|portableMBIconWarning|portableMBDefButton2)
	if answer != portableIDYes {
		return
	}
	app.mu.Lock()
	if app.runCancel != nil {
		app.mu.Unlock()
		messageBox(app.hwnd, "删除本机 Device", "数据面仍在运行，请先断开后重试。", portableMBOK|portableMBIconWarning)
		return
	}
	app.state = guiLoading
	app.detail = "正在删除本机身份和配置…"
	app.mu.Unlock()
	app.repaint()

	app.workers.Add(1)
	go func() {
		defer app.workers.Done()
		if err := removeWindowsLocalDevice(app.root, app.edition); err != nil {
			app.update(guiError, true, snapshot.deviceID, "删除本机 Device 失败："+err.Error())
			return
		}
		app.mu.Lock()
		app.joined = false
		app.deviceID = ""
		app.state = guiNeedsJoin
		app.detail = ""
		app.routeOptions = nil
		app.routeSelected = -1
		app.routeBusy = false
		app.routeDetail = ""
		app.mu.Unlock()
		app.repaint()
		messageBox(app.hwnd, "删除本机 Device", "本机身份和配置已删除。请在中控端下线并吊销原 Device。", portableMBOK)
	}()
}

func removeWindowsLocalDevice(root string, edition clientEdition) error {
	expected, err := windowsGUIStateRoot(edition)
	if err != nil {
		return err
	}
	if filepath.Clean(root) != expected || !filepath.IsAbs(root) {
		return fmt.Errorf("拒绝删除非预期状态目录 %q", root)
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("状态目录不是普通目录")
	}
	return os.RemoveAll(root)
}

func (app *portableGUI) primaryAction() {
	snapshot := app.snapshot()
	switch snapshot.state {
	case guiNeedsJoin:
		app.chooseJoinArtifact()
	case guiError:
		if snapshot.joined {
			app.startRuntime()
		} else {
			app.chooseJoinArtifact()
		}
	case guiNeedsElevation:
		app.restartElevated()
	case guiStarting, guiConnected:
		app.stopRuntime()
	case guiStopped:
		app.startRuntime()
	}
}

func (app *portableGUI) chooseJoinArtifact() {
	path, err := openJoinArtifact(app.hwnd)
	if err != nil {
		showWindowsError("导入 Loom 二维码", err)
		return
	}
	if path != "" {
		app.importJoinArtifact(path)
	}
}

func (app *portableGUI) pasteJoinArtifact() {
	snapshot := app.snapshot()
	if snapshot.joined || (snapshot.state != guiNeedsJoin && snapshot.state != guiError) {
		return
	}
	invite, err := readWindowsClipboardInvite(app.hwnd)
	if err != nil {
		showWindowsError("粘贴 Loom 二维码", err)
		return
	}
	app.importJoinInvite(invite)
}

func (app *portableGUI) acceptDroppedFiles(drop uintptr) {
	defer dragFinish(drop)
	paths, err := droppedFiles(drop)
	if err != nil {
		showWindowsError("导入 Loom 二维码", err)
		return
	}
	if len(paths) != 1 {
		showWindowsError("导入 Loom 二维码", errors.New("请一次只拖入一个二维码 PNG 或 .loom-invite 文件"))
		return
	}
	snapshot := app.snapshot()
	if snapshot.joined || (snapshot.state != guiNeedsJoin && snapshot.state != guiError) {
		showWindowsError("导入 Loom 二维码", errors.New("此 Device 已经加入网络，不能导入另一张二维码"))
		return
	}
	app.importJoinArtifact(paths[0])
}

func (app *portableGUI) restartElevated() {
	snapshot := app.snapshot()
	app.update(guiStarting, snapshot.joined, snapshot.deviceID, "正在请求 Windows 管理员权限…")
	app.releasePortableLock()
	executable, err := os.Executable()
	if err == nil {
		verb, _ := windows.UTF16PtrFromString("runas")
		file, _ := windows.UTF16PtrFromString(executable)
		cwd, _ := windows.UTF16PtrFromString(filepath.Dir(executable))
		err = windows.ShellExecute(windows.Handle(app.hwnd), verb, file, nil, cwd, portableSWShowNormal)
	}
	if err != nil {
		lock, lockErr := acquireWindowsClientUILock()
		if lockErr == nil {
			app.lockMu.Lock()
			app.lock = lock
			app.lockMu.Unlock()
		}
		app.update(guiNeedsElevation, true, app.snapshot().deviceID, "未获得管理员权限："+err.Error())
		return
	}
	postPortableMessage(app.hwnd, portableWMAppExit, 0, 0)
}

func windowsGUIStateRoot(edition clientEdition) (string, error) {
	switch edition {
	case editionInstalled:
		return programDataRoot()
	case editionPortableMixed, editionPortableTUN:
		return localAppDataRoot()
	default:
		return "", fmt.Errorf("unsupported Windows client edition %q", edition)
	}
}

func windowsEditionLabel(edition clientEdition) string {
	switch edition {
	case editionInstalled:
		return "Installed"
	case editionPortableTUN:
		return "Portable TUN"
	default:
		return "Portable Mixed"
	}
}

func windowsEditionRequiresElevation(edition clientEdition) bool {
	return edition == editionInstalled || edition == editionPortableTUN
}

func (app *portableGUI) protector() clientsecret.Protector {
	if app.edition == editionInstalled {
		return clientsecret.MachineProtector{}
	}
	return clientsecret.UserProtector{}
}

func (app *portableGUI) elevationDetail(afterJoin bool) string {
	if app.edition == editionInstalled {
		return "Installed 版使用机器范围凭据和 ProgramData 状态；请以管理员身份启动。"
	}
	if afterJoin {
		return "启用系统 TUN 需要管理员权限；导入二维码本身不需要提权。"
	}
	return "启用系统 TUN 需要管理员权限。"
}

func (app *portableGUI) update(state portableGUIState, joined bool, deviceID, detail string) {
	app.mu.Lock()
	if app.ctx.Err() == nil {
		app.state = state
		app.joined = joined
		if deviceID != "" {
			app.deviceID = deviceID
		}
		app.detail = detail
	}
	app.mu.Unlock()
	app.repaint()
}

func (app *portableGUI) snapshot() portableGUISnapshot {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return portableGUISnapshot{
		state: app.state, joined: app.joined, deviceID: app.deviceID,
		detail: app.detail, hostname: app.hostname,
		routeOptions:  append([]portableRouteOption(nil), app.routeOptions...),
		routeSelected: app.routeSelected, routeBusy: app.routeBusy, routeDetail: app.routeDetail,
	}
}

func (app *portableGUI) repaint() {
	app.mu.RLock()
	defer app.mu.RUnlock()
	app.repaintLocked()
}

func (app *portableGUI) repaintLocked() {
	if app.hwnd != 0 {
		postPortableMessage(app.hwnd, portableWMAppRepaint, 0, 0)
	}
}

func (app *portableGUI) beginClose() {
	app.cancel()
	app.mu.Lock()
	if app.runCancel != nil {
		app.stopRequested = true
		app.runCancel()
	}
	app.mu.Unlock()
}

func (app *portableGUI) shutdown() {
	app.beginClose()
	done := make(chan struct{})
	go func() {
		app.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

func (app *portableGUI) releasePortableLock() {
	app.lockMu.Lock()
	defer app.lockMu.Unlock()
	if app.lock != nil {
		app.lock.close()
		app.lock = nil
	}
}

func showWindowsError(title string, err error) {
	if err == nil {
		return
	}
	messageBox(0, title, err.Error(), portableMBOK|portableMBIconError)
}

// Native Win32 controls keep the Portable shell compact and consistent with
// Windows desktop conventions. The window itself owns no custom-painted canvas.

const (
	portableWMCreate         = 0x0001
	portableWMDestroy        = 0x0002
	portableWMNull           = 0x0000
	portableWMSize           = 0x0005
	portableWMClose          = 0x0010
	portableWMGetMinMaxInfo  = 0x0024
	portableWMSetFont        = 0x0030
	portableWMGetFont        = 0x0031
	portableWMSetIcon        = 0x0080
	portableWMDrawItem       = 0x002B
	portableWMMeasureItem    = 0x002C
	portableWMKeyDown        = 0x0100
	portableWMChar           = 0x0102
	portableWMCommand        = 0x0111
	portableWMCtlColorStatic = 0x0138
	portableWMLButtonDblClk  = 0x0203
	portableWMRButtonUp      = 0x0205
	portableWMDropFiles      = 0x0233
	portableWMDPIChanged     = 0x02E0
	portableWMAppRepaint     = 0x8001
	portableWMAppTray        = 0x8002
	portableWMAppExit        = 0x8003

	portableWSOverlapped    = 0x00000000
	portableWSCaption       = 0x00C00000
	portableWSSysMenu       = 0x00080000
	portableWSThickFrame    = 0x00040000
	portableWSMinimizeBox   = 0x00020000
	portableWSMaximizeBox   = 0x00010000
	portableWSChild         = 0x40000000
	portableWSVisible       = 0x10000000
	portableWSVScroll       = 0x00200000
	portableWSTabStop       = 0x00010000
	portableMainWindowStyle = portableWSOverlapped | portableWSCaption | portableWSSysMenu |
		portableWSThickFrame | portableWSMinimizeBox | portableWSMaximizeBox

	portableWSExClientEdge    = 0x00000200
	portableLBSNotify         = 0x0001
	portableLBSOwnerDraw      = 0x0010
	portableLBSHasStrings     = 0x0040
	portableLBSNoIntegral     = 0x0100
	portableCBSDropDownList   = 0x0003
	portableCBSOwnerDrawFixed = 0x0010
	portableCBSHasStrings     = 0x0200
	portableBSGroupBox        = 0x0007
	portableBSOwnerDraw       = 0x000B
	portableSSLeft            = 0x0000
	portableSSRight           = 0x0002
	portableSSIcon            = 0x0003
	portableSSNoPrefix        = 0x0080
	portableSSCenterImage     = 0x0200
	portableSTMSetIcon        = 0x0170
	portableImageIcon         = 1
	portableLRShared          = 0x00008000
	portableDrawIconNormal    = 0x0003
	portableDIBRGBColors      = 0
	portableBIRGB             = 0
	portableTrayIconSize      = 32
	portableSMCXIcon          = 11
	portableSMCYIcon          = 12
	portableSMCXSmallIcon     = 49
	portableSMCYSmallIcon     = 50
	portableIconSmall         = 0
	portableIconBig           = 1

	portableLBAddString     = 0x0180
	portableLBResetContent  = 0x0184
	portableLBSetCurSel     = 0x0186
	portableLBGetText       = 0x0189
	portableLBGetTextLen    = 0x018A
	portableLBSetItemHeight = 0x01A0
	portableCBAddString     = 0x0143
	portableCBGetCurSel     = 0x0147
	portableCBGetLBText     = 0x0148
	portableCBGetLBTextLen  = 0x0149
	portableCBResetContent  = 0x014B
	portableCBSetCurSel     = 0x014E
	portableCBShowDropDown  = 0x014F
	portableCBSetItemHeight = 0x0153
	portableCBNSelChange    = 1
	portableCBNSelEndOK     = 9
	portableCBNSelEndCancel = 10

	portableControlNetworkList = 1001
	portableControlPrimary     = 1003
	portableControlPaste       = 1004
	portableControlRoute       = 1005
	portableControlStateIcon   = 1006
	portableControlDelete      = 1007

	portableCWUseDefault       = -2147483648
	portableSWHide             = 0
	portableSWShowNormal       = 1
	portableSWShow             = 5
	portableSWRestore          = 9
	portableSWPNoZOrder        = 0x0004
	portableSWPNoActivate      = 0x0010
	portableMBOK               = 0x00000000
	portableMBIconError        = 0x00000010
	portableMBIconWarning      = 0x00000030
	portableMBYesNo            = 0x00000004
	portableMBDefButton2       = 0x00000100
	portableIDYes              = 6
	portableIDCArrow           = 32512
	portableVKBack             = 0x08
	portableVKReturn           = 0x0D
	portableVKControl          = 0x11
	portableVKEscape           = 0x1B
	portableVKV                = 0x56
	portableGARoot             = 2
	portableColorWindow        = 5
	portableColorWindowText    = 8
	portableColorHighlight     = 13
	portableColorHighlightText = 14
	portableColorBtnFace       = 15
	portableColorGrayText      = 17
	portableOFNPathExists      = 0x00000800
	portableOFNFileExists      = 0x00001000
	portableOFNNoChange        = 0x00000008

	portableFWNormal        = 400
	portableFWSemibold      = 600
	portableClearType       = 5
	portableTransparent     = 1
	portableDTLeft          = 0x0000
	portableDTCenter        = 0x0001
	portableDTVCenter       = 0x0004
	portableDTSingleLine    = 0x0020
	portableDTEndEllipsis   = 0x8000
	portableDTNoPrefix      = 0x0800
	portableDTCalcRect      = 0x0400
	portableRDWInvalidate   = 0x0001
	portableRDWErase        = 0x0004
	portableRDWAllChildren  = 0x0080
	portableODSSelected     = 0x0001
	portableODSGrayed       = 0x0002
	portableODSDisabled     = 0x0004
	portableODSFocus        = 0x0010
	portableODSHotLight     = 0x0040
	portableODSComboBoxEdit = 0x1000
	portableNullPen         = 8
	portableGreenColor      = 0x0075A82A
	portableTagBackground   = 0x00F3F7EF
	portableButtonBorder    = 0x00C6C6C6
	portableButtonFocus     = 0x00D77800
	portableButtonHover     = 0x00F7F7F7
	portableButtonPressed   = 0x00EEEEEE
	portablePSSolid         = 0

	portableNIMAdd     = 0x00000000
	portableNIMModify  = 0x00000001
	portableNIMDelete  = 0x00000002
	portableNIFMessage = 0x00000001
	portableNIFIcon    = 0x00000002
	portableNIFTip     = 0x00000004

	portableMFString       = 0x00000000
	portableMFGrayED       = 0x00000001
	portableMFSeparator    = 0x00000800
	portableTPMRightButton = 0x00000002
	portableTPMReturnCmd   = 0x00000100

	portableTrayID          = 1
	portableTrayMenuShow    = 2001
	portableTrayMenuPrimary = 2002
	portableTrayMenuExit    = 2003

	// Layout dimensions are DPI-independent units. The outer window size is
	// derived from this client area with AdjustWindowRectExForDpi.
	portableLayoutMargin       = 5
	portableLayoutGap          = 10
	portableInterfaceHeight    = 154
	portableLocalMinimumHeight = 145
	portableStatusGap          = 8
	portableStatusHeight       = 20
	portableStatusBottomMargin = 2
	portableMinClientWidth     = 584
	portableMinClientHeight    = portableLayoutMargin + portableInterfaceHeight + portableLayoutGap +
		portableLocalMinimumHeight + portableStatusGap + portableStatusHeight + portableStatusBottomMargin

	// Resource group 2 is the favicon (also the executable default). Each ICO
	// has 13 native DPI sizes, so rsrc assigns the second group (logo v4) ID 16.
	portableIconApp   = 2
	portableIconBrand = 16
)

type portablePoint struct{ x, y int32 }

type portableRect struct {
	left, top, right, bottom int32
}

type portableMinMaxInfo struct {
	reserved     portablePoint
	maxSize      portablePoint
	maxPosition  portablePoint
	minTrackSize portablePoint
	maxTrackSize portablePoint
}

type portableDrawItem struct {
	controlType uint32
	controlID   uint32
	itemID      uint32
	itemAction  uint32
	itemState   uint32
	hwndItem    uintptr
	dc          uintptr
	rect        portableRect
	itemData    uintptr
}

type portableMeasureItem struct {
	controlType uint32
	controlID   uint32
	itemID      uint32
	itemWidth   uint32
	itemHeight  uint32
	itemData    uintptr
}

type portableMSG struct {
	hwnd    uintptr
	msg     uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	point   portablePoint
	private uint32
}

type portableWNDClassEx struct {
	size        uint32
	style       uint32
	wndProc     uintptr
	classExtra  int32
	windowExtra int32
	instance    uintptr
	icon        uintptr
	cursor      uintptr
	background  uintptr
	menuName    *uint16
	className   *uint16
	iconSmall   uintptr
}

type portableOpenFileName struct {
	size             uint32
	owner            uintptr
	instance         uintptr
	filter           *uint16
	customFilter     *uint16
	maxCustomFilter  uint32
	filterIndex      uint32
	file             *uint16
	maxFile          uint32
	fileTitle        *uint16
	maxFileTitle     uint32
	initialDir       *uint16
	title            *uint16
	flags            uint32
	fileOffset       uint16
	fileExtension    uint16
	defaultExtension *uint16
	customData       uintptr
	hook             uintptr
	templateName     *uint16
	reserved         unsafe.Pointer
	reservedSize     uint32
	flagsEx          uint32
}

type portableNotifyIconData struct {
	size             uint32
	hwnd             uintptr
	id               uint32
	flags            uint32
	callbackMessage  uint32
	icon             uintptr
	tip              [128]uint16
	state            uint32
	stateMask        uint32
	info             [256]uint16
	timeoutOrVersion uint32
	infoTitle        [64]uint16
	infoFlags        uint32
	guidItem         [16]byte
	balloonIcon      uintptr
}

type portableBitmapInfoHeader struct {
	size          uint32
	width         int32
	height        int32
	planes        uint16
	bitCount      uint16
	compression   uint32
	sizeImage     uint32
	xPelsPerMeter int32
	yPelsPerMeter int32
	clrUsed       uint32
	clrImportant  uint32
}

type portableIconInfo struct {
	icon     int32
	xHotspot uint32
	yHotspot uint32
	mask     uintptr
	color    uintptr
}

type portableGUIControls struct {
	brandIcon        uintptr
	brandName        uintptr
	brandEdition     uintptr
	networkList      uintptr
	interfaceGroup   uintptr
	stateCaption     uintptr
	stateIcon        uintptr
	stateValue       uintptr
	modeCaption      uintptr
	modeValue        uintptr
	deviceCaption    uintptr
	deviceValue      uintptr
	endpointCaption  uintptr
	endpointValue    uintptr
	routeCaption     uintptr
	routeCombo       uintptr
	primaryButton    uintptr
	deleteButton     uintptr
	pasteButton      uintptr
	localGroup       uintptr
	profileCaption   uintptr
	profileValue     uintptr
	storageCaption   uintptr
	storageValue     uintptr
	privilegeCaption uintptr
	privilegeValue   uintptr
	message          uintptr
}

func (controls portableGUIControls) all() []uintptr {
	return []uintptr{
		controls.brandIcon, controls.brandName, controls.brandEdition,
		controls.networkList, controls.interfaceGroup,
		controls.stateCaption, controls.stateIcon, controls.stateValue,
		controls.modeCaption, controls.modeValue,
		controls.deviceCaption, controls.deviceValue,
		controls.endpointCaption, controls.endpointValue,
		controls.routeCaption, controls.routeCombo,
		controls.primaryButton, controls.deleteButton, controls.pasteButton, controls.localGroup,
		controls.profileCaption, controls.profileValue,
		controls.storageCaption, controls.storageValue,
		controls.privilegeCaption, controls.privilegeValue,
		controls.message,
	}
}

var (
	portableUser32   = windows.NewLazySystemDLL("user32.dll")
	portableGDI32    = windows.NewLazySystemDLL("gdi32.dll")
	portableKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	portableShell32  = windows.NewLazySystemDLL("shell32.dll")
	portableComdlg32 = windows.NewLazySystemDLL("comdlg32.dll")

	procRegisterClassEx     = portableUser32.NewProc("RegisterClassExW")
	procAdjustWindowRectEx  = portableUser32.NewProc("AdjustWindowRectEx")
	procAdjustWindowRectDPI = portableUser32.NewProc("AdjustWindowRectExForDpi")
	procCreateWindowEx      = portableUser32.NewProc("CreateWindowExW")
	procDefWindowProc       = portableUser32.NewProc("DefWindowProcW")
	procDestroyWindow       = portableUser32.NewProc("DestroyWindow")
	procShowWindow          = portableUser32.NewProc("ShowWindow")
	procUpdateWindow        = portableUser32.NewProc("UpdateWindow")
	procGetMessage          = portableUser32.NewProc("GetMessageW")
	procTranslateMessage    = portableUser32.NewProc("TranslateMessage")
	procDispatchMessage     = portableUser32.NewProc("DispatchMessageW")
	procPostQuitMessage     = portableUser32.NewProc("PostQuitMessage")
	procPostMessage         = portableUser32.NewProc("PostMessageW")
	procSendMessage         = portableUser32.NewProc("SendMessageW")
	procMessageBox          = portableUser32.NewProc("MessageBoxW")
	procLoadCursor          = portableUser32.NewProc("LoadCursorW")
	procLoadIcon            = portableUser32.NewProc("LoadIconW")
	procLoadImage           = portableUser32.NewProc("LoadImageW")
	procDestroyIcon         = portableUser32.NewProc("DestroyIcon")
	procCreateIconIndirect  = portableUser32.NewProc("CreateIconIndirect")
	procGetSystemMetrics    = portableUser32.NewProc("GetSystemMetrics")
	procGetClientRect       = portableUser32.NewProc("GetClientRect")
	procGetCursorPos        = portableUser32.NewProc("GetCursorPos")
	procGetAncestor         = portableUser32.NewProc("GetAncestor")
	procGetKeyState         = portableUser32.NewProc("GetKeyState")
	procGetWindowText       = portableUser32.NewProc("GetWindowTextW")
	procGetWindowTextLength = portableUser32.NewProc("GetWindowTextLengthW")
	procInvalidateRect      = portableUser32.NewProc("InvalidateRect")
	procRedrawWindow        = portableUser32.NewProc("RedrawWindow")
	procMoveWindow          = portableUser32.NewProc("MoveWindow")
	procSetWindowPos        = portableUser32.NewProc("SetWindowPos")
	procSetWindowText       = portableUser32.NewProc("SetWindowTextW")
	procEnableWindow        = portableUser32.NewProc("EnableWindow")
	procSetForegroundWindow = portableUser32.NewProc("SetForegroundWindow")
	procBringWindowToTop    = portableUser32.NewProc("BringWindowToTop")
	procDrawIconEx          = portableUser32.NewProc("DrawIconEx")
	procCreatePopupMenu     = portableUser32.NewProc("CreatePopupMenu")
	procAppendMenu          = portableUser32.NewProc("AppendMenuW")
	procTrackPopupMenu      = portableUser32.NewProc("TrackPopupMenu")
	procDestroyMenu         = portableUser32.NewProc("DestroyMenu")
	procDrawText            = portableUser32.NewProc("DrawTextW")
	procDrawFocusRect       = portableUser32.NewProc("DrawFocusRect")
	procFillRect            = portableUser32.NewProc("FillRect")
	procGetSysColor         = portableUser32.NewProc("GetSysColor")
	procGetSysColorBrush    = portableUser32.NewProc("GetSysColorBrush")
	procGetDPIForWindow     = portableUser32.NewProc("GetDpiForWindow")
	procGetDPIForSystem     = portableUser32.NewProc("GetDpiForSystem")
	procGetSystemMetricsDPI = portableUser32.NewProc("GetSystemMetricsForDpi")
	procSetDPIAware         = portableUser32.NewProc("SetProcessDpiAwarenessContext")

	procCreateFont         = portableGDI32.NewProc("CreateFontW")
	procCreateCompatibleDC = portableGDI32.NewProc("CreateCompatibleDC")
	procDeleteDC           = portableGDI32.NewProc("DeleteDC")
	procCreateDIBSection   = portableGDI32.NewProc("CreateDIBSection")
	procCreateBitmap       = portableGDI32.NewProc("CreateBitmap")
	procCreatePen          = portableGDI32.NewProc("CreatePen")
	procCreateSolidBrush   = portableGDI32.NewProc("CreateSolidBrush")
	procDeleteObject       = portableGDI32.NewProc("DeleteObject")
	procEllipse            = portableGDI32.NewProc("Ellipse")
	procGetStockObject     = portableGDI32.NewProc("GetStockObject")
	procRoundRect          = portableGDI32.NewProc("RoundRect")
	procSelectObject       = portableGDI32.NewProc("SelectObject")
	procSetBkMode          = portableGDI32.NewProc("SetBkMode")
	procSetTextColor       = portableGDI32.NewProc("SetTextColor")
	procGetModuleHandle    = portableKernel32.NewProc("GetModuleHandleW")
	procDragAcceptFiles    = portableShell32.NewProc("DragAcceptFiles")
	procDragQueryFile      = portableShell32.NewProc("DragQueryFileW")
	procDragFinish         = portableShell32.NewProc("DragFinish")
	procSHDefExtractIcon   = portableShell32.NewProc("SHDefExtractIconW")
	procShellNotifyIcon    = portableShell32.NewProc("Shell_NotifyIconW")
	procGetOpenFileName    = portableComdlg32.NewProc("GetOpenFileNameW")
	procCommDlgError       = portableComdlg32.NewProc("CommDlgExtendedError")

	portableGUIWindows sync.Map
)

func createPortableWindow(app *portableGUI) (uintptr, error) {
	// PER_MONITOR_AWARE_V2. Failure on an older Windows build is harmless.
	procSetDPIAware.Call(^uintptr(3))
	className, _ := windows.UTF16PtrFromString("LoomPortableClientWindow")
	title := "Loom — " + windowsEditionLabel(app.edition)
	titlePtr, _ := windows.UTF16PtrFromString(title)
	instance, _, _ := procGetModuleHandle.Call(0)
	cursor, _, _ := procLoadCursor.Call(0, portableIDCArrow)
	dpiValue, _, _ := procGetDPIForSystem.Call()
	dpi := int32(dpiValue)
	if dpi == 0 {
		dpi = 96
	}
	icon := loadPortableAppIcon(instance, portableSMCXIcon, portableSMCYIcon, dpi)
	iconSmall := loadPortableAppIcon(instance, portableSMCXSmallIcon, portableSMCYSmallIcon, dpi)
	wndClass := portableWNDClassEx{
		size:       uint32(unsafe.Sizeof(portableWNDClassEx{})),
		wndProc:    windows.NewCallback(portableWindowProc),
		instance:   instance,
		icon:       icon,
		cursor:     cursor,
		background: portableColorWindow + 1,
		className:  className,
		iconSmall:  iconSmall,
	}
	atom, _, registerErr := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wndClass)))
	if atom == 0 && !errors.Is(registerErr, windows.ERROR_CLASS_ALREADY_EXISTS) {
		return 0, fmt.Errorf("register Windows client UI: %w", registerErr)
	}
	style := uintptr(portableMainWindowStyle)
	width, height := portableMinimumWindowSize(dpi)
	screenWidth, _, _ := procGetSystemMetrics.Call(0)
	screenHeight, _, _ := procGetSystemMetrics.Call(1)
	x, y := int32(portableCWUseDefault), int32(portableCWUseDefault)
	if screenWidth > uintptr(width) && screenHeight > uintptr(height) {
		x = (int32(screenWidth) - width) / 2
		y = (int32(screenHeight) - height) / 2
	}
	hwnd, _, createErr := procCreateWindowEx.Call(
		0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(titlePtr)), style,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height), 0, 0, instance, 0,
	)
	if hwnd == 0 {
		return 0, fmt.Errorf("create Windows client UI: %w", createErr)
	}
	// GetDpiForSystem can still report the virtualized system DPI before the
	// window is attached to its monitor. Correct the initial size using the
	// window's real DPI so controls and the bottom status row cannot overlap.
	if windowDPI, _, _ := procGetDPIForWindow.Call(hwnd); windowDPI != 0 && int32(windowDPI) != dpi {
		dpi = int32(windowDPI)
		width, height = portableMinimumWindowSize(dpi)
		screenWidth, _, _ = procGetSystemMetrics.Call(0)
		screenHeight, _, _ = procGetSystemMetrics.Call(1)
		if screenWidth > uintptr(width) && screenHeight > uintptr(height) {
			x = (int32(screenWidth) - width) / 2
			y = (int32(screenHeight) - height) / 2
		}
		procMoveWindow.Call(hwnd, uintptr(x), uintptr(y), uintptr(width), uintptr(height), 0)
	}
	app.windowDPI = dpi
	runtime.KeepAlive(wndClass)
	return hwnd, nil
}

func portableMinimumWindowSize(dpi int32) (int32, int32) {
	if dpi <= 0 {
		dpi = 96
	}
	rect := portableRect{
		right:  int32(portableMinClientWidth) * dpi / 96,
		bottom: int32(portableMinClientHeight) * dpi / 96,
	}
	adjusted := false
	if err := procAdjustWindowRectDPI.Find(); err == nil {
		result, _, _ := procAdjustWindowRectDPI.Call(
			uintptr(unsafe.Pointer(&rect)), portableMainWindowStyle, 0, 0, uintptr(dpi),
		)
		adjusted = result != 0
	}
	if !adjusted {
		result, _, _ := procAdjustWindowRectEx.Call(
			uintptr(unsafe.Pointer(&rect)), portableMainWindowStyle, 0, 0,
		)
		adjusted = result != 0
	}
	if !adjusted {
		return rect.right, rect.bottom
	}
	return rect.right - rect.left, rect.bottom - rect.top
}

func portableSystemMetricForDPI(metric, dpi int32) int32 {
	if err := procGetSystemMetricsDPI.Find(); err == nil {
		if value, _, _ := procGetSystemMetricsDPI.Call(uintptr(metric), uintptr(dpi)); value != 0 {
			return int32(value)
		}
	}
	value, _, _ := procGetSystemMetrics.Call(uintptr(metric))
	return int32(value)
}

func loadPortableAppIcon(instance uintptr, widthMetric, heightMetric, dpi int32) uintptr {
	width := portableSystemMetricForDPI(widthMetric, dpi)
	height := portableSystemMetricForDPI(heightMetric, dpi)
	icon, _, _ := procLoadImage.Call(instance, portableIconApp, portableImageIcon, uintptr(width), uintptr(height), portableLRShared)
	if icon == 0 {
		icon, _, _ = procLoadIcon.Call(instance, portableIconApp)
	}
	return icon
}

func (app *portableGUI) createControls() error {
	instance, _, _ := procGetModuleHandle.Call(0)
	create := func(target *uintptr, exStyle uintptr, className, text string, style, id uintptr) error {
		classPtr, _ := windows.UTF16PtrFromString(className)
		textPtr, _ := windows.UTF16PtrFromString(text)
		hwnd, _, callErr := procCreateWindowEx.Call(
			exStyle,
			uintptr(unsafe.Pointer(classPtr)),
			uintptr(unsafe.Pointer(textPtr)),
			portableWSChild|portableWSVisible|style,
			0, 0, 10, 10,
			app.hwnd, id, instance, 0,
		)
		if hwnd == 0 {
			return fmt.Errorf("create Windows control %q: %w", className, callErr)
		}
		*target = hwnd
		return nil
	}

	specs := []struct {
		target    *uintptr
		exStyle   uintptr
		className string
		text      string
		style     uintptr
		id        uintptr
	}{
		{&app.controls.brandIcon, 0, "STATIC", "", portableSSIcon, 0},
		{&app.controls.brandName, 0, "STATIC", "Loom", portableSSLeft | portableSSNoPrefix | portableSSCenterImage, 0},
		{&app.controls.brandEdition, 0, "STATIC", "", portableSSLeft | portableSSNoPrefix | portableSSCenterImage, 0},
		{&app.controls.networkList, portableWSExClientEdge, "LISTBOX", "", portableWSVScroll | portableWSTabStop | portableLBSNotify | portableLBSOwnerDraw | portableLBSHasStrings | portableLBSNoIntegral, portableControlNetworkList},
		{&app.controls.interfaceGroup, 0, "BUTTON", "连接: Loom 网络", portableBSGroupBox, 0},
		{&app.controls.stateCaption, 0, "STATIC", "状态:", portableSSRight | portableSSNoPrefix, 0},
		{&app.controls.stateIcon, 0, "STATIC", "", portableSSIcon | portableSSCenterImage, portableControlStateIcon},
		{&app.controls.stateValue, 0, "STATIC", "正在检查", portableSSLeft | portableSSNoPrefix | portableSSCenterImage, 0},
		{&app.controls.modeCaption, 0, "STATIC", "模式:", portableSSRight | portableSSNoPrefix, 0},
		{&app.controls.modeValue, 0, "STATIC", "", portableSSLeft | portableSSNoPrefix, 0},
		{&app.controls.endpointCaption, 0, "STATIC", "本地入口:", portableSSRight | portableSSNoPrefix, 0},
		{&app.controls.endpointValue, 0, "STATIC", "", portableSSLeft | portableSSNoPrefix, 0},
		{&app.controls.routeCaption, 0, "STATIC", "出口:", portableSSRight | portableSSNoPrefix, 0},
		{&app.controls.routeCombo, portableWSExClientEdge, "COMBOBOX", "", portableWSVScroll | portableWSTabStop | portableCBSDropDownList | portableCBSOwnerDrawFixed | portableCBSHasStrings, portableControlRoute},
		{&app.controls.primaryButton, 0, "BUTTON", "请稍候…", portableWSTabStop | portableBSOwnerDraw, portableControlPrimary},
		{&app.controls.deleteButton, 0, "BUTTON", "删除…", portableWSTabStop | portableBSOwnerDraw, portableControlDelete},
		{&app.controls.pasteButton, 0, "BUTTON", "粘贴二维码", portableWSTabStop | portableBSOwnerDraw, portableControlPaste},
		{&app.controls.localGroup, 0, "BUTTON", "设备", portableBSGroupBox, 0},
		{&app.controls.deviceCaption, 0, "STATIC", "Device:", portableSSRight | portableSSNoPrefix, 0},
		{&app.controls.deviceValue, 0, "STATIC", "", portableSSLeft | portableSSNoPrefix, 0},
		{&app.controls.profileCaption, 0, "STATIC", "配置:", portableSSRight | portableSSNoPrefix, 0},
		{&app.controls.profileValue, 0, "STATIC", "", portableSSLeft | portableSSNoPrefix, 0},
		{&app.controls.storageCaption, 0, "STATIC", "状态目录:", portableSSRight | portableSSNoPrefix, 0},
		{&app.controls.storageValue, 0, "STATIC", "", portableSSLeft | portableSSNoPrefix, 0},
		{&app.controls.privilegeCaption, 0, "STATIC", "权限:", portableSSRight | portableSSNoPrefix, 0},
		{&app.controls.privilegeValue, 0, "STATIC", "", portableSSLeft | portableSSNoPrefix, 0},
		{&app.controls.message, 0, "STATIC", "", portableSSLeft | portableSSNoPrefix, 0},
	}
	for _, spec := range specs {
		if err := create(spec.target, spec.exStyle, spec.className, spec.text, spec.style, spec.id); err != nil {
			return err
		}
	}

	if err := app.updateFonts(); err != nil {
		return err
	}
	statusIcon, err := loadPortableConnectedIcon(app.scale(16))
	if err != nil {
		return err
	}
	app.statusIcon = statusIcon
	traySize := uintptr(portableTrayIconSize)
	trayBase, _, _ := procLoadImage.Call(instance, portableIconApp, portableImageIcon, traySize, traySize, portableLRShared)
	if trayBase == 0 {
		trayBase, _, _ = procLoadIcon.Call(instance, portableIconApp)
	}
	trayConnected, err := composePortableConnectedTrayIcon(trayBase, statusIcon, portableTrayIconSize)
	if err != nil {
		return err
	}
	app.trayConnectedIcon = trayConnected
	mode := windowsEditionLabel(app.edition)
	setPortableControlText(app.controls.brandEdition, mode)
	brandSize := uintptr(app.scale(48))
	icon, _, _ := procLoadImage.Call(instance, portableIconBrand, portableImageIcon, brandSize, brandSize, portableLRShared)
	if icon == 0 {
		icon, _, _ = procLoadIcon.Call(instance, portableIconBrand)
	}
	procSendMessage.Call(app.controls.brandIcon, portableSTMSetIcon, icon, 0)
	app.layoutControls()
	return nil
}

func (app *portableGUI) updateFonts() error {
	dpi := app.dpi()
	regular, err := createPortableFont(9, portableFWNormal, dpi)
	if err != nil {
		return err
	}
	brand, err := createPortableFont(11, portableFWSemibold, dpi)
	if err != nil {
		procDeleteObject.Call(regular)
		return err
	}
	// 所有控件换用新字体后才能释放旧字体；本轮布局完成后统一重绘。
	for _, control := range app.controls.all() {
		procSendMessage.Call(control, portableWMSetFont, regular, 0)
	}
	procSendMessage.Call(app.controls.brandName, portableWMSetFont, brand, 0)
	procSendMessage.Call(app.controls.stateValue, portableWMSetFont, brand, 0)
	app.deleteFonts()
	app.fonts = []uintptr{regular, brand}
	// Owner-draw 控件不会根据 WM_SETFONT 自动重新测量行高。
	procSendMessage.Call(app.controls.networkList, portableLBSetItemHeight, 0, uintptr(app.scale(23)))
	procSendMessage.Call(app.controls.routeCombo, portableCBSetItemHeight, ^uintptr(0), uintptr(app.scale(23)))
	procSendMessage.Call(app.controls.routeCombo, portableCBSetItemHeight, 0, uintptr(app.scale(23)))
	return nil
}

func createPortableFont(points, weight, dpi int32) (uintptr, error) {
	return createPortableFontFace(points, weight, dpi, "Segoe UI")
}

func createPortableFontFace(points, weight, dpi int32, faceName string) (uintptr, error) {
	height := -points * dpi / 72
	face, _ := windows.UTF16PtrFromString(faceName)
	font, _, callErr := procCreateFont.Call(
		uintptr(uint32(height)), 0, 0, 0, uintptr(weight), 0, 0, 0,
		1, 0, 0, portableClearType, 0, uintptr(unsafe.Pointer(face)),
	)
	if font == 0 {
		return 0, fmt.Errorf("create Windows UI font: %w", callErr)
	}
	return font, nil
}

func (app *portableGUI) deleteFonts() {
	for _, font := range app.fonts {
		if font != 0 {
			procDeleteObject.Call(font)
		}
	}
	app.fonts = nil
}

func (app *portableGUI) deleteIcons() {
	if app.statusIcon != 0 {
		procDestroyIcon.Call(app.statusIcon)
		app.statusIcon = 0
	}
	if app.trayConnectedIcon != 0 {
		procDestroyIcon.Call(app.trayConnectedIcon)
		app.trayConnectedIcon = 0
	}
}

func loadPortableConnectedIcon(size int32) (uintptr, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return 0, fmt.Errorf("locate Windows system icons: %w", err)
	}
	path, _ := windows.UTF16PtrFromString(filepath.Join(systemDirectory, "imageres.dll"))
	var large, small uintptr
	packedSize := uintptr(uint32(size)&0xffff | uint32(size)<<16)
	iconIndex := int32(-106) // Same native active-state resource used by WireGuard for Windows.
	result, _, callErr := procSHDefExtractIcon.Call(
		uintptr(unsafe.Pointer(path)), uintptr(iconIndex), 0,
		uintptr(unsafe.Pointer(&large)), uintptr(unsafe.Pointer(&small)), packedSize,
	)
	if int32(result) < 0 || (large == 0 && small == 0) {
		return 0, fmt.Errorf("load Windows connected-state icon: HRESULT 0x%x: %w", uint32(result), callErr)
	}
	if small != 0 {
		if large != 0 {
			procDestroyIcon.Call(large)
		}
		return small, nil
	}
	return large, nil
}

func composePortableConnectedTrayIcon(baseIcon, connectedIcon uintptr, size int32) (uintptr, error) {
	if baseIcon == 0 || connectedIcon == 0 || size < 2 {
		return 0, errors.New("compose connected tray icon: missing source icon")
	}
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return 0, errors.New("compose connected tray icon: get screen DC")
	}
	defer procReleaseDC.Call(0, screenDC)
	memoryDC, _, _ := procCreateCompatibleDC.Call(screenDC)
	if memoryDC == 0 {
		return 0, errors.New("compose connected tray icon: create memory DC")
	}
	defer procDeleteDC.Call(memoryDC)

	header := portableBitmapInfoHeader{
		size:        uint32(unsafe.Sizeof(portableBitmapInfoHeader{})),
		width:       size,
		height:      -size,
		planes:      1,
		bitCount:    32,
		compression: portableBIRGB,
		sizeImage:   uint32(size * size * 4),
	}
	var pixels uintptr
	colorBitmap, _, _ := procCreateDIBSection.Call(
		memoryDC, uintptr(unsafe.Pointer(&header)), portableDIBRGBColors,
		uintptr(unsafe.Pointer(&pixels)), 0, 0,
	)
	if colorBitmap == 0 || pixels == 0 {
		return 0, errors.New("compose connected tray icon: create color bitmap")
	}
	defer procDeleteObject.Call(colorBitmap)
	clear(unsafe.Slice((*byte)(unsafe.Pointer(pixels)), int(size*size*4)))
	oldBitmap, _, _ := procSelectObject.Call(memoryDC, colorBitmap)
	if oldBitmap == 0 {
		return 0, errors.New("compose connected tray icon: select color bitmap")
	}
	selected := true
	defer func() {
		if selected {
			procSelectObject.Call(memoryDC, oldBitmap)
		}
	}()
	if drawn, _, _ := procDrawIconEx.Call(memoryDC, 0, 0, baseIcon, uintptr(size), uintptr(size), 0, 0, portableDrawIconNormal); drawn == 0 {
		return 0, errors.New("compose connected tray icon: draw favicon")
	}
	// Start from the requested half-size badge, then enlarge it by 40% so the
	// connected state remains legible in Windows' compact notification area.
	overlaySize := size * 7 / 10
	overlayOffset := size - overlaySize
	if drawn, _, _ := procDrawIconEx.Call(memoryDC, uintptr(overlayOffset), uintptr(overlayOffset), connectedIcon, uintptr(overlaySize), uintptr(overlaySize), 0, 0, portableDrawIconNormal); drawn == 0 {
		return 0, errors.New("compose connected tray icon: draw connected shield")
	}
	procSelectObject.Call(memoryDC, oldBitmap)
	selected = false

	maskBitmap, _, _ := procCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, 0)
	if maskBitmap == 0 {
		return 0, errors.New("compose connected tray icon: create mask bitmap")
	}
	defer procDeleteObject.Call(maskBitmap)
	info := portableIconInfo{icon: 1, mask: maskBitmap, color: colorBitmap}
	icon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&info)))
	if icon == 0 {
		return 0, errors.New("compose connected tray icon: create icon")
	}
	runtime.KeepAlive(header)
	runtime.KeepAlive(info)
	return icon, nil
}

func (app *portableGUI) dpi() int32 {
	if app.windowDPI > 0 {
		return app.windowDPI
	}
	dpi, _, _ := procGetDPIForWindow.Call(app.hwnd)
	if dpi == 0 {
		return 96
	}
	return int32(dpi)
}

func (app *portableGUI) changeDPI(dpi int32, suggested portableRect) {
	if dpi <= 0 {
		return
	}
	// WM_DPICHANGED 给出本窗口的新 DPI；字体、图标和布局必须使用同一值。
	app.windowDPI = dpi
	if err := app.updateFonts(); err != nil {
		log.Printf("更新 Windows 缩放字体失败: %v", err)
	}
	if icon, err := loadPortableConnectedIcon(app.scale(16)); err != nil {
		log.Printf("更新 Windows 缩放图标失败: %v", err)
	} else {
		old := app.statusIcon
		app.statusIcon = icon
		stateIcon := uintptr(0)
		if app.snapshot().state == guiConnected {
			stateIcon = icon
		}
		procSendMessage.Call(app.controls.stateIcon, portableSTMSetIcon, stateIcon, 0)
		if old != 0 {
			procDestroyIcon.Call(old)
		}
	}
	app.updateBrandIcon(app.snapshot())
	procSetWindowPos.Call(app.hwnd, 0,
		uintptr(suggested.left), uintptr(suggested.top),
		uintptr(suggested.right-suggested.left), uintptr(suggested.bottom-suggested.top),
		portableSWPNoZOrder|portableSWPNoActivate,
	)
	app.layoutControls()
}

func (app *portableGUI) scale(value int32) int32 {
	return value * app.dpi() / 96
}

func (app *portableGUI) layoutControls() {
	if app.controls.networkList == 0 {
		return
	}
	var client portableRect
	if result, _, _ := procGetClientRect.Call(app.hwnd, uintptr(unsafe.Pointer(&client))); result == 0 {
		return
	}
	// 控件移动时会复用旧像素；切换加入页后，旧标题可能被复制到新标题下方。
	// 完成整轮布局后再清除背景并重绘所有子控件，避免中间布局留下残影。
	defer procRedrawWindow.Call(app.hwnd, 0, 0, portableRDWInvalidate|portableRDWErase|portableRDWAllChildren)
	width := client.right - client.left
	height := client.bottom - client.top
	s := app.scale
	margin := s(portableLayoutMargin)
	gap := s(portableLayoutGap)
	leftWidth := s(140)
	buttonHeight := s(26)
	rightX := margin + leftWidth + gap
	rightWidth := width - rightX - margin
	if rightWidth < s(300) {
		rightWidth = s(300)
	}
	move := func(control uintptr, x, y, w, h int32) {
		if control != 0 {
			procMoveWindow.Call(control, uintptr(x), uintptr(y), uintptr(w), uintptr(h), 0)
		}
	}

	snapshot := app.snapshot()
	joinedOnly := []uintptr{
		app.controls.networkList, app.controls.interfaceGroup,
		app.controls.stateCaption, app.controls.stateIcon, app.controls.modeCaption, app.controls.modeValue,
		app.controls.endpointCaption, app.controls.endpointValue,
		app.controls.routeCaption, app.controls.routeCombo,
		app.controls.deleteButton,
		app.controls.localGroup, app.controls.deviceCaption, app.controls.deviceValue,
		app.controls.profileCaption, app.controls.profileValue,
		app.controls.storageCaption, app.controls.storageValue,
		app.controls.privilegeCaption, app.controls.privilegeValue,
	}
	for _, control := range joinedOnly {
		setPortableControlVisible(control, snapshot.joined)
	}
	// The local proxy endpoint belongs in the bottom status line, not among
	// connection controls. Keep these legacy controls hidden in both states.
	setPortableControlVisible(app.controls.endpointCaption, false)
	setPortableControlVisible(app.controls.endpointValue, false)
	for _, control := range []uintptr{
		app.controls.brandIcon, app.controls.brandName, app.controls.brandEdition,
		app.controls.stateValue, app.controls.primaryButton, app.controls.pasteButton, app.controls.message,
	} {
		setPortableControlVisible(control, true)
	}
	if !snapshot.joined {
		brandLeft := margin + s(12)
		brandTop := margin + s(10)
		move(app.controls.brandIcon, brandLeft, brandTop, s(48), s(48))
		move(app.controls.brandName, brandLeft+s(58), brandTop+s(4), s(210), s(20))
		move(app.controls.brandEdition, brandLeft+s(58), brandTop+s(24), s(210), s(20))

		contentWidth := s(360)
		contentLeft := (width - contentWidth) / 2
		contentTop := s(125)
		move(app.controls.stateValue, contentLeft, contentTop, contentWidth, s(26))
		move(app.controls.message, contentLeft, contentTop+s(38), contentWidth, s(62))
		move(app.controls.primaryButton, contentLeft, contentTop+s(108), s(120), buttonHeight)
		move(app.controls.pasteButton, contentLeft+s(130), contentTop+s(108), s(120), buttonHeight)
		return
	}

	brandTop := margin + s(3)
	move(app.controls.brandIcon, margin+s(5), brandTop, s(48), s(48))
	move(app.controls.brandName, margin+s(60), brandTop+s(4), s(80), s(20))
	move(app.controls.brandEdition, margin+s(60), brandTop+s(24), s(80), s(20))
	listTop := margin + s(60)

	interfaceTop := margin
	interfaceHeight := s(portableInterfaceHeight)
	move(app.controls.interfaceGroup, rightX, interfaceTop, rightWidth, interfaceHeight)
	captionX := rightX + s(10)
	captionWidth := s(82)
	valueX := captionX + captionWidth + s(8)
	valueWidth := rightWidth - (valueX - rightX) - s(12)
	rowTop := interfaceTop + s(28)
	rowHeight := s(28)
	move(app.controls.stateCaption, captionX, rowTop, captionWidth, s(20))
	move(app.controls.stateIcon, valueX, rowTop, s(20), s(20))
	move(app.controls.stateValue, valueX+s(24), rowTop, valueWidth-s(24), s(20))
	interfaceRows := []struct {
		caption uintptr
		value   uintptr
	}{
		{app.controls.modeCaption, app.controls.modeValue},
		{app.controls.routeCaption, app.controls.routeCombo},
	}
	for index, row := range interfaceRows {
		y := rowTop + int32(index+1)*rowHeight
		move(row.caption, captionX, y, captionWidth, s(20))
		if row.value == app.controls.routeCombo {
			move(row.value, valueX, y-s(3), valueWidth, s(180))
		} else {
			move(row.value, valueX, y, valueWidth, s(20))
		}
	}
	primaryWidth := s(105)
	move(app.controls.primaryButton, valueX, interfaceTop+s(117), primaryWidth, buttonHeight)
	move(app.controls.deleteButton, valueX+primaryWidth+s(10), interfaceTop+s(117), s(80), buttonHeight)
	setPortableControlVisible(app.controls.pasteButton, false)

	localTop := interfaceTop + interfaceHeight + gap
	messageHeight := s(portableStatusHeight)
	messageTop := height - s(portableStatusBottomMargin) - messageHeight
	localHeight := messageTop - s(portableStatusGap) - localTop
	if localHeight < s(portableLocalMinimumHeight) {
		localHeight = s(portableLocalMinimumHeight)
	}
	move(app.controls.networkList, margin, listTop, leftWidth, localTop+localHeight-listTop)
	move(app.controls.localGroup, rightX, localTop, rightWidth, localHeight)
	localRows := []struct {
		caption uintptr
		value   uintptr
	}{
		{app.controls.deviceCaption, app.controls.deviceValue},
		{app.controls.profileCaption, app.controls.profileValue},
		{app.controls.storageCaption, app.controls.storageValue},
		{app.controls.privilegeCaption, app.controls.privilegeValue},
	}
	for index, row := range localRows {
		y := localTop + s(29) + int32(index)*rowHeight
		move(row.caption, captionX, y, captionWidth, s(20))
		move(row.value, valueX, y, valueWidth, s(20))
	}
	messageInset := margin + s(5)
	move(app.controls.message, messageInset, messageTop, width-2*messageInset, messageHeight)
}

func (app *portableGUI) renderControls() {
	if app.controls.networkList == 0 {
		return
	}
	snapshot := app.snapshot()
	app.layoutControls()
	stateText, message, primaryText, primaryEnabled := app.presentation(snapshot)
	if snapshot.routeDetail != "" {
		if message != "" {
			message += "  "
		}
		message += snapshot.routeDetail
	}
	setPortableControlText(app.controls.stateValue, stateText)
	stateIcon := uintptr(0)
	if snapshot.state == guiConnected {
		stateIcon = app.statusIcon
	}
	procSendMessage.Call(app.controls.stateIcon, portableSTMSetIcon, stateIcon, 0)
	setPortableControlText(app.controls.message, message)
	setPortableControlText(app.controls.primaryButton, primaryText)
	enablePortableControl(app.controls.primaryButton, primaryEnabled)
	setPortableControlText(app.controls.deleteButton, "删除…")
	deleteEnabled := snapshot.joined && (snapshot.state == guiStopped || snapshot.state == guiError || snapshot.state == guiNeedsElevation)
	enablePortableControl(app.controls.deleteButton, deleteEnabled)
	setPortableControlText(app.controls.pasteButton, "粘贴二维码")
	pasteEnabled := primaryEnabled && !snapshot.joined && (snapshot.state == guiNeedsJoin || snapshot.state == guiError)
	enablePortableControl(app.controls.pasteButton, pasteEnabled)

	procSendMessage.Call(app.controls.networkList, portableLBResetContent, 0, 0)
	if snapshot.joined {
		entryPtr, _ := windows.UTF16PtrFromString(snapshot.deviceID)
		procSendMessage.Call(app.controls.networkList, portableLBAddString, 0, uintptr(unsafe.Pointer(entryPtr)))
		procSendMessage.Call(app.controls.networkList, portableLBSetCurSel, 0, 0)
		runtime.KeepAlive(entryPtr)
		setPortableControlText(app.controls.interfaceGroup, "连接: Loom 网络")
		setPortableControlText(app.controls.localGroup, "设备: "+snapshot.deviceID)
	} else {
		setPortableControlText(app.controls.interfaceGroup, "加入 Loom 网络")
		setPortableControlText(app.controls.localGroup, "设备")
	}

	mode := windowsEditionLabel(app.edition)
	deviceValue := "尚未绑定"
	profileValue := "未导入"
	endpointValue := "—"
	if snapshot.joined {
		deviceValue = snapshot.deviceID
		profileValue = "中控签名配置（只读）"
		endpointValue = "127.0.0.1:1080  (HTTP / SOCKS)"
	}
	setPortableControlText(app.controls.modeValue, mode)
	setPortableControlText(app.controls.deviceValue, deviceValue)
	setPortableControlText(app.controls.endpointValue, endpointValue)
	setPortableControlText(app.controls.profileValue, profileValue)
	setPortableControlText(app.controls.storageValue, app.root)

	privilege := "普通用户"
	if windows.GetCurrentProcessToken().IsElevated() {
		privilege = "管理员"
	}
	setPortableControlText(app.controls.privilegeValue, fmt.Sprintf("%s  ·  Windows/%s", privilege, runtime.GOARCH))
	routeSelectable := portableRouteSelectable(snapshot)
	if !routeSelectable {
		app.routeFiltering = false
		app.routeFilter = ""
	}
	app.renderRouteCombo(snapshot)
	enablePortableControl(app.controls.routeCombo, routeSelectable)
	app.updateBrandIcon(snapshot)
	app.modifyTrayIcon(snapshot)
}

func (app *portableGUI) updateBrandIcon(_ portableGUISnapshot) {
	instance, _, _ := procGetModuleHandle.Call(0)
	brandSize := uintptr(app.scale(48))
	icon, _, _ := procLoadImage.Call(instance, portableIconBrand, portableImageIcon, brandSize, brandSize, portableLRShared)
	if icon == 0 {
		icon, _, _ = procLoadIcon.Call(instance, portableIconBrand)
	}
	procSendMessage.Call(app.controls.brandIcon, portableSTMSetIcon, icon, 0)
	dpi := app.dpi()
	smallIcon := loadPortableAppIcon(instance, portableSMCXSmallIcon, portableSMCYSmallIcon, dpi)
	bigIcon := loadPortableAppIcon(instance, portableSMCXIcon, portableSMCYIcon, dpi)
	procSendMessage.Call(app.hwnd, portableWMSetIcon, portableIconSmall, smallIcon)
	procSendMessage.Call(app.hwnd, portableWMSetIcon, portableIconBig, bigIcon)
}

func (app *portableGUI) addTrayIcon() error {
	data := app.trayIconData(app.snapshot())
	result, _, callErr := procShellNotifyIcon.Call(portableNIMAdd, uintptr(unsafe.Pointer(&data)))
	if result == 0 {
		return fmt.Errorf("add Windows tray icon: %w", callErr)
	}
	app.trayAdded = true
	return nil
}

func (app *portableGUI) modifyTrayIcon(snapshot portableGUISnapshot) {
	if !app.trayAdded {
		return
	}
	data := app.trayIconData(snapshot)
	procShellNotifyIcon.Call(portableNIMModify, uintptr(unsafe.Pointer(&data)))
}

func (app *portableGUI) removeTrayIcon() {
	if !app.trayAdded {
		return
	}
	data := portableNotifyIconData{
		size: uint32(unsafe.Sizeof(portableNotifyIconData{})),
		hwnd: app.hwnd,
		id:   portableTrayID,
	}
	procShellNotifyIcon.Call(portableNIMDelete, uintptr(unsafe.Pointer(&data)))
	app.trayAdded = false
}

func (app *portableGUI) trayIconData(snapshot portableGUISnapshot) portableNotifyIconData {
	instance, _, _ := procGetModuleHandle.Call(0)
	icon, _, _ := procLoadIcon.Call(instance, portableIconApp)
	if snapshot.state == guiConnected && app.trayConnectedIcon != 0 {
		icon = app.trayConnectedIcon
	}
	stateText, _, _, _ := app.presentation(snapshot)
	mode := windowsEditionLabel(app.edition)
	data := portableNotifyIconData{
		size:            uint32(unsafe.Sizeof(portableNotifyIconData{})),
		hwnd:            app.hwnd,
		id:              portableTrayID,
		flags:           portableNIFMessage | portableNIFIcon | portableNIFTip,
		callbackMessage: portableWMAppTray,
		icon:            icon,
	}
	tip, _ := windows.UTF16FromString("Loom — " + mode + " — " + stateText)
	if len(tip) > len(data.tip) {
		tip = tip[:len(data.tip)]
		tip[len(tip)-1] = 0
	}
	copy(data.tip[:], tip)
	return data
}

func (app *portableGUI) showMainWindow() {
	procShowWindow.Call(app.hwnd, portableSWRestore)
	procBringWindowToTop.Call(app.hwnd)
	procSetForegroundWindow.Call(app.hwnd)
}

func (app *portableGUI) showTrayMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	appendPortableMenuText(menu, portableMFString, portableTrayMenuShow, "显示窗口")
	_, _, button, enabled := app.presentation(app.snapshot())
	primaryFlags := uintptr(portableMFString)
	if !enabled {
		primaryFlags |= portableMFGrayED
	}
	appendPortableMenuText(menu, primaryFlags, portableTrayMenuPrimary, button)
	procAppendMenu.Call(menu, portableMFSeparator, 0, 0)
	appendPortableMenuText(menu, portableMFString, portableTrayMenuExit, "退出 Loom")
	var point portablePoint
	if result, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&point))); result == 0 {
		return
	}
	procSetForegroundWindow.Call(app.hwnd)
	command, _, _ := procTrackPopupMenu.Call(
		menu, portableTPMRightButton|portableTPMReturnCmd,
		uintptr(point.x), uintptr(point.y), 0, app.hwnd, 0,
	)
	switch command {
	case portableTrayMenuShow:
		app.showMainWindow()
	case portableTrayMenuPrimary:
		if enabled {
			app.primaryAction()
		}
	case portableTrayMenuExit:
		postPortableMessage(app.hwnd, portableWMAppExit, 0, 0)
	}
	postPortableMessage(app.hwnd, portableWMNull, 0, 0)
}

func appendPortableMenuText(menu, flags, id uintptr, label string) {
	wide, _ := windows.UTF16PtrFromString(label)
	procAppendMenu.Call(menu, flags, id, uintptr(unsafe.Pointer(wide)))
	runtime.KeepAlive(wide)
}

func (app *portableGUI) presentation(snapshot portableGUISnapshot) (state, message, button string, enabled bool) {
	detail := snapshot.detail
	switch snapshot.state {
	case guiLoading:
		return "正在检查", "正在检查本机身份和发行包。", "请稍候…", false
	case guiNeedsJoin:
		return "尚未加入 Loom 网络", "在中控页面复制二维码后按 Ctrl+V，或粘贴、选择、拖入 PNG / .loom-invite 文件。", "选择文件…", true
	case guiJoining:
		return "正在加入", detail, "正在导入…", false
	case guiNeedsElevation:
		return "需要管理员权限", detail, "管理员启动", true
	case guiStarting:
		return "正在连接", detail, "断开", true
	case guiConnected:
		return "已连接", detail, "断开", true
	case guiStopping:
		return "正在断开", detail, "正在断开…", false
	case guiStopped:
		return "已断开", detail, "连接", true
	case guiError:
		if snapshot.joined {
			return "连接错误", detail, "重新连接", true
		}
		return "导入失败", detail, "重新选择…", true
	default:
		return "未知状态", detail, "连接", false
	}
}

func setPortableControlText(hwnd uintptr, value string) {
	wide, _ := windows.UTF16PtrFromString(value)
	procSetWindowText.Call(hwnd, uintptr(unsafe.Pointer(wide)))
	runtime.KeepAlive(wide)
}

func enablePortableControl(hwnd uintptr, enabled bool) {
	value := uintptr(0)
	if enabled {
		value = 1
	}
	procEnableWindow.Call(hwnd, value)
}

func setPortableControlVisible(hwnd uintptr, visible bool) {
	command := uintptr(portableSWHide)
	if visible {
		command = portableSWShow
	}
	procShowWindow.Call(hwnd, command)
}

func showPortableWindow(hwnd uintptr) {
	procShowWindow.Call(hwnd, portableSWShowNormal)
	procUpdateWindow.Call(hwnd)
}

func runPortableMessageLoop() error {
	var message portableMSG
	for {
		result, _, err := procGetMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) == -1 {
			return fmt.Errorf("read Windows client UI message: %w", err)
		}
		if result == 0 {
			return nil
		}
		if handlePortableRouteFilter(message) {
			continue
		}
		if handlePortablePasteShortcut(message) {
			continue
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&message)))
	}
}

func handlePortableRouteFilter(message portableMSG) bool {
	root, _, _ := procGetAncestor.Call(message.hwnd, portableGARoot)
	value, found := portableGUIWindows.Load(root)
	app, ok := value.(*portableGUI)
	if !found || !ok || message.hwnd != app.controls.routeCombo {
		return false
	}
	snapshot := app.snapshot()
	if !portableRouteSelectable(snapshot) {
		return false
	}
	switch message.msg {
	case portableWMKeyDown:
		switch message.wParam {
		case portableVKBack:
			query := ""
			if app.routeFiltering {
				runes := []rune(app.routeFilter)
				if len(runes) > 0 {
					query = string(runes[:len(runes)-1])
				}
			}
			app.applyRouteFilter(snapshot, query)
			return true
		case portableVKEscape:
			if app.routeFiltering {
				app.cancelRouteFilter(snapshot)
				return true
			}
		case portableVKReturn:
			if app.routeFiltering {
				selection, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
				if selection == ^uintptr(0) && len(app.routeVisible) == 1 {
					app.routeUpdating = true
					procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, 0, 0)
					app.routeUpdating = false
				}
				app.routeSelectionChanged()
				return true
			}
		}
	case portableWMChar:
		character := rune(message.wParam)
		if character >= ' ' && character != 0x7f {
			query := app.routeFilter
			if !app.routeFiltering {
				query = ""
			}
			app.applyRouteFilter(snapshot, query+string(character))
			return true
		}
	}
	return false
}

func portableRouteSelectable(snapshot portableGUISnapshot) bool {
	selectableState := snapshot.state == guiConnected || snapshot.state == guiStopped || snapshot.state == guiError || snapshot.state == guiNeedsElevation
	return selectableState && !snapshot.routeBusy && len(snapshot.routeOptions) > 0
}

func (app *portableGUI) applyRouteFilter(snapshot portableGUISnapshot, query string) {
	app.routeFiltering = true
	app.routeFilter = query
	app.renderRouteCombo(snapshot)
	procSendMessage.Call(app.controls.routeCombo, portableCBShowDropDown, 1, 0)
	procInvalidateRect.Call(app.controls.routeCombo, 0, 1)
}

func (app *portableGUI) cancelRouteFilter(snapshot portableGUISnapshot) {
	if !app.routeFiltering {
		return
	}
	app.routeFiltering = false
	app.routeFilter = ""
	app.routeUpdating = true
	procSendMessage.Call(app.controls.routeCombo, portableCBShowDropDown, 0, 0)
	app.routeUpdating = false
	app.renderRouteCombo(snapshot)
	procInvalidateRect.Call(app.controls.routeCombo, 0, 1)
}

func (app *portableGUI) renderRouteCombo(snapshot portableGUISnapshot) {
	app.routeUpdating = true
	defer func() { app.routeUpdating = false }()
	procSendMessage.Call(app.controls.routeCombo, portableCBResetContent, 0, 0)
	app.routeVisible = app.routeVisible[:0]
	query := strings.ToLower(app.routeFilter)
	for index, option := range snapshot.routeOptions {
		if app.routeFiltering && !strings.Contains(strings.ToLower(option.Label), query) {
			continue
		}
		label, _ := windows.UTF16PtrFromString(option.Label)
		procSendMessage.Call(app.controls.routeCombo, portableCBAddString, 0, uintptr(unsafe.Pointer(label)))
		runtime.KeepAlive(label)
		app.routeVisible = append(app.routeVisible, index)
	}
	if app.routeFiltering {
		procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, ^uintptr(0), 0)
		return
	}
	for visibleIndex, optionIndex := range app.routeVisible {
		if optionIndex == snapshot.routeSelected {
			procSendMessage.Call(app.controls.routeCombo, portableCBSetCurSel, uintptr(visibleIndex), 0)
			return
		}
	}
}

func handlePortablePasteShortcut(message portableMSG) bool {
	if message.msg != portableWMKeyDown || message.wParam != portableVKV {
		return false
	}
	control, _, _ := procGetKeyState.Call(portableVKControl)
	if uint16(control)&0x8000 == 0 {
		return false
	}
	root, _, _ := procGetAncestor.Call(message.hwnd, portableGARoot)
	value, found := portableGUIWindows.Load(root)
	app, ok := value.(*portableGUI)
	if !found || !ok {
		return false
	}
	app.pasteJoinArtifact()
	return true
}

func (app *portableGUI) drawActionButton(item *portableDrawItem) bool {
	if item == nil || (item.hwndItem != app.controls.primaryButton && item.hwndItem != app.controls.deleteButton && item.hwndItem != app.controls.pasteButton) {
		return false
	}

	disabled := item.itemState&(portableODSDisabled|portableODSGrayed) != 0
	background, _, _ := procGetSysColor.Call(portableColorWindow)
	borderColor := uintptr(portableButtonBorder)
	textColor, _, _ := procGetSysColor.Call(portableColorWindowText)
	switch {
	case disabled:
		background, _, _ = procGetSysColor.Call(portableColorBtnFace)
		borderColor = 0x00E0E0E0
		textColor, _, _ = procGetSysColor.Call(portableColorGrayText)
	case item.itemState&portableODSSelected != 0:
		background = portableButtonPressed
		borderColor = portableButtonFocus
	case item.itemState&(portableODSFocus|portableODSHotLight) != 0:
		background = portableButtonHover
		borderColor = portableButtonFocus
	}

	brush, _, _ := procCreateSolidBrush.Call(background)
	pen, _, _ := procCreatePen.Call(portablePSSolid, uintptr(app.scale(1)), borderColor)
	oldBrush, _, _ := procSelectObject.Call(item.dc, brush)
	oldPen, _, _ := procSelectObject.Call(item.dc, pen)
	corner := app.scale(3)
	procRoundRect.Call(
		item.dc,
		uintptr(item.rect.left), uintptr(item.rect.top), uintptr(item.rect.right-1), uintptr(item.rect.bottom-1),
		uintptr(corner), uintptr(corner),
	)
	procSelectObject.Call(item.dc, oldPen)
	procSelectObject.Call(item.dc, oldBrush)
	procDeleteObject.Call(pen)
	procDeleteObject.Call(brush)

	length, _, _ := procGetWindowTextLength.Call(item.hwndItem)
	if int32(length) <= 0 {
		return true
	}
	label := make([]uint16, int(length)+1)
	procGetWindowText.Call(item.hwndItem, uintptr(unsafe.Pointer(&label[0])), length+1)
	font, _, _ := procSendMessage.Call(item.hwndItem, portableWMGetFont, 0, 0)
	oldFont, _, _ := procSelectObject.Call(item.dc, font)
	procSetBkMode.Call(item.dc, portableTransparent)
	procSetTextColor.Call(item.dc, textColor)
	textRect := item.rect
	textRect.right--
	textRect.bottom--
	procDrawText.Call(
		item.dc,
		uintptr(unsafe.Pointer(&label[0])),
		length,
		uintptr(unsafe.Pointer(&textRect)),
		portableDTCenter|portableDTVCenter|portableDTSingleLine|portableDTNoPrefix,
	)
	procSelectObject.Call(item.dc, oldFont)
	runtime.KeepAlive(label)
	return true
}

func (app *portableGUI) drawRouteOption(item *portableDrawItem) bool {
	if item == nil || item.hwndItem != app.controls.routeCombo {
		return false
	}

	isSelectionField := item.itemState&portableODSComboBoxEdit != 0
	backgroundIndex := uintptr(portableColorWindow)
	textColorIndex := uintptr(portableColorWindowText)
	if item.itemState&portableODSDisabled != 0 {
		backgroundIndex = portableColorBtnFace
		textColorIndex = portableColorGrayText
	} else if !isSelectionField && item.itemState&portableODSSelected != 0 {
		backgroundIndex = portableColorHighlight
		textColorIndex = portableColorHighlightText
	}
	background, _, _ := procGetSysColorBrush.Call(backgroundIndex)
	procFillRect.Call(item.dc, uintptr(unsafe.Pointer(&item.rect)), background)

	var label []uint16
	var length uintptr
	if isSelectionField && app.routeFiltering {
		label, _ = windows.UTF16FromString(app.routeFilter)
		length = uintptr(len(label) - 1)
	} else {
		if item.itemID == ^uint32(0) {
			return true
		}
		length, _, _ = procSendMessage.Call(item.hwndItem, portableCBGetLBTextLen, uintptr(item.itemID), 0)
		if int32(length) < 0 {
			return true
		}
		label = make([]uint16, int(length)+1)
		procSendMessage.Call(item.hwndItem, portableCBGetLBText, uintptr(item.itemID), uintptr(unsafe.Pointer(&label[0])))
	}

	font, _, _ := procSendMessage.Call(item.hwndItem, portableWMGetFont, 0, 0)
	oldFont, _, _ := procSelectObject.Call(item.dc, font)
	procSetBkMode.Call(item.dc, portableTransparent)
	textColor, _, _ := procGetSysColor.Call(textColorIndex)
	procSetTextColor.Call(item.dc, textColor)

	textRect := item.rect
	if isSelectionField && !app.routeFiltering {
		measurement := portableRect{}
		procDrawText.Call(
			item.dc,
			uintptr(unsafe.Pointer(&label[0])),
			length,
			uintptr(unsafe.Pointer(&measurement)),
			portableDTLeft|portableDTSingleLine|portableDTNoPrefix|portableDTCalcRect,
		)
		tagRect := item.rect
		tagRect.left += app.scale(4)
		tagRect.top += app.scale(3)
		tagRect.bottom -= app.scale(3)
		tagRect.right = tagRect.left + (measurement.right - measurement.left) + app.scale(16)
		maxRight := item.rect.right - app.scale(4)
		if tagRect.right > maxRight {
			tagRect.right = maxRight
		}

		tagColor := uintptr(portableTagBackground)
		borderColor := uintptr(portableGreenColor)
		if item.itemState&portableODSDisabled != 0 {
			tagColor, _, _ = procGetSysColor.Call(portableColorBtnFace)
			borderColor, _, _ = procGetSysColor.Call(portableColorGrayText)
		}
		tagBrush, _, _ := procCreateSolidBrush.Call(tagColor)
		tagPen, _, _ := procCreatePen.Call(portablePSSolid, uintptr(app.scale(1)), borderColor)
		oldBrush, _, _ := procSelectObject.Call(item.dc, tagBrush)
		oldPen, _, _ := procSelectObject.Call(item.dc, tagPen)
		corner := app.scale(8)
		procRoundRect.Call(
			item.dc,
			uintptr(tagRect.left), uintptr(tagRect.top), uintptr(tagRect.right), uintptr(tagRect.bottom),
			uintptr(corner), uintptr(corner),
		)
		procSelectObject.Call(item.dc, oldPen)
		procSelectObject.Call(item.dc, oldBrush)
		procDeleteObject.Call(tagPen)
		procDeleteObject.Call(tagBrush)

		textRect = tagRect
		textRect.left += app.scale(8)
		textRect.right -= app.scale(8)
	} else {
		textRect.left += app.scale(8)
		textRect.right -= app.scale(5)
	}
	procDrawText.Call(
		item.dc,
		uintptr(unsafe.Pointer(&label[0])),
		length,
		uintptr(unsafe.Pointer(&textRect)),
		portableDTLeft|portableDTVCenter|portableDTSingleLine|portableDTEndEllipsis|portableDTNoPrefix,
	)
	if item.itemState&portableODSFocus != 0 {
		focusRect := item.rect
		focusRect.left++
		focusRect.top++
		focusRect.right--
		focusRect.bottom--
		procDrawFocusRect.Call(item.dc, uintptr(unsafe.Pointer(&focusRect)))
	}
	procSelectObject.Call(item.dc, oldFont)
	runtime.KeepAlive(label)
	return true
}

func (app *portableGUI) drawNetworkListItem(item *portableDrawItem) bool {
	if item == nil || item.hwndItem != app.controls.networkList || item.itemID == ^uint32(0) {
		return false
	}
	background := uintptr(portableColorWindow)
	textColor := uintptr(portableColorWindowText)
	if item.itemState&portableODSSelected != 0 {
		background = portableColorHighlight
		textColor = portableColorHighlightText
	}
	brush, _, _ := procGetSysColorBrush.Call(background)
	procFillRect.Call(item.dc, uintptr(unsafe.Pointer(&item.rect)), brush)

	connected := app.snapshot().state == guiConnected
	if connected {
		dotSize := app.scale(7)
		dotLeft := item.rect.left + app.scale(6)
		dotTop := item.rect.top + (item.rect.bottom-item.rect.top-dotSize)/2
		greenBrush, _, _ := procCreateSolidBrush.Call(portableGreenColor)
		oldBrush, _, _ := procSelectObject.Call(item.dc, greenBrush)
		nullPen, _, _ := procGetStockObject.Call(portableNullPen)
		oldPen, _, _ := procSelectObject.Call(item.dc, nullPen)
		procEllipse.Call(item.dc, uintptr(dotLeft), uintptr(dotTop), uintptr(dotLeft+dotSize), uintptr(dotTop+dotSize))
		procSelectObject.Call(item.dc, oldPen)
		procSelectObject.Call(item.dc, oldBrush)
		procDeleteObject.Call(greenBrush)
	}

	length, _, _ := procSendMessage.Call(item.hwndItem, portableLBGetTextLen, uintptr(item.itemID), 0)
	if int32(length) < 0 {
		return true
	}
	text := make([]uint16, int(length)+1)
	procSendMessage.Call(item.hwndItem, portableLBGetText, uintptr(item.itemID), uintptr(unsafe.Pointer(&text[0])))
	textRect := item.rect
	textRect.left += app.scale(5)
	if connected {
		textRect.left += app.scale(15)
	}
	font, _, _ := procSendMessage.Call(item.hwndItem, portableWMGetFont, 0, 0)
	oldFont, _, _ := procSelectObject.Call(item.dc, font)
	procSetBkMode.Call(item.dc, portableTransparent)
	procSetTextColor.Call(item.dc, textColor)
	procDrawText.Call(item.dc, uintptr(unsafe.Pointer(&text[0])), length, uintptr(unsafe.Pointer(&textRect)), portableDTLeft|portableDTVCenter|portableDTSingleLine|portableDTNoPrefix)
	procSelectObject.Call(item.dc, oldFont)
	runtime.KeepAlive(text)
	return true
}

func portableWindowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	value, found := portableGUIWindows.Load(hwnd)
	app, _ := value.(*portableGUI)
	switch message {
	case portableWMGetMinMaxInfo:
		if lParam != 0 {
			dpi := int32(96)
			if found {
				dpi = app.dpi()
			} else if systemDPI, _, _ := procGetDPIForSystem.Call(); systemDPI != 0 {
				dpi = int32(systemDPI)
			}
			info := (*portableMinMaxInfo)(unsafe.Pointer(lParam))
			info.minTrackSize.x, info.minTrackSize.y = portableMinimumWindowSize(dpi)
			return 0
		}
	case portableWMSize:
		if found {
			app.layoutControls()
			return 0
		}
	case portableWMDPIChanged:
		if found && lParam != 0 {
			// Windows 提供的 RECT 仅在本次回调内有效；先复制，再调整窗口。
			suggested := *(*portableRect)(unsafe.Pointer(lParam))
			app.changeDPI(int32((wParam>>16)&0xffff), suggested)
			return 0
		}
	case portableWMCommand:
		if found {
			controlID := uint16(wParam & 0xffff)
			notification := uint16((wParam >> 16) & 0xffff)
			switch controlID {
			case portableControlPrimary:
				app.primaryAction()
				return 0
			case portableControlPaste:
				app.pasteJoinArtifact()
				return 0
			case portableControlDelete:
				app.deleteLocalDevice()
				return 0
			case portableControlRoute:
				if app.routeUpdating {
					return 0
				}
				if notification == portableCBNSelChange || notification == portableCBNSelEndOK {
					app.routeSelectionChanged()
				} else if notification == portableCBNSelEndCancel && app.routeFiltering {
					app.cancelRouteFilter(app.snapshot())
				}
				return 0
			}
		}
	case portableWMCtlColorStatic:
		procSetBkMode.Call(wParam, portableTransparent)
		brush, _, _ := procGetSysColorBrush.Call(portableColorWindow)
		return brush
	case portableWMDrawItem:
		if found {
			item := (*portableDrawItem)(unsafe.Pointer(lParam))
			if app.drawActionButton(item) || app.drawRouteOption(item) || app.drawNetworkListItem(item) {
				return 1
			}
		}
	case portableWMMeasureItem:
		if found && lParam != 0 {
			item := (*portableMeasureItem)(unsafe.Pointer(lParam))
			if item.controlID == portableControlRoute {
				item.itemHeight = uint32(app.scale(23))
				return 1
			}
		}
	case portableWMAppTray:
		if found {
			switch uint32(lParam) {
			case portableWMLButtonDblClk:
				app.showMainWindow()
			case portableWMRButtonUp:
				app.showTrayMenu()
			}
			return 0
		}
	case portableWMAppRepaint:
		if found {
			app.renderControls()
			return 0
		}
	case portableWMDropFiles:
		if found {
			app.acceptDroppedFiles(wParam)
			return 0
		}
	case portableWMClose:
		if found {
			procShowWindow.Call(hwnd, portableSWHide)
			return 0
		}
		procDestroyWindow.Call(hwnd)
		return 0
	case portableWMAppExit:
		if found {
			app.beginClose()
		}
		procDestroyWindow.Call(hwnd)
		return 0
	case portableWMDestroy:
		if found {
			app.removeTrayIcon()
		}
		portableGUIWindows.Delete(hwnd)
		procPostQuitMessage.Call(0)
		return 0
	case portableWMCreate:
		return 0
	}
	result, _, _ := procDefWindowProc.Call(hwnd, uintptr(message), wParam, lParam)
	return result
}

func postPortableMessage(hwnd uintptr, message uint32, wParam, lParam uintptr) {
	if hwnd != 0 {
		procPostMessage.Call(hwnd, uintptr(message), wParam, lParam)
	}
}

func dragAcceptFiles(hwnd uintptr, accept bool) {
	value := uintptr(0)
	if accept {
		value = 1
	}
	procDragAcceptFiles.Call(hwnd, value)
}

func dragFinish(drop uintptr) { procDragFinish.Call(drop) }

func droppedFiles(drop uintptr) ([]string, error) {
	count, _, _ := procDragQueryFile.Call(drop, 0xffffffff, 0, 0)
	if count == 0 || count > 16 {
		return nil, errors.New("没有可导入的本地文件")
	}
	paths := make([]string, 0, count)
	for index := uintptr(0); index < count; index++ {
		length, _, _ := procDragQueryFile.Call(drop, index, 0, 0)
		if length == 0 || length > 32767 {
			return nil, errors.New("拖入的文件路径无效")
		}
		buffer := make([]uint16, length+1)
		written, _, _ := procDragQueryFile.Call(drop, index, uintptr(unsafe.Pointer(&buffer[0])), length+1)
		if written != length {
			return nil, errors.New("读取拖入的文件路径失败")
		}
		paths = append(paths, windows.UTF16ToString(buffer))
		runtime.KeepAlive(buffer)
	}
	return paths, nil
}

func openJoinArtifact(owner uintptr) (string, error) {
	buffer := make([]uint16, 32768)
	filterText := "二维码图片 (*.png)\x00*.png\x00Loom 加入文件 (*.loom-invite)\x00*.loom-invite\x00所有文件 (*.*)\x00*.*\x00"
	filter := append(utf16.Encode([]rune(filterText)), 0)
	title, _ := windows.UTF16PtrFromString("导入中控生成的 Device 二维码")
	dialog := portableOpenFileName{
		size: uint32(unsafe.Sizeof(portableOpenFileName{})), owner: owner,
		filter: &filter[0], filterIndex: 1, file: &buffer[0], maxFile: uint32(len(buffer)),
		title: title, flags: portableOFNPathExists | portableOFNFileExists | portableOFNNoChange,
	}
	result, _, callErr := procGetOpenFileName.Call(uintptr(unsafe.Pointer(&dialog)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(buffer)
	if result == 0 {
		code, _, _ := procCommDlgError.Call()
		if code == 0 {
			return "", nil
		}
		return "", fmt.Errorf("打开文件选择器失败（0x%x）: %w", code, callErr)
	}
	return windows.UTF16ToString(buffer), nil
}

func messageBoxResult(owner uintptr, title, message string, flags uint32) int32 {
	titlePtr, _ := windows.UTF16PtrFromString(title)
	messagePtr, _ := windows.UTF16PtrFromString(message)
	result, _, _ := procMessageBox.Call(owner, uintptr(unsafe.Pointer(messagePtr)), uintptr(unsafe.Pointer(titlePtr)), uintptr(flags))
	return int32(result)
}

func messageBox(owner uintptr, title, message string, flags uint32) {
	messageBoxResult(owner, title, message, flags)
}
