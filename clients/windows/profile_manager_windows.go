//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"loom/internal/clientcore"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
)

type windowsProfileDisplay struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	DeviceID string           `json:"device_id,omitempty"`
	State    portableGUIState `json:"state"`
}

// §7.2：每份加入身份复用现有运行宿主；切换锁覆盖旧宿主完全退出到新宿主启动。
// 它只管理用户连接操作，不参与 Agent 探测、排序或 selector 写入。
type windowsProfileManager struct {
	mu               sync.Mutex
	transitionMu     sync.Mutex
	store            *connectionProfileStore
	owner            *portableGUI
	children         map[string]*portableGUI
	transitionID     string
	transitionCancel context.CancelFunc
	epoch            uint64
	closing          bool
	start            func(*portableGUI)
	resume           func(*portableGUI) (windowsJoinResult, error)
	workers          sync.WaitGroup
}

type windowsProfileConnect struct {
	id     string
	child  *portableGUI
	ctx    context.Context
	cancel context.CancelFunc
	epoch  uint64
}

type windowsProfileDisconnect struct {
	id    string
	epoch uint64
	done  []<-chan struct{}
}

func checkWindowsProfilePath(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("连接配置目录不能包含目录联接或链接")
	}
	return nil
}

func newWindowsProfileManager(owner *portableGUI) (*windowsProfileManager, error) {
	store, err := loadConnectionProfiles(owner.root, writeWindowsJoinFile, checkWindowsProfilePath)
	if err != nil {
		return nil, err
	}
	m := &windowsProfileManager{store: store, owner: owner, children: make(map[string]*portableGUI), start: (*portableGUI).startRuntime,
		resume: func(child *portableGUI) (windowsJoinResult, error) { return child.joinInput("", nil) }}
	for _, p := range store.Snapshot().Profiles {
		child, err := m.makeChild(p.ID)
		if err != nil {
			return nil, err
		}
		m.children[p.ID] = child
	}
	return m, nil
}

func (m *windowsProfileManager) makeChild(id string) (*portableGUI, error) {
	root, err := m.store.ResolveRoot(id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(m.owner.ctx)
	child := &portableGUI{edition: m.owner.edition, root: root, ctx: ctx, cancel: cancel,
		state: guiNeedsJoin, routeSelected: -1, profileChild: true, hostname: m.owner.hostname}
	config, err := clientupdate.ReadConfig(filepath.Join(root, "config", "client.json"))
	if err == nil {
		child.joined, child.deviceID, child.state = true, config.NodeID, guiStopped
		child.detail = "已保存加入身份；尚未连接。"
		child.loadOfflineProfileRoutes()
	} else if !os.IsNotExist(err) {
		child.state, child.detail = guiError, "连接配置无效："+err.Error()
	}
	return child, nil
}

func (app *portableGUI) loadOfflineProfileRoutes() {
	plan, err := readWindowsLocalSelectorPlan(app.root, app.protector(), app.edition)
	if err != nil {
		return
	}
	options, err := portableRouteOptions(plan)
	if err != nil {
		return
	}
	pref, err := clientcore.ReadPreference(filepath.Join(app.root, "state", "preference.json"))
	if err != nil {
		return
	}
	app.mu.Lock()
	app.routeOptions, app.routeSelected = options, routeOptionIndex(options, pref)
	app.mu.Unlock()
}

func readWindowsLocalSelectorPlan(root string, protector clientsecret.Protector, edition clientEdition) (*clientruntime.WindowsSelectorPlan, error) {
	files, _, err := clientruntime.ReadCandidateBundle(root, protector)
	if err != nil {
		return nil, err
	}
	profile, err := runtimeProfile(edition)
	if err != nil {
		return nil, err
	}
	caPath := filepath.Join(root, "tls", "ca.crt")
	source, agentBody := []byte(files["sing-box/config.json"]), []byte(files["agent/config.json"])
	defer clear(source)
	defer clear(agentBody)
	runtimeBody, err := clientruntime.DeriveWindowsRuntimeConfig(source, profile, caPath)
	if err != nil {
		return nil, err
	}
	defer clear(runtimeBody)
	return clientruntime.BuildWindowsSelectorPlan(runtimeBody, agentBody, profile, caPath)
}

func (m *windowsProfileManager) snapshot() portableGUISnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	index := m.store.Snapshot()
	s := portableGUISnapshot{state: guiNeedsJoin, routeSelected: -1, hostname: m.owner.hostname,
		selectedProfile: index.Selected, profilesReady: true}
	if child := m.children[index.Selected]; child != nil {
		s = child.snapshot()
		s.profilesReady = true
		s.selectedProfile = index.Selected
	}
	for _, p := range index.Profiles {
		child := m.children[p.ID]
		if child == nil {
			s.profiles = append(s.profiles, windowsProfileDisplay{ID: p.ID, Name: p.Name, State: guiError})
			if p.ID == index.Selected {
				s.state = guiError
				s.profileName = p.Name
				s.detail = "配置目录无效，请删除此列表项后重新添加。"
			}
			continue
		}
		cs := child.snapshot()
		s.profiles = append(s.profiles, windowsProfileDisplay{p.ID, p.Name, cs.deviceID, cs.state})
		child.mu.RLock()
		running := child.runCancel != nil
		child.mu.RUnlock()
		if running {
			s.activeProfile = p.ID
			s.activeProfileName = p.Name
		}
		if p.ID == index.Selected {
			s.profileName = p.Name
		}
	}
	if m.transitionID != "" {
		for i := range s.profiles {
			if s.profiles[i].ID == m.transitionID && s.profiles[i].State != guiStopping {
				s.profiles[i].State = guiStarting
			}
		}
		if index.Selected == m.transitionID {
			s.state = guiStarting
			s.detail = "正在切换连接，等待原连接完全停止…"
			s.paths = nil
		}
	}
	return s
}

// §7.2：接收请求时就发布取消代次，不能等 goroutine 获得调度后才建立连接意图。
func (m *windowsProfileManager) prepareConnectLocked(id string) (*windowsProfileConnect, error) {
	child := m.children[id]
	if m.closing || m.owner.ctx.Err() != nil || child == nil || child.ctx.Err() != nil || !child.snapshot().joined {
		return nil, errors.New("请选择已加入网络的连接配置")
	}
	if m.transitionCancel != nil {
		m.transitionCancel()
	}
	ctx, cancel := context.WithCancel(m.owner.ctx)
	m.epoch++
	m.transitionID, m.transitionCancel = id, cancel
	return &windowsProfileConnect{id: id, child: child, ctx: ctx, cancel: cancel, epoch: m.epoch}, nil
}

func (m *windowsProfileManager) connect(id string) error {
	m.mu.Lock()
	op, err := m.prepareConnectLocked(id)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.owner.repaint()
	return m.runConnect(op)
}

func (m *windowsProfileManager) runConnect(op *windowsProfileConnect) error {
	defer func() {
		op.cancel()
		m.mu.Lock()
		if m.epoch == op.epoch {
			m.transitionID = ""
			m.transitionCancel = nil
		}
		m.mu.Unlock()
		m.owner.repaint()
	}()
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	if err := op.ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	children := make([]*portableGUI, 0, len(m.children))
	for _, child := range m.children {
		if child != op.child {
			children = append(children, child)
		}
	}
	m.mu.Unlock()
	if err := m.store.SetLastConnected(""); err != nil {
		return err
	}
	for _, child := range children {
		stopWindowsProfileAndWait(child)
	}
	// §7.2：同一配置仍在断开时也要等旧宿主退出，不能让 startRuntime 的幂等检查吞掉重连。
	op.child.mu.RLock()
	stopping := op.child.stopRequested || op.child.state == guiStopping
	done := op.child.runDone
	op.child.mu.RUnlock()
	if stopping && done != nil {
		<-done
	}
	if err := op.ctx.Err(); err != nil {
		return err
	}
	if err := m.store.SetLastConnected(op.id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := op.ctx.Err(); err != nil {
		return err
	}
	if m.closing || m.children[op.id] != op.child || op.child.ctx.Err() != nil {
		return context.Canceled
	}
	op.child.mu.Lock()
	if op.child.runCancel == nil {
		op.child.stopRequested = false
	}
	op.child.mu.Unlock()
	// §7.2：只有创建 runCancel 的短操作与取消请求互斥；预检、API 等待均在子宿主后台进行。
	m.start(op.child)
	return nil
}

func stopWindowsProfileAndWait(child *portableGUI) {
	child.mu.RLock()
	done := child.runDone
	child.mu.RUnlock()
	child.stopRuntime()
	if done != nil {
		<-done
	}
}

func (m *windowsProfileManager) prepareDisconnectLocked(id string) (*windowsProfileDisconnect, error) {
	if m.closing {
		return nil, context.Canceled
	}
	if id != "" && m.children[id] == nil {
		return nil, errors.New("请选择连接配置")
	}
	if id == "" || id == m.transitionID {
		if m.transitionCancel != nil {
			m.transitionCancel()
		}
		m.epoch++
		m.transitionID, m.transitionCancel = "", nil
	}
	op := &windowsProfileDisconnect{id: id, epoch: m.epoch}
	for key, child := range m.children {
		if id != "" && key != id {
			continue
		}
		child.mu.RLock()
		done := child.runDone
		child.mu.RUnlock()
		if done != nil {
			op.done = append(op.done, done)
		}
		child.stopRuntime()
	}
	return op, nil
}

func (m *windowsProfileManager) disconnect(id string) error {
	m.mu.Lock()
	op, err := m.prepareDisconnectLocked(id)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return m.runDisconnect(op)
}

func (m *windowsProfileManager) runDisconnect(op *windowsProfileDisconnect) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	// §7.2：这里只等待接收请求时捕获的宿主；迟到的断开 worker 不能停止后来新建的连接。
	for _, done := range op.done {
		<-done
	}
	m.mu.Lock()
	current := m.epoch == op.epoch
	m.mu.Unlock()
	if last := m.store.Snapshot().LastConnected; current && (op.id == "" || op.id == last) {
		return m.store.SetLastConnected("")
	}
	return nil
}

func (m *windowsProfileManager) dispatch(req brokerRequest) error {
	m.mu.Lock()
	if m.closing || m.owner.ctx.Err() != nil {
		m.mu.Unlock()
		return context.Canceled
	}
	var run func() error
	switch req.Operation {
	case "connect":
		op, err := m.prepareConnectLocked(req.ProfileID)
		if err != nil {
			m.mu.Unlock()
			return err
		}
		run = func() error { return m.runConnect(op) }
	case "disconnect":
		op, err := m.prepareDisconnectLocked(req.ProfileID)
		if err != nil {
			m.mu.Unlock()
			return err
		}
		run = func() error { return m.runDisconnect(op) }
	default:
		run = func() error { return m.command(req) }
	}
	m.workers.Add(1)
	m.mu.Unlock()
	m.owner.repaint()
	go func() {
		defer m.workers.Done()
		m.owner.profileError(run())
		m.owner.repaint()
	}()
	return nil
}

func (m *windowsProfileManager) command(req brokerRequest) error {
	if req.Operation == "connect" {
		return m.connect(req.ProfileID)
	}
	if req.Operation == "disconnect" {
		return m.disconnect(req.ProfileID)
	}
	if req.Operation == "select_profile" || req.Operation == "rename_profile" {
		m.mu.Lock()
		closing := m.closing
		m.mu.Unlock()
		if closing {
			return context.Canceled
		}
		// §7.2：查看或命名配置不改变运行宿主，也不应等待连接退出。
		if req.Operation == "select_profile" {
			return m.store.Select(req.ProfileID)
		}
		return m.store.Rename(req.ProfileID, req.Name)
	}
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return context.Canceled
	}
	child := m.children[req.ProfileID]
	m.mu.Unlock()
	switch req.Operation {
	case "add_profile":
		name := req.Name
		if name == "" {
			for n := 1; ; n++ {
				name = fmt.Sprintf("连接配置 %d", n)
				if !slices.ContainsFunc(m.store.Snapshot().Profiles, func(p connectionProfile) bool { return p.Name == name }) {
					break
				}
			}
		}
		p, err := m.store.Add(name)
		if err != nil {
			return err
		}
		newChild, err := m.makeChild(p.ID)
		if err != nil {
			return errors.Join(err, m.store.Remove(p.ID))
		}
		m.mu.Lock()
		m.children[p.ID] = newChild
		closing := m.closing
		m.mu.Unlock()
		if closing {
			newChild.beginClose()
		}
		return nil
	case "join":
		if child == nil || req.Invite == nil {
			return errors.New("请选择连接配置并导入加入二维码")
		}
		if _, err := m.store.ResolveRoot(req.ProfileID); err != nil {
			return err
		}
		s := child.snapshot()
		if child.ctx.Err() != nil || s.joined || (s.state != guiNeedsJoin && s.state != guiError) {
			return errors.New("当前配置不能导入二维码")
		}
		child.importJoinInvite(*req.Invite)
		return nil
	case "preference":
		if child == nil || req.Preference == nil {
			return errors.New("请选择连接配置")
		}
		return child.setRoutePreference(*req.Preference)
	case "delete":
		if child == nil {
			// §13.5：目录校验失败的条目只能移出索引，不能沿无效路径清理磁盘。
			return m.store.Remove(req.ProfileID)
		}
		s := child.snapshot()
		child.mu.RLock()
		busy := child.runCancel != nil
		child.mu.RUnlock()
		m.mu.Lock()
		pending := m.transitionID == req.ProfileID
		m.mu.Unlock()
		if busy || s.state == guiJoining || s.state == guiLoading || pending {
			return errors.New("请先停止该配置的连接或加入操作")
		}
		child.beginClose()
		child.workers.Wait()
		err := removeWindowsProfileDataWithCommit(m.owner.root, child.root, func() error { return m.store.Remove(req.ProfileID) })
		m.mu.Lock()
		delete(m.children, req.ProfileID)
		m.mu.Unlock()
		if err != nil && connectionProfilePosition(m.store.Snapshot(), req.ProfileID) >= 0 {
			// §13.5：删除回滚后使用新的宿主 context，不能保留一个永远无法重连的已取消 child。
			restored, restoreErr := m.makeChild(req.ProfileID)
			if restoreErr == nil {
				m.mu.Lock()
				m.children[req.ProfileID] = restored
				m.mu.Unlock()
			}
			return errors.Join(err, restoreErr)
		}
		return err
	default:
		return errors.New("未支持的连接配置操作")
	}
}

func (m *windowsProfileManager) close() {
	m.mu.Lock()
	m.closing = true
	if m.transitionCancel != nil {
		m.transitionCancel()
	}
	children := make([]*portableGUI, 0, len(m.children))
	for _, child := range m.children {
		children = append(children, child)
	}
	m.mu.Unlock()
	for _, child := range children {
		child.beginClose()
	}
	// §7.2：先取消子宿主，再等排队命令；持 transitionMu 等 worker 会阻塞 worker 自己的退出。
	m.workers.Wait()
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	m.mu.Lock()
	children = children[:0]
	for _, child := range m.children {
		children = append(children, child)
	}
	m.mu.Unlock()
	for _, child := range children {
		child.beginClose()
	}
	for _, child := range children {
		child.workers.Wait()
	}
}

// §13.5：旧根目录就地保留；删除旧身份也不能清掉其他配置或配置索引。
func removeWindowsProfileData(base, root string) error {
	return removeWindowsProfileDataWithCommit(base, root, nil)
}

func removeWindowsProfileDataWithCommit(base, root string, commit func() error) error {
	if root != base && (filepath.Dir(root) != filepath.Join(base, "profiles") || !validConnectionProfileID(filepath.Base(root))) {
		return errors.New("拒绝删除未登记的连接配置目录")
	}
	checkTree := func(path string) error {
		return filepath.WalkDir(path, func(path string, entry os.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			return checkWindowsProfilePath(path)
		})
	}
	if err := checkWindowsProfilePath(base); err != nil {
		return err
	}
	parent := filepath.Join(base, "profiles")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	if err := checkWindowsProfilePath(parent); err != nil {
		return err
	}
	var sources []string
	if root != base {
		if _, err := os.Lstat(root); !os.IsNotExist(err) {
			if err != nil {
				return err
			}
			sources = append(sources, root)
		}
	} else {
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() == "profiles" || entry.Name() == "client.log" {
				continue
			}
			path := filepath.Join(root, entry.Name())
			if entry.Name() == "state" {
				if err := checkWindowsProfilePath(path); err != nil {
					return err
				}
				states, err := os.ReadDir(path)
				if err != nil {
					return err
				}
				for _, state := range states {
					if state.Name() != "profiles.json" {
						sources = append(sources, filepath.Join(path, state.Name()))
					}
				}
			} else {
				sources = append(sources, path)
			}
		}
	}
	for _, source := range sources {
		if err := checkTree(source); err != nil {
			return err
		}
	}
	staging, err := os.MkdirTemp(parent, ".delete-profile-")
	if err != nil {
		return err
	}
	type movedPath struct{ source, staged string }
	var moved []movedPath
	rollback := func(cause error) error {
		var restoreErrors []error
		for i := len(moved) - 1; i >= 0; i-- {
			if err := os.Rename(moved[i].staged, moved[i].source); err != nil {
				restoreErrors = append(restoreErrors, err)
			}
		}
		if len(restoreErrors) == 0 {
			_ = os.Remove(staging)
		}
		return errors.Join(append([]error{cause}, restoreErrors...)...)
	}
	// §13.5：先同卷暂存身份；索引原子提交失败则恢复原位，不留下已取消且丢失身份的配置。
	for i, source := range sources {
		staged := filepath.Join(staging, fmt.Sprintf("entry-%d", i))
		if err := os.Rename(source, staged); err != nil {
			return rollback(err)
		}
		moved = append(moved, movedPath{source, staged})
	}
	if commit != nil {
		if err := commit(); err != nil {
			return rollback(err)
		}
	}
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("配置已从列表删除，但清理暂存数据失败：%w", err)
	}
	return nil
}

func (app *portableGUI) profileManager() *windowsProfileManager {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.profiles
}

func (app *portableGUI) initializeProfiles() {
	m, err := newWindowsProfileManager(app)
	if err != nil {
		app.update(guiError, false, "", "读取连接配置失败："+err.Error())
		return
	}
	defer m.close()
	m.resumePendingProfiles()
	// §7.2：在界面能发送取消之前登记启动意图，避免取消落在恢复完成与自动连接之间。
	index := m.store.Snapshot()
	var initial *windowsProfileConnect
	m.mu.Lock()
	if child := m.children[index.LastConnected]; child != nil && child.snapshot().joined {
		initial, err = m.prepareConnectLocked(index.LastConnected)
	}
	m.mu.Unlock()
	app.mu.Lock()
	app.profiles = m
	app.mu.Unlock()
	app.repaint()
	app.profileError(err)
	if initial != nil {
		app.profileError(m.runConnect(initial))
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-app.ctx.Done():
			return
		case <-ticker.C:
			app.repaint()
		}
	}
}

func (m *windowsProfileManager) resumePendingProfiles() {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return
	}
	children := make([]*portableGUI, 0, len(m.children))
	for _, child := range m.children {
		children = append(children, child)
	}
	m.mu.Unlock()
	for _, child := range children {
		if child.snapshot().joined {
			// §13.5：已提交 client.json 的事务仍要清掉旧 bearer，保留原身份密钥。
			if err := clearWindowsPendingInvite(child.root, child.protector()); err != nil {
				child.update(guiError, false, "", "读取已保存加入身份失败："+err.Error())
			} else {
				_ = os.Remove(windowsJoinReadyPath(child.root))
			}
			continue
		}
		pending, err := windowsProfileHasJoinRecovery(child)
		if err != nil {
			child.update(guiError, false, "", "读取待恢复的加入事务失败："+err.Error())
			continue
		}
		if pending {
			child.beginJoin(func() (windowsJoinResult, error) { return m.resume(child) })
		}
	}
}

func windowsProfileHasJoinRecovery(child *portableGUI) (bool, error) {
	path := windowsJoinReadyPath(child.root)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return false, errors.New("加入恢复材料必须是普通文件")
		}
		if err := checkWindowsProfilePath(path); err != nil {
			return false, err
		}
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	invite, err := readWindowsPendingInvite(child.root, child.protector())
	invite.Token = ""
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (app *portableGUI) profileError(err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	app.mu.Lock()
	app.profileMessage = err.Error()
	app.mu.Unlock()
	app.repaint()
}

func (app *portableGUI) profileCommand(req brokerRequest) {
	if req.ProfileID == "" && req.Operation != "add_profile" && req.Operation != "disconnect" {
		req.ProfileID = app.snapshot().selectedProfile
	}
	app.mu.Lock()
	app.profileMessage = ""
	app.mu.Unlock()
	if app.brokerClient {
		app.installedCommand(req)
		return
	}
	m := app.profileManager()
	if m == nil {
		return
	}
	app.profileError(m.dispatch(req))
}

func (app *portableGUI) selectProfileFromList() {
	index, _, _ := procSendMessage.Call(app.controls.networkList, portableLBGetCurSel, 0, 0)
	s := app.snapshot()
	if int(index) < 0 || int(index) >= len(s.profiles) {
		return
	}
	app.profileCommand(brokerRequest{Operation: "select_profile", ProfileID: s.profiles[int(index)].ID})
}

func (app *portableGUI) renameSelectedProfile() {
	s := app.snapshot()
	if s.selectedProfile == "" {
		return
	}
	length, _, _ := procGetWindowTextLength.Call(app.controls.profileNameEdit)
	text := make([]uint16, int(length)+1)
	procGetWindowText.Call(app.controls.profileNameEdit, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)))
	app.profileCommand(brokerRequest{Operation: "rename_profile", ProfileID: s.selectedProfile, Name: windows.UTF16ToString(text)})
}
