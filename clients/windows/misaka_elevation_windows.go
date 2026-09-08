//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type windowsElevationActions struct {
	launch  func() error
	release func()
	acquire func() error
	exit    func()
}

func (app *portableGUI) isElevationPending() bool {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.elevationPending
}

func (app *portableGUI) restartElevatedFor(profileID string) {
	app.restartElevatedWith(profileID, windowsElevationActions{
		launch: func() error {
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			verb, _ := windows.UTF16PtrFromString("runas")
			file, _ := windows.UTF16PtrFromString(executable)
			cwd, _ := windows.UTF16PtrFromString(filepath.Dir(executable))
			return windows.ShellExecute(windows.Handle(app.hwnd), verb, file, nil, cwd, portableSWShowNormal)
		},
		release: app.releasePortableLock,
		acquire: func() error {
			lock, err := acquireWindowsClientUILock()
			if err != nil {
				return err
			}
			app.lockMu.Lock()
			app.lock = lock
			app.lockMu.Unlock()
			return nil
		},
		exit: func() { postPortableMessage(app.hwnd, portableWMAppExit, 0, 0) },
	})
}

// §7.2：UAC 可以等待用户任意长时间，不能占住窗口线程而触发系统无响应替身窗口。
func (app *portableGUI) restartElevatedWith(profileID string, actions windowsElevationActions) {
	app.mu.Lock()
	if app.elevationPending || app.ctx.Err() != nil || app.edition != editionPortableTUN {
		app.mu.Unlock()
		return
	}
	app.elevationPending = true
	app.profileMessage = ""
	app.mu.Unlock()
	manager, child := app.profileManager(), app
	if manager != nil {
		manager.mu.Lock()
		child = manager.children[profileID]
		valid := child != nil && !manager.closing && manager.transitionID == "" && manager.elevationID == ""
		if valid {
			child.mu.Lock()
			valid = child.joined && child.state == guiNeedsElevation && child.runCancel == nil
			child.mu.Unlock()
		}
		if valid {
			manager.elevationID = profileID
		}
		manager.mu.Unlock()
		if !valid {
			app.mu.Lock()
			app.elevationPending = false
			app.mu.Unlock()
			return
		}
	}
	child.mu.Lock()
	child.state, child.detail = guiLoading, "正在请求 Windows 管理员权限…"
	child.mu.Unlock()
	app.repaint()
	app.workers.Add(1)
	go func() {
		defer app.workers.Done()
		var previous connectionProfileIndex
		var err error
		saved := false
		if manager != nil {
			// §13.5：交接进程锁之前清空已接收的写操作，新进程不能与旧 worker 共写身份。
			manager.workers.Wait()
			previous, err = manager.store.prepareElevation(profileID)
			saved = err == nil
		}
		if err == nil {
			err = app.ctx.Err()
		}
		released := false
		if err == nil {
			actions.release()
			released = true
			err = actions.launch()
		}
		if err == nil {
			actions.exit()
			return
		}
		if released {
			if lockErr := actions.acquire(); lockErr != nil {
				// §13.5：另一个进程取得身份所有权后，旧窗口不能再回滚或修改其索引。
				child.update(guiError, true, child.snapshot().deviceID, "无法恢复客户端所有权："+lockErr.Error())
				actions.exit()
				return
			}
		}
		state := guiNeedsElevation
		if saved {
			if restoreErr := manager.store.restoreElevation(profileID, previous); restoreErr != nil {
				err = errors.Join(err, restoreErr)
				state = guiError
			}
		}
		child.update(state, true, child.snapshot().deviceID, "未获得管理员权限："+err.Error())
		if manager != nil {
			manager.mu.Lock()
			manager.elevationID = ""
			manager.mu.Unlock()
		}
		app.mu.Lock()
		app.elevationPending = false
		app.mu.Unlock()
		app.profileError(errors.New("未获得管理员权限：" + err.Error()))
		app.repaint()
	}()
}

// §7.2：新进程恢复 LastConnected；只改左侧 Selected 会启动另一份保存的配置。
func (store *connectionProfileStore) prepareElevation(id string) (connectionProfileIndex, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	previous := cloneConnectionProfileIndex(store.index)
	if connectionProfilePosition(previous, id) < 0 {
		return previous, errors.New("[§7.2] 提权启动的连接配置已不存在")
	}
	next := cloneConnectionProfileIndex(previous)
	next.Selected, next.LastConnected = id, id
	return previous, store.save(next)
}

func (store *connectionProfileStore) restoreElevation(id string, previous connectionProfileIndex) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	next := cloneConnectionProfileIndex(store.index)
	if next.Selected == id {
		next.Selected = previous.Selected
		if connectionProfilePosition(next, next.Selected) < 0 {
			next.Selected = ""
		}
	}
	if next.LastConnected == id {
		next.LastConnected = previous.LastConnected
		if connectionProfilePosition(next, next.LastConnected) < 0 {
			next.LastConnected = ""
		}
	}
	return store.save(next)
}
