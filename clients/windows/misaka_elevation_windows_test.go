//go:build windows

package main

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func newMisakaElevationFixture(t *testing.T) (*portableGUI, *windowsProfileManager, string) {
	t.Helper()
	app, manager, _ := newMisakaRouteGUITestWindow(t)
	id := addProfileFixture(t, manager)
	manager.children[id].state = guiNeedsElevation
	if err := manager.store.Select(legacyConnectionProfile); err != nil {
		t.Fatal(err)
	}
	if err := manager.store.SetLastConnected(legacyConnectionProfile); err != nil {
		t.Fatal(err)
	}
	app.renderControls()
	return app, manager, id
}

func assertMisakaElevationControlsDisabled(t *testing.T, app *portableGUI) {
	t.Helper()
	for _, control := range []uintptr{app.controls.networkList, app.controls.addProfileButton,
		app.controls.deleteButton, app.controls.primaryButton, app.controls.modeAuto, app.controls.modeFixed, app.controls.modeDirect, app.controls.routeCombo} {
		if enabled, _, _ := procIsWindowEnabled.Call(control); enabled != 0 {
			t.Fatal("[§7.2] 提权交接期间仍允许更改身份、连接或路由偏好")
		}
	}
}

func TestGUIMisakaElevationKeepsMessagePumpResponsiveAndRollsBackCancel(t *testing.T) {
	app, manager, id := newMisakaElevationFixture(t)
	previous := manager.store.Snapshot()
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	t.Cleanup(finish)
	var launches, releases, acquires, exits atomic.Int32
	actions := windowsElevationActions{
		launch:  func() error { launches.Add(1); close(started); <-release; return windows.ERROR_CANCELLED },
		release: func() { releases.Add(1) },
		acquire: func() error { acquires.Add(1); return nil },
		exit:    func() { exits.Add(1) },
	}
	before := time.Now()
	app.restartElevatedWith(id, actions)
	if time.Since(before) > time.Second {
		t.Fatal("[§7.2] 请求 UAC 阻塞了窗口消息线程")
	}
	waitProfileSignal(t, started)
	if snapshot := manager.store.Snapshot(); snapshot.Selected != id || snapshot.LastConnected != id {
		t.Fatal("[§7.2] 提权前没有原子绑定所请求的启动配置")
	}
	app.renderControls()
	assertMisakaElevationControlsDisabled(t, app)
	if snapshot := app.snapshot(); snapshot.selectedProfile != id || snapshot.state != guiLoading || !app.isElevationPending() {
		t.Fatal("[§7.2] manager 快照没有显示真实的提权等待状态")
	}
	// §7.2：此时模拟 UAC 仍未返回，原生窗口依然可以处理激活和绘制状态更新。
	procSendMessage.Call(app.hwnd, 0x0086, 1, 0)
	app.renderControls()
	app.restartElevatedWith(id, actions)
	if err := manager.dispatch(brokerRequest{Operation: "select_profile", ProfileID: legacyConnectionProfile}); err == nil {
		t.Fatal("[§7.2] 交接身份所有权时仍可修改配置索引")
	}
	finish()
	app.workers.Wait()
	app.renderControls()
	if launches.Load() != 1 || releases.Load() != 1 || acquires.Load() != 1 || exits.Load() != 0 {
		t.Fatal("[§7.2] 重复提权、取消或 UI 所有权恢复次数不正确")
	}
	if restored := manager.store.Snapshot(); restored.Selected != previous.Selected || restored.LastConnected != previous.LastConnected {
		t.Fatal("[§7.2] 取消 UAC 后未恢复原来的查看与启动配置")
	}
	if app.isElevationPending() || manager.children[id].snapshot().state != guiNeedsElevation || !strings.Contains(app.snapshot().detail, "未获得管理员权限") {
		t.Fatal("[§7.2] 取消提权后没有恢复可重试状态和失败原因")
	}
	for _, control := range []uintptr{app.controls.networkList, app.controls.addProfileButton, app.controls.primaryButton} {
		if enabled, _, _ := procIsWindowEnabled.Call(control); enabled == 0 {
			t.Fatal("[§7.2] 取消提权后没有恢复可用操作")
		}
	}
}

func TestGUIMisakaElevationWaitsForOldWorkersBeforeReleasingOwnership(t *testing.T) {
	app, manager, id := newMisakaElevationFixture(t)
	oldDone, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseOld := func() { once.Do(func() { close(unblock) }) }
	t.Cleanup(releaseOld)
	manager.workers.Add(1)
	go func() {
		defer manager.workers.Done()
		<-unblock
		close(oldDone)
	}()
	launched := make(chan struct{})
	var released, acquired atomic.Int32
	app.restartElevatedWith(id, windowsElevationActions{
		release: func() {
			select {
			case <-oldDone:
			default:
				t.Error("[§13.5] 旧身份 worker 未退出就释放了进程锁")
			}
			released.Add(1)
		},
		launch:  func() error { close(launched); return windows.ERROR_CANCELLED },
		acquire: func() error { acquired.Add(1); return nil },
		exit:    func() { t.Error("[§7.2] 取消提权不应退出已恢复所有权的窗口") },
	})
	app.renderControls()
	assertMisakaElevationControlsDisabled(t, app)
	select {
	case <-launched:
		t.Fatal("[§13.5] UAC 启动越过了旧 worker 的完成屏障")
	case <-time.After(100 * time.Millisecond):
	}
	if released.Load() != 0 || manager.store.Snapshot().LastConnected != legacyConnectionProfile {
		t.Fatal("[§13.5] 旧 worker 未结束就交接了启动对象或身份所有权")
	}
	releaseOld()
	waitProfileSignal(t, launched)
	app.workers.Wait()
	if released.Load() != 1 || acquired.Load() != 1 || app.isElevationPending() {
		t.Fatal("[§7.2] worker 结束后没有继续提权并完成取消恢复")
	}
}

func TestGUIMisakaElevationLaunchesTheRequestedProfile(t *testing.T) {
	app, manager, id := newMisakaElevationFixture(t)
	var releases, exits atomic.Int32
	app.restartElevatedWith(id, windowsElevationActions{
		launch: func() error {
			index := manager.store.Snapshot()
			if index.Selected != id || index.LastConnected != id {
				return errors.New("[§7.2] 新进程将恢复错误配置")
			}
			return nil
		},
		release: func() { releases.Add(1) },
		acquire: func() error { t.Error("[§7.2] 启动成功后旧进程不应重新抢占 UI 锁"); return nil },
		exit:    func() { exits.Add(1) },
	})
	app.workers.Wait()
	if releases.Load() != 1 || exits.Load() != 1 || manager.store.Snapshot().LastConnected != id {
		t.Fatal("[§7.2] 成功交接没有保持请求的启动配置并退出旧界面")
	}
	if manager.children[legacyConnectionProfile].snapshot().state != guiStopped {
		t.Fatal("[§7.2] 提权启动误修改了另一配置的状态")
	}
}

func TestGUIMisakaElevationCannotRollbackWithoutTheUILock(t *testing.T) {
	app, manager, id := newMisakaElevationFixture(t)
	var exits atomic.Int32
	app.restartElevatedWith(id, windowsElevationActions{
		launch: func() error { return windows.ERROR_CANCELLED }, release: func() {},
		acquire: func() error { return errors.New("[§13.5] demo-owner 已取得锁") },
		exit:    func() { exits.Add(1) },
	})
	app.workers.Wait()
	if exits.Load() != 1 || manager.store.Snapshot().LastConnected != id || !app.isElevationPending() {
		t.Fatal("[§13.5] 丢失 UI 所有权后旧窗口仍回滚索引或恢复写操作")
	}
}

func TestGUIMisakaElevationIndexFailureDoesNotReleaseOwnership(t *testing.T) {
	app, manager, id := newMisakaElevationFixture(t)
	previous := manager.store.Snapshot()
	manager.store.writeFile = func(string, []byte) error { return errors.New("[§7.2] demo-write-failure") }
	var launches, releases, acquires, exits atomic.Int32
	app.restartElevatedWith(id, windowsElevationActions{
		launch: func() error { launches.Add(1); return nil }, release: func() { releases.Add(1) },
		acquire: func() error { acquires.Add(1); return nil }, exit: func() { exits.Add(1) },
	})
	app.workers.Wait()
	if launches.Load() != 0 || releases.Load() != 0 || acquires.Load() != 0 || exits.Load() != 0 || app.isElevationPending() {
		t.Fatal("[§7.2] 无法持久化启动对象时仍启动 UAC 或释放身份所有权")
	}
	if snapshot := manager.store.Snapshot(); snapshot.Selected != previous.Selected || snapshot.LastConnected != previous.LastConnected {
		t.Fatal("[§7.2] 原子写入失败改变了原启动索引")
	}
}
