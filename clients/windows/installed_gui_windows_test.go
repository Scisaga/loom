//go:build windows

package main

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// §13.5：原生普通用户窗口导入中控 PNG，私钥只在 SCM 服务中生成和保存。
func TestInstalledGUIJoinLive(t *testing.T) {
	qr := os.Getenv("LOOM_ACCEPT_INSTALLED_QR")
	if qr == "" {
		t.Skip("set LOOM_ACCEPT_INSTALLED_QR to a fresh control-issued PNG after MSI install")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("GUI join must run unprivileged")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	lock, err := acquireWindowsClientUILock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root, err := installedStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	app := &portableGUI{brokerClient: true, edition: editionInstalled, root: root, ctx: ctx, cancel: cancel, state: guiLoading, routeSelected: -1}
	hwnd, err := createPortableWindow(app)
	if err != nil {
		t.Fatal(err)
	}
	app.hwnd = hwnd
	portableGUIWindows.Store(hwnd, app)
	defer func() {
		cancel()
		app.workers.Wait()
		procDestroyWindow.Call(hwnd)
		app.deleteFonts()
		app.deleteIcons()
		var message portableMSG
		portableUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&message)), 0, 0x0012, 0x0012, 1)
	}()
	if err := app.createControls(); err != nil {
		t.Fatal(err)
	}
	app.exchangeInstalledBroker(brokerRequest{Operation: "status"})
	if s := app.snapshot(); s.joined || s.state != guiNeedsJoin {
		t.Fatal("service must be waiting for its first join")
	}
	app.renderControls()
	showPortableWindow(hwnd)
	app.importJoinArtifact(qr)
	for ctx.Err() == nil {
		app.exchangeInstalledBroker(brokerRequest{Operation: "status"})
		var msg portableMSG
		for {
			ok, _, _ := portableUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
			if ok == 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
		s := app.snapshot()
		if s.state == guiError {
			t.Fatalf("ordinary GUI join failed: %s", s.detail)
		}
		if s.state == guiConnected && len(s.routeOptions) > 0 {
			if _, err := os.ReadDir(root); !os.IsPermission(err) {
				t.Fatal("GUI gained access to machine state")
			}
			t.Log("ordinary native GUI imported QR; SCM service joined, activated TUN and exposed authorized route choices")
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("GUI join did not finish before timeout")
}
