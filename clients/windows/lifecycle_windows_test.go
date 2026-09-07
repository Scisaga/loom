//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
)

// §7.3：只在显式实机验收时使用正常加入的身份，不创建或修补 Device。
func requireLiveTUN(t *testing.T) string {
	t.Helper()
	if os.Getenv("LOOM_ACCEPT_TUN_LIFECYCLE") != "1" {
		t.Skip("set LOOM_ACCEPT_TUN_LIFECYCLE=1 on an elevated, joined Windows host")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("TUN lifecycle acceptance requires elevation")
	}
	root, err := localAppDataRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ensureWindowsJoined(context.Background(), root, clientsecret.UserProtector{}, ""); err != nil {
		t.Fatal("normal QR join is required before lifecycle acceptance")
	}
	return root
}

func liveTUNInterface() *net.Interface {
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		addresses, _ := iface.Addrs()
		for _, addr := range addresses {
			if addr.String() == "172.19.0.1/30" {
				return &iface
			}
		}
	}
	return nil
}

func waitLiveTUN(t *testing.T, root string) int {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if iface := liveTUNInterface(); iface != nil {
			_, body, err := activePortableRuntimeConfig(root)
			if err == nil {
				plan, err := clientruntime.BuildWindowsHealthPlan(body, clientruntime.WindowsPortableTUNProfile, windowsClientCAPath(root, editionPortableTUN))
				clear(body)
				if err == nil {
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					problems := clientruntime.CheckWindowsHealth(ctx, plan)
					cancel()
					if len(problems) == 0 {
						return iface.Index
					}
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("TUN did not become healthy")
	return 0
}

func waitLiveTUNCleanup(t *testing.T, index int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if liveTUNInterface() == nil {
			listener, err := net.Listen("tcp", "127.0.0.1:1080")
			if err == nil {
				listener.Close()
				// 不删除或重置其他网卡；只核对刚才捕获的接口索引没有残留路由。
				command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
					"@(Get-NetRoute -InterfaceIndex "+strconv.Itoa(index)+" -ErrorAction SilentlyContinue).Count")
				body, err := command.Output()
				if err == nil && strings.TrimSpace(string(body)) == "0" {
					return
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("managed TUN adapter, routes or proxy listener survived shutdown")
}

func TestWindowsTUNLifecycleLive(t *testing.T) {
	root := requireLiveTUN(t)
	if liveTUNInterface() != nil {
		t.Fatal("disconnect the existing TUN before acceptance")
	}
	for cycle := 0; cycle < 3; cycle++ {
		ctx, cancel := context.WithCancel(context.Background())
		app := &portableGUI{edition: editionPortableTUN, root: root, ctx: ctx, cancel: cancel, state: guiLoading, routeSelected: -1}
		t.Cleanup(func() { app.beginClose(); app.workers.Wait() })
		app.initialize()
		index := waitLiveTUN(t, root)
		// 等待真实激活以及自动上报有机会完成；停止后沿用现有 stale 判定。
		time.Sleep(dataPlaneStartupGrace + 6*time.Second)
		app.beginClose()
		app.workers.Wait()
		waitLiveTUNCleanup(t, index)
		paths, err := filepath.Glob(filepath.Join(root, "runtime", ".sing-box-active-*.json"))
		if err != nil || len(paths) != 0 {
			t.Fatal("plaintext runtime config survived clean shutdown")
		}
		t.Logf("cycle %d: real DNS/HTTPS healthy; adapter, routes, listener and runtime files cleaned", cycle+1)
	}
	// §7.3：杀死宿主，验证 Job Object 接管子进程，随后正常启动清理旧运行文件。
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestWindowsTUNCrashHelper$", "-test.timeout=90s")
	command.Env = append(os.Environ(), "LOOM_TUN_CRASH_CHILD=1")
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	index := waitLiveTUN(t, root)
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	waitLiveTUNCleanup(t, index)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &portableGUI{edition: editionPortableTUN, root: root, ctx: ctx, cancel: cancel, state: guiLoading, routeSelected: -1}
	t.Cleanup(func() { app.beginClose(); app.workers.Wait() })
	app.initialize()
	index = waitLiveTUN(t, root)
	app.beginClose()
	app.workers.Wait()
	waitLiveTUNCleanup(t, index)
	paths, _ := filepath.Glob(filepath.Join(root, "runtime", ".sing-box-active-*.json"))
	if len(paths) != 0 {
		t.Fatal("runtime files survived crash recovery")
	}
	t.Log("host crash and restart: managed adapter/routes removed; signed state recovered")
}

func TestWindowsTUNCrashHelper(t *testing.T) {
	if os.Getenv("LOOM_TUN_CRASH_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	root := requireLiveTUN(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &portableGUI{edition: editionPortableTUN, root: root, ctx: ctx, cancel: cancel, state: guiLoading, routeSelected: -1}
	app.initialize()
	defer func() { app.beginClose(); app.workers.Wait() }()
	<-ctx.Done()
}

// §7.2：实机验收只读运行配置，生产 UI 已不再从临时文件推断选路。
func activePortableRuntimeConfig(root string) (string, []byte, error) {
	paths, err := filepath.Glob(filepath.Join(root, "runtime", ".sing-box-active-*.json"))
	if err != nil || len(paths) != 1 {
		return "", nil, errors.New("本地数据面尚未提供出口控制")
	}
	info, err := os.Lstat(paths[0])
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 16<<20 {
		return "", nil, errors.New("本地出口控制配置无效")
	}
	body, err := os.ReadFile(paths[0])
	if err != nil || int64(len(body)) != info.Size() {
		clear(body)
		return "", nil, errors.New("读取本地出口控制配置失败")
	}
	return paths[0], body, nil
}
