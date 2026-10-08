//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"loom/internal/deviceclient"
)

// The opt-in VM fixture owns a separate demo network on the repository host.
// This process imports its invite through the real GUI, retains identity only
// in guest DPAPI, and exports only public readbacks and screenshots.
func TestWindowsCertifiedGUIRuntimeLive(t *testing.T) {
	input := os.Getenv("LOOM_ACCEPT_WINDOWS_FIXTURE")
	if input == "" {
		t.Skip("requires an isolated live fixture and an interactive Windows desktop")
	}
	var fixture struct {
		Root    string `json:"root"`
		Target  string `json:"target"`
		Resume  bool   `json:"resume"`
		Capture string `json:"capture,omitempty"`
	}
	body, err := os.ReadFile(input)
	if err != nil || json.Unmarshal(body, &fixture) != nil || !filepath.IsAbs(fixture.Root) {
		t.Fatal("invalid native fixture input")
	}
	base := filepath.Dir(input)
	edition := editionPortableMixed
	if fixture.Capture == "tun" {
		edition = editionPortableTUN
	} else if fixture.Capture != "" && fixture.Capture != "mixed" {
		t.Fatal("unsupported native fixture capture")
	}
	evidence := filepath.Join(base, "evidence")
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(base, "demo-ca.pem"))
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture business trust is missing")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	lock, err := acquireWindowsClientUILock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.close()
	app := &portableGUI{profileHost: true, edition: edition, root: fixture.Root,
		ctx: ctx, cancel: cancel, state: guiLoading, hostname: "demo-windows", routeSelected: -1}
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
		portableGUIWindows.Delete(hwnd)
	}()
	if err := app.createControls(); err != nil {
		t.Fatal(err)
	}
	app.renderControls()
	showPortableWindow(hwnd)
	app.workers.Add(1)
	go func() { defer app.workers.Done(); app.initializeProfiles() }()
	pump := func() {
		var msg portableMSG
		for {
			pending, _, _ := portableUser32.NewProc("PeekMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
			if pending == 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}
	wait := func(label string, accept func() bool) {
		t.Helper()
		deadline := time.Now().Add(150 * time.Second)
		for ctx.Err() == nil && time.Now().Before(deadline) {
			pump()
			if accept() {
				t.Log(label + " passed")
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s did not complete; UI detail: %s", label, app.snapshot().detail)
	}
	mark := func(name string, value any) {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil || os.WriteFile(filepath.Join(evidence, name+".json"), encoded, 0600) != nil {
			t.Fatal("write public fixture readback")
		}
	}
	signal := func(name string) {
		wait(name, func() bool { _, err := os.Stat(filepath.Join(base, name)); return err == nil })
	}
	wait("profile catalog", func() bool { return app.snapshot().profilesReady })
	if !fixture.Resume && !app.snapshot().joined {
		if len(app.snapshot().profiles) != 0 {
			t.Fatal("new fixture must not replace an existing device")
		}
		if draft := app.snapshot().profileDraft; draft == nil || !draft.Recoverable {
			procSendMessage.Call(app.controls.addProfileButton, 0x00F5, 0, 0) // BM_CLICK follows the actual parent.
			wait("join draft", func() bool { return app.snapshot().profileDraft != nil })
			app.importJoinArtifact(filepath.Join(base, "demo-windows.loom-invite"))
		}
		setPortableControlText(app.controls.draftName, "Demo certified network")
		procSendMessage.Call(app.controls.draftSubmit, 0x00F5, 0, 0)
		wait("normal UI enrollment", func() bool { return app.snapshot().joined && len(app.snapshot().profiles) == 1 })
	} else if len(app.snapshot().profiles) != 1 || !app.snapshot().joined {
		t.Fatal("restart did not recover the existing profile")
	}
	manager := app.profileManager()
	profileRoot, err := manager.store.ResolveRoot(app.snapshot().selectedProfile)
	if err != nil {
		t.Fatal(err)
	}
	load := func() *deviceclient.ProtectedStore {
		t.Helper()
		store, err := deviceclient.LoadProtected(windowsProfileStatePath(profileRoot), app.protector())
		if err != nil || store.LKG() == nil {
			t.Fatal("DPAPI profile readback failed", err)
		}
		return store
	}
	store := load()
	publicHash := sha256.Sum256([]byte(store.PublicKey()))
	identity := hex.EncodeToString(publicHash[:])
	if fixture.Resume && len(store.LKG().View.PolicyIDs) != 0 {
		t.Fatal("restart restored the withdrawn authorization")
	}
	mark("joined", map[string]any{"device_id": store.LKG().View.DeviceID, "public_key_hash": identity, "resume": fixture.Resume})
	if state := app.snapshot().state; state == guiStopped || state == guiError {
		procSendMessage.Call(app.controls.primaryButton, 0x00F5, 0, 0)
	}
	readback := func(authorized bool) windowsRuntimeStatus {
		var status windowsRuntimeStatus
		wait("certified runtime and report", func() bool {
			if current := app.snapshot(); current.state == guiError {
				t.Fatalf("certified runtime failed: %s", current.detail)
			}
			current, err := readWindowsRuntimeStatus(profileRoot)
			if err != nil || !current.Reported || current.RuntimeState != "running" || app.snapshot().state != guiConnected {
				return false
			}
			s := load()
			count := 0
			if authorized {
				count = 1
			}
			if current.ViewDigest != s.LKG().ViewDigest || len(current.Selections) != count || len(s.LKG().View.PolicyIDs) != count || len(app.snapshot().paths) != count {
				return false
			}
			if authorized && current.Selections[0].FinalExit != "demo-exit" {
				t.Fatal("GUI connected through a different final exit")
			}
			status = current
			return true
		})
		return status
	}
	business := func() error {
		proxy, _ := url.Parse("http://127.0.0.1:1080")
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "demo.example", MinVersion: tls.VersionTLS12}}
		if edition == editionPortableTUN {
			transport.Proxy = nil
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get(fixture.Target)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "demo-windows-business" {
			return fmt.Errorf("fixture HTTPS response mismatch")
		}
		return nil
	}
	if !fixture.Resume {
		status := readback(true)
		var lastBusinessError error
		t.Cleanup(func() {
			if t.Failed() && lastBusinessError != nil {
				t.Log("last actual business error:", lastBusinessError)
			}
		})
		wait("certified HTTPS business", func() bool { lastBusinessError = business(); return lastBusinessError == nil })
		captureProfileGUITestWindow(t, app, filepath.Join(evidence, "allowed.png"))
		mark("allowed", status)
		signal("withdrawn")
		status = readback(false)
		if business() == nil {
			t.Fatal("withdrawn Service still accepted business")
		}
		captureProfileGUITestWindow(t, app, filepath.Join(evidence, "revoked.png"))
		mark("revoked", status)
	} else {
		status := readback(false)
		if business() == nil {
			t.Fatal("restart revived withdrawn Service")
		}
		mark("restarted", status)
		signal("regranted")
		status = readback(true)
		wait("reauthorized HTTPS business", func() bool { return business() == nil })
		captureProfileGUITestWindow(t, app, filepath.Join(evidence, "regranted.png"))
		mark("regranted", status)
	}
	signal("finish")
	procSendMessage.Call(app.controls.primaryButton, 0x00F5, 0, 0)
	wait("normal disconnect", func() bool { return app.snapshot().state == guiStopped })
	if _, err := os.Stat(windowsRuntimeStatusPath(profileRoot)); !os.IsNotExist(err) {
		t.Fatal("stopped profile retained running status")
	}
	if next := sha256.Sum256([]byte(load().PublicKey())); hex.EncodeToString(next[:]) != identity {
		t.Fatal("business lifecycle replaced device identity")
	}
	mark("finished", map[string]any{"normal_disconnect": true, "identity_preserved": true})
}
