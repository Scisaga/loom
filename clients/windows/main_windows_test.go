//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"loom/internal/clientcore"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
)

func TestPrepareClientNativeNotJoinedLifecycle(t *testing.T) {
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	workload, err := prepareClient()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(programData, "Loom", "state", "preference.json"))
	if err != nil {
		t.Fatal(err)
	}
	preference, err := clientcore.ParsePreference(body)
	if err != nil {
		t.Fatal(err)
	}
	if preference.Mode != clientcore.Auto {
		t.Fatalf("initial preference mode = %q, want auto", preference.Mode)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := workload(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPreparePortableClientNativeNotJoinedLifecycle(t *testing.T) {
	localAppData := t.TempDir()
	t.Setenv("LocalAppData", localAppData)
	workload, err := preparePortableClient(editionPortableMixed)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(localAppData, "LoomPortable", "state", "preference.json"))
	if err != nil {
		t.Fatal(err)
	}
	preference, err := clientcore.ParsePreference(body)
	if err != nil {
		t.Fatal(err)
	}
	if preference.Mode != clientcore.Auto {
		t.Fatalf("initial portable preference mode = %q, want auto", preference.Mode)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := workload(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredEdition(t *testing.T) {
	original := buildEdition
	t.Cleanup(func() { buildEdition = original })
	for _, want := range []clientEdition{editionInstalled, editionPortableMixed, editionPortableTUN} {
		buildEdition = string(want)
		got, err := configuredEdition()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("configured edition = %q, want %q", got, want)
		}
	}
	buildEdition = "renamed-copy"
	if _, err := configuredEdition(); err == nil {
		t.Fatal("invalid build edition was accepted")
	}
}

func TestWindowsGUIEditionBoundaries(t *testing.T) {
	programData := t.TempDir()
	localAppData := t.TempDir()
	t.Setenv("ProgramData", programData)
	t.Setenv("LocalAppData", localAppData)

	installedRoot, err := windowsGUIStateRoot(editionInstalled)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := installedStateRoot(); installedRoot != want {
		t.Fatalf("Installed GUI root = %q, want %q", installedRoot, want)
	}
	if got := windowsClientCAPath(installedRoot, editionInstalled); got != clientruntime.WindowsInstalledCAPath {
		t.Fatalf("Installed CA path = %q, want %q", got, clientruntime.WindowsInstalledCAPath)
	}
	if _, ok := (&portableGUI{edition: editionInstalled}).protector().(clientsecret.MachineProtector); !ok {
		t.Fatal("Installed GUI did not select machine-scope DPAPI")
	}

	for _, edition := range []clientEdition{editionPortableMixed, editionPortableTUN} {
		root, err := windowsGUIStateRoot(edition)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(localAppData, "LoomPortable"); root != want {
			t.Fatalf("%s GUI root = %q, want %q", edition, root, want)
		}
		if got, want := windowsClientCAPath(root, edition), filepath.Join(root, "tls", "ca.crt"); got != want {
			t.Fatalf("%s CA path = %q, want %q", edition, got, want)
		}
		if _, ok := (&portableGUI{edition: edition}).protector().(clientsecret.UserProtector); !ok {
			t.Fatalf("%s GUI did not select current-user DPAPI", edition)
		}
	}
	if windowsEditionLabel(editionInstalled) != "Installed" || windowsEditionLabel(editionPortableTUN) != "Portable TUN" {
		t.Fatal("Windows GUI edition labels are not distinct")
	}
	if windowsEditionRequiresElevation(editionInstalled) || !windowsEditionRequiresElevation(editionPortableTUN) || windowsEditionRequiresElevation(editionPortableMixed) {
		t.Fatal("Windows GUI elevation boundary is incorrect")
	}
}

func TestWindowsNamedLockRejectsASecondOwner(t *testing.T) {
	name := fmt.Sprintf(`Local\LoomWindowsLockTest-%d-%d`, os.Getpid(), time.Now().UnixNano())
	first, err := acquireWindowsNamedLock(name, "busy")
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if second, err := acquireWindowsNamedLock(name, "busy"); err == nil {
		second.close()
		t.Fatal("second process lock owner was accepted")
	} else if !strings.Contains(err.Error(), "busy") {
		t.Fatalf("second lock result=%v", err)
	}
	first.close()
	third, err := acquireWindowsNamedLock(name, "busy")
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	third.close()
}

func TestPortableTUNRejectsNonElevatedNativeToken(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("native test process is already elevated")
	}
	err := requirePortableTUNElevation(editionPortableTUN)
	if err == nil || !strings.Contains(err.Error(), "UAC") {
		t.Fatalf("Portable TUN elevation result = %v", err)
	}
	if err := requirePortableTUNElevation(editionPortableMixed); err != nil {
		t.Fatalf("Portable Mixed requested elevation: %v", err)
	}
}

func TestLoomServiceNativeStopLifecycle(t *testing.T) {
	handler := &loomService{prepare: func() (func(context.Context) error, error) {
		return func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		}, nil
	}}
	requests := make(chan svc.ChangeRequest)
	statuses := make(chan svc.Status)
	type executeResult struct {
		specific bool
		code     uint32
	}
	done := make(chan executeResult, 1)
	go func() {
		specific, code := handler.Execute(nil, requests, statuses)
		done <- executeResult{specific: specific, code: code}
	}()
	wantStatus(t, statuses, svc.StartPending)
	wantStatus(t, statuses, svc.Running)
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	wantStatus(t, statuses, svc.StopPending)
	select {
	case result := <-done:
		if result.specific || result.code != 0 {
			t.Fatalf("service stop result = %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}

func wantStatus(t *testing.T, statuses <-chan svc.Status, want svc.State) {
	t.Helper()
	select {
	case got := <-statuses:
		if got.State != want {
			t.Fatalf("service status = %v, want %v", got.State, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("service did not report status %v", want)
	}
}
