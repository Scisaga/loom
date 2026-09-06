//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"loom/internal/clientcore"
)

func TestBrokerRejectsUnboundedAuthority(t *testing.T) {
	for _, input := range []string{
		`{"operation":"execute","command":"cmd.exe"}`,
		`{"operation":"join","path":"C:\\demo\\invite.png"}`,
		`{"operation":"connect","root":"C:\\demo"}`,
		`{"operation":"status","preference":{}}`,
		`{"operation":"status"} {}`,
		`{"operation":"join","invite":{}}`,
		strings.Repeat(" ", 16385),
	} {
		if _, err := decodeBrokerRequest([]byte(input)); err == nil {
			t.Fatalf("accepted invalid request: %.80s", input)
		}
	}
	app := &portableGUI{state: guiStopped, joined: true, routeSelected: -1}
	if err := app.setRoutePreference(clientcore.Preference{Schema: 1, Mode: clientcore.FixedExit, Exit: "demo-unauthorized"}); err == nil {
		t.Fatal("broker accepted an exit outside the signed options")
	}
}

func TestBrokerDisconnectDuringJoinKeepsCommittedIdentityOffline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &portableGUI{edition: editionInstalled, ctx: ctx, cancel: cancel, state: guiJoining}
	if err := app.handleBrokerRequest(brokerRequest{Operation: "disconnect"}); err != nil {
		t.Fatal(err)
	}
	app.afterJoin("demo-device")
	if s := app.snapshot(); s.state != guiStopped || !s.joined || s.deviceID != "demo-device" || app.runCancel != nil {
		t.Fatal("completed join ignored the user's disconnect and started a workload")
	}
}

func TestInstalledStateRejectsUserReadableMachineSecrets(t *testing.T) {
	for _, sddl := range []string{
		`O:SYD:(A;;FA;;;WD)`,
		`O:SYD:(A;;FA;;;SY)(A;;FR;;;BU)`,
		`O:BUD:(A;;FA;;;SY)(A;;FA;;;BA)`,
		`O:SYD:NO_ACCESS_CONTROL`,
	} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateMachineDescriptor(sd); err == nil {
			t.Fatalf("accepted unsafe ACL %s", sddl)
		}
	}
	sd, err := windows.SecurityDescriptorFromString(`O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMachineDescriptor(sd); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ProgramData", t.TempDir())
	actual, err := installedStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(actual, os.Getenv("ProgramData")) {
		t.Fatal("service trusted an environment-supplied root")
	}
}

func TestBrokerNativePipeLifecycle(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf(`\\.\pipe\LoomBrokerTest-%d`, os.Getpid())
	pipe, err := createBrokerPipe(name, user.User.Sid.String())
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	ctx, cancel := context.WithCancel(context.Background())
	app := &portableGUI{ctx: ctx, cancel: cancel, state: guiNeedsJoin, routeSelected: -1}
	done := make(chan error, 1)
	go func() { done <- serveBroker(ctx, pipe, app) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for _, oversized := range []bool{true, false, false} {
		callCtx, callCancel := context.WithTimeout(ctx, 3*time.Second)
		h, err := connectBrokerPipe(callCtx, name)
		if err != nil {
			callCancel()
			t.Fatal(err)
		}
		if err := verifyBrokerServer(h); err == nil {
			t.Fatal("unregistered pipe passed SCM identity check")
		}
		if oversized {
			var header [4]byte
			binary.LittleEndian.PutUint32(header[:], maxBrokerMessage+1)
			if err := pipeBytes(callCtx, h, header[:], true); err != nil {
				t.Fatal(err)
			}
			if _, err := readPipeMessage(callCtx, h); err == nil {
				t.Fatal("oversized message was accepted")
			}
		} else {
			if err := writePipeMessage(callCtx, h, []byte(`{"operation":"status"}`)); err != nil {
				t.Fatal(err)
			}
			body, err := readPipeMessage(callCtx, h)
			if err != nil {
				t.Fatal(err)
			}
			var response brokerResponse
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatal(err)
			}
			if response.Error != "" || response.Snapshot.State != guiNeedsJoin {
				t.Fatalf("unexpected reply: %s", body)
			}
			if err := pipeBytes(callCtx, h, []byte{1}, true); err != nil {
				t.Fatal(err)
			}
		}
		windows.CloseHandle(h)
		callCancel()
	}
	// 客户端不发送消息时，SCM 停止也必须取消读操作并释放管道。
	stallCtx, stallCancel := context.WithTimeout(ctx, time.Second)
	defer stallCancel()
	h, err := connectBrokerPipe(stallCtx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
}

func TestBrokerNativePipeRejectsOtherUser(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("administrators are authorized")
	}
	name := fmt.Sprintf(`\\.\pipe\LoomBrokerDenied-%d`, os.Getpid())
	pipe, err := createBrokerPipe(name, "S-1-5-32-546")
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if h, err := connectBrokerPipe(ctx, name); err == nil {
		windows.CloseHandle(h)
		t.Fatal("non-operator could access the service pipe")
	}
}

func TestInstalledServiceLive(t *testing.T) {
	if os.Getenv("LOOM_ACCEPT_INSTALLED") != "1" {
		t.Skip("set LOOM_ACCEPT_INSTALLED=1 after MSI installation")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("run this acceptance as the ordinary installing user")
	}
	root, err := installedStateRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadDir(root); !os.IsPermission(err) {
		t.Fatalf("ordinary UI could read protected machine state: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	response, err := callInstalledBroker(ctx, brokerRequest{Operation: "status"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != "" || response.Snapshot.State == guiNeedsElevation || response.Snapshot.State == guiError {
		t.Fatalf("invalid service state: %+v", response)
	}
	app := &portableGUI{brokerClient: true, edition: editionInstalled, root: root, ctx: ctx, cancel: cancel, state: guiLoading}
	app.exchangeInstalledBroker(brokerRequest{Operation: "status"})
	if app.snapshot().state != response.Snapshot.State {
		t.Fatal("ordinary GUI did not reflect service state")
	}
	t.Log("ordinary user queried the SCM-verified service; machine state access was denied")
}

func TestInstalledConnectStopLive(t *testing.T) {
	if os.Getenv("LOOM_ACCEPT_INSTALLED") != "1" {
		t.Skip("set LOOM_ACCEPT_INSTALLED=1 after normal Installed join")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("lifecycle operations must run unprivileged")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	call := func(req brokerRequest) brokerSnapshot {
		t.Helper()
		response, err := callInstalledBroker(ctx, req)
		if err != nil || response.Error != "" {
			t.Fatalf("service operation %s: %v %s", req.Operation, err, response.Error)
		}
		return response.Snapshot
	}
	wait := func(state portableGUIState) brokerSnapshot {
		t.Helper()
		for ctx.Err() == nil {
			s := call(brokerRequest{Operation: "status"})
			if s.State == state {
				return s
			}
			if s.State == guiError {
				t.Fatalf("service error: %s", s.Detail)
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("service lifecycle timed out")
		return brokerSnapshot{}
	}
	wait(guiConnected)
	if path := os.Getenv("LOOM_ACCEPT_INSTALLED_PREFERENCE"); path != "" {
		preference, err := clientcore.ReadPreference(path)
		if err != nil {
			t.Fatal(err)
		}
		s := call(brokerRequest{Operation: "preference", Preference: &preference})
		if s.RouteSelected < 0 || s.Routes[s.RouteSelected].Preference != preference {
			t.Fatal("selected preference was not applied")
		}
	}
	iface := liveTUNInterface()
	if iface == nil {
		t.Fatal("Installed TUN was not active")
	}
	call(brokerRequest{Operation: "disconnect"})
	wait(guiStopped)
	waitLiveTUNCleanup(t, iface.Index)
	call(brokerRequest{Operation: "connect"})
	wait(guiConnected)
	t.Log("ordinary user selected an authorized route, disconnected with route cleanup, and reconnected through the service")
}
