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
	"loom/internal/wire"
)

func TestBrokerRejectsUnboundedAuthority(t *testing.T) {
	for _, input := range []string{
		`{"operation":"execute","command":"cmd.exe"}`,
		`{"operation":"join","path":"C:\\demo\\invite.png"}`,
		`{"operation":"connect","root":"C:\\demo"}`,
		`{"operation":"status","preference":{}}`,
		`{"operation":"status"} {}`,
		`{"operation":"join","invite":{}}`,
		`{"operation":"connect","profile_id":"../demo"}`,
		`{"operation":"connect","profile_id":"C:\\demo"}`,
		`{"operation":"select_profile"}`,
		`{"operation":"add_profile","profile_id":"legacy"}`,
		`{"operation":"join_profile","profile_id":"legacy"}`,
		`{"operation":"join_profile","invite":{}}`,
		`{"operation":"join_profile","preference":{"schema":1,"mode":"auto"}}`,
		`{"operation":"cancel_add_profile","name":"demo"}`,
		`{"operation":"cancel_add_profile","profile_id":"legacy"}`,
		`{"operation":"cancel_add_profile","invite":{}}`,
		`{"operation":"add_profile","operation":"cancel_add_profile"}`,
		`{"operation":"add_profile","Operation":"cancel_add_profile"}`,
		`{"operation":"join_profile","invite":{"Token":"demo-first","token":"demo-second"}}`,
		`{"operation":"rename_profile","profile_id":"legacy","name":""}`,
		`{"operation":"rename_profile","profile_id":"legacy","name":"demo\nname"}`,
		`{"operation":"status","profile_id":"legacy"}`,
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

func TestBrokerAcceptsExactlyOneBoundedV2Carrier(t *testing.T) {
	carrier, err := wire.MarshalCanonical(wire.InviteBootstrapDescriptorV2{
		Schema: 2, ClusterID: "demo-cluster", InviteID: "demo-invite",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := brokerRequest{Operation: "join", V2Carrier: string(carrier)}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeBrokerRequest(body); err != nil {
		t.Fatalf("bounded v2 carrier 被 broker 拒绝: %v", err)
	}
	var old map[string]any
	if err := json.Unmarshal(body, &old); err != nil {
		t.Fatal(err)
	}
	old["invite"] = map[string]any{"schema": 1}
	oldBody, _ := json.Marshal(old)
	if _, err := decodeBrokerRequest(oldBody); err == nil {
		t.Fatal("broker accepted removed v1 field")
	}
	request.V2Carrier = strings.Repeat("x", 2<<20)
	body, _ = json.Marshal(request)
	if _, err := decodeBrokerRequest(body); err == nil {
		t.Fatal("broker 接受了超出边界的 v2 carrier")
	}
}

func TestBrokerCannotBypassUnavailableProfileIndex(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &portableGUI{profileHost: true, ctx: ctx, cancel: cancel, state: guiError}
	for _, operation := range []string{"join", "connect", "disconnect", "delete", "preference", "add_profile", "join_profile", "cancel_add_profile", "select_profile", "rename_profile"} {
		if err := app.handleBrokerRequest(brokerRequest{Operation: operation, ProfileID: "legacy"}); err == nil {
			t.Fatalf("配置索引不可用时接受了 %s", operation)
		}
	}
	if err := app.handleBrokerRequest(brokerRequest{Operation: "status"}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, enabled := app.presentation(app.snapshot()); enabled {
		t.Fatal("损坏索引不能显示可连接的按钮")
	}
}

func TestBrokerProfileDraftUsesBoundedActionsAndDisplayOnlySnapshot(t *testing.T) {
	for _, req := range []brokerRequest{
		{Operation: "add_profile"}, {Operation: "cancel_add_profile"}, {Operation: "join_profile"},
		{Operation: "join_profile", Name: "演示网络", V2Carrier: profileDraftInvite()},
	} {
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBrokerRequest(body); err != nil {
			t.Fatalf("valid draft action rejected: %s: %v", req.Operation, err)
		}
	}
	draft := &windowsProfileDraftDisplay{State: guiJoining, Name: "演示网络", Detail: "正在等待加入配置", Recoverable: true, Busy: true}
	app := &portableGUI{brokerProfilesReady: true, brokerProfileDraft: draft}
	snapshot := app.brokerSnapshot()
	if snapshot.ProfileDraft == nil || *snapshot.ProfileDraft != *draft {
		t.Fatal("broker dropped join draft progress")
	}
	snapshot.ProfileDraft.Name = "仅修改返回值"
	if app.brokerProfileDraft.Name != "演示网络" {
		t.Fatal("broker draft snapshot aliases mutable host state")
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"token", "invite", "private_key", "profile-draft.json", "identity.json.dpapi", "endpoint"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("broker draft snapshot leaked %q", forbidden)
		}
	}
}

func TestBrokerProfileSnapshotCarriesOnlyReadOnlyPaths(t *testing.T) {
	app := &portableGUI{brokerProfilesReady: true, brokerProfiles: []windowsProfileDisplay{{ID: "legacy", Name: "演示连接", State: guiConnected}},
		selectedProfile: "legacy", profileName: "演示连接", activeProfile: "legacy", activeProfileName: "演示连接", state: guiConnected, joined: true, windowsV2: true,
		paths: []windowsPathDisplay{{Service: "demo-service", Candidate: "opaque-current", Chain: "本机 → demo-prefix → demo-exit → 目标", Health: "正常", SelectedQuality: "P50 25 ms", Reason: "改善达到切换门槛"}}}
	body, err := json.Marshal(app.brokerSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	var got brokerSnapshot
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.WindowsV2 || !got.ProfilesReady || got.SelectedProfile != "legacy" || len(got.Profiles) != 1 || len(got.Paths) != 1 || got.Paths[0] != app.paths[0] {
		t.Fatalf("配置和实际路径快照丢失: %s", body)
	}
	for _, secret := range []string{"private_key", "api_secret", "certificate_path", "runtime_dir"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("显示快照暴露了 %s", secret)
		}
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
	// v2 carrier 可以超过旧 64 KiB 管道上限；内核缓冲区仍保持有界，读写循环
	// 必须在其上分段传输，随后由严格 JSON decoder 拒绝未知字段。
	largeCtx, largeCancel := context.WithTimeout(ctx, 3*time.Second)
	h, err := connectBrokerPipe(largeCtx, name)
	if err != nil {
		largeCancel()
		t.Fatal(err)
	}
	large := []byte(`{"operation":"status","padding":"` + strings.Repeat("a", 96<<10) + `"}`)
	if err := writePipeMessage(largeCtx, h, large); err != nil {
		t.Fatal(err)
	}
	body, err := readPipeMessage(largeCtx, h)
	if err != nil {
		t.Fatal(err)
	}
	var rejected brokerResponse
	if err := json.Unmarshal(body, &rejected); err != nil || rejected.Error == "" {
		t.Fatal("超过 64 KiB 的 broker 消息未完成有界传输与严格拒绝")
	}
	if err := pipeBytes(largeCtx, h, []byte{1}, true); err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	largeCancel()
	// 客户端不发送消息时，SCM 停止也必须取消读操作并释放管道。
	stallCtx, stallCancel := context.WithTimeout(ctx, time.Second)
	defer stallCancel()
	h, err = connectBrokerPipe(stallCtx, name)
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
	if os.Getenv("LOOM_ACCEPT_WINDOWS_V2") == "1" && !response.Snapshot.WindowsV2 {
		t.Fatal("Issue #13 Installed 验收要求服务当前选中的连接配置使用 active Windows v2 LKG")
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
	if os.Getenv("LOOM_ACCEPT_WINDOWS_V2") == "1" {
		response, err := callInstalledBroker(ctx, brokerRequest{Operation: "status"})
		if err != nil || response.Error != "" || !response.Snapshot.WindowsV2 {
			t.Fatalf("Issue #13 Installed 生命周期没有运行 active Windows v2 LKG: %v %s", err, response.Error)
		}
	}
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
