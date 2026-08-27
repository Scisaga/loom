package report

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func successfulWireGuardProbe(name string, args ...string) ([]byte, error) {
	switch name {
	case wireGuardExecutable:
		return []byte("wireguard-tools v1.0.20250521 - https://www.wireguard.com/\n"), nil
	case "dpkg-query":
		if len(args) > 0 && args[0] == "-W" {
			return []byte("install ok installed\t1.0.20250521-1loom1~noble1\n"), nil
		}
		return []byte(strings.Join([]string{
			"/.", wireGuardExecutable, wireGuardQuick, wireGuardReresolve,
			"/usr/lib/systemd/system/wg-quick@.service", "",
		}, "\n")), nil
	case "dpkg":
		return nil, nil
	default:
		return nil, errors.New("unexpected command")
	}
}

func TestCollectComponentsParsesKnownCommands(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		switch name {
		case "systemctl":
			return []byte("4242\n"), nil
		case "/proc/4242/exe":
			return []byte("sing-box version 1.11.4\nEnvironment: running\n"), nil
		case singBoxExecutablePath:
			return []byte("sing-box version 1.11.4\nEnvironment: installed\n"), nil
		case wireGuardExecutable, "dpkg-query", "dpkg":
			return successfulWireGuardProbe(name, args...)
		default:
			t.Fatalf("unexpected command %q %v", name, args)
			return nil, nil
		}
	}
	got := collectComponentsWith(ComponentVersions{
		SingBox: "1.11.4", WireGuard: "1.0.20250521",
	}, run)
	wantNames := []string{"sing-box", wireGuardComponentName}
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
		if !c.OK() {
			t.Errorf("%s unexpectedly unhealthy: %+v", c.Name, c)
		}
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("component order = %v, want %v", names, wantNames)
	}
}

func TestCollectComponentsKeepsMismatchAndReadFailureDistinct(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		switch name {
		case "systemctl":
			return []byte("42\n"), nil
		case "/proc/42/exe", singBoxExecutablePath:
			return []byte("sing-box version 1.11.3\n"), nil
		case wireGuardExecutable:
			return []byte("permission denied\n"), errors.New("exit status 1")
		case "dpkg-query", "dpkg":
			return successfulWireGuardProbe(name)
		}
		return nil, errors.New("unexpected command")
	}
	got := collectComponentsWith(ComponentVersions{
		SingBox: "1.11.4", WireGuard: "1.0.20250521",
	}, run)
	if len(got) != 2 {
		t.Fatalf("got %d components: %+v", len(got), got)
	}
	if got[0].Actual != "1.11.3" || got[0].Error != "" || got[0].OK() {
		t.Fatalf("version mismatch was not preserved: %+v", got[0])
	}
	if got[1].Actual != "" || got[1].Error == "" || got[1].OK() {
		t.Fatalf("command failure was not preserved: %+v", got[1])
	}
}

func TestCollectComponentsSkipsRolesNotExpectedOnNode(t *testing.T) {
	calls := 0
	got := collectComponentsWith(ComponentVersions{Agent: "0.1.0"}, func(string, ...string) ([]byte, error) {
		calls++
		return nil, nil
	})
	if calls != 0 {
		t.Fatalf("executed %d external commands for absent roles", calls)
	}
	if len(got) != 0 {
		t.Fatalf("agent process version must come from agent-state, got %+v", got)
	}
}

func TestCollectComponentsRunsIndependentProbesConcurrently(t *testing.T) {
	var started atomic.Int32
	var readyOnce sync.Once
	ready := make(chan struct{})
	run := func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" || name == wireGuardExecutable {
			if started.Add(1) == 2 {
				readyOnce.Do(func() { close(ready) })
			}
			select {
			case <-ready:
			case <-time.After(time.Second):
				return nil, errors.New("探测没有并发启动")
			}
		}
		switch name {
		case "systemctl":
			return []byte("99\n"), nil
		case "/proc/99/exe":
			return []byte("sing-box version 1.11.4\n"), nil
		case singBoxExecutablePath:
			return []byte("sing-box version 1.11.4\n"), nil
		case wireGuardExecutable, "dpkg-query", "dpkg":
			return successfulWireGuardProbe(name, args...)
		}
		return nil, errors.New("unexpected command")
	}
	startedAt := time.Now()
	got := collectComponentsWith(ComponentVersions{
		SingBox: "1.11.4", WireGuard: "1.0.20250521",
	}, run)
	if elapsed := time.Since(startedAt); elapsed >= time.Second {
		t.Fatalf("探测疑似串行执行，耗时 %s: %+v", elapsed, got)
	}
	for _, component := range got {
		if !component.OK() {
			t.Fatalf("并发探测结果异常: %+v", got)
		}
	}
}

func TestRunComponentCommandBoundsInheritedPipeWait(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("测试需要 /bin/sh")
	}
	startedAt := time.Now()
	// shell 很快退出，但后台 sleep 继续持有同一 stdout 管道。没有
	// Cmd.WaitDelay 时，Run 会一直等到 sleep 退出。
	out, err := runComponentCommand("/bin/sh", "-c", `sleep 10 & printf '%s\n' "$!"`)
	if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(out))); parseErr == nil {
		if process, findErr := os.FindProcess(pid); findErr == nil {
			_ = process.Kill()
			_ = process.Release()
		}
	} else {
		t.Fatalf("无法读取后台测试进程 PID %q:%v", out, parseErr)
	}
	if err == nil {
		t.Fatal("继承输出管道未关闭，却被当成成功")
	}
	if elapsed := time.Since(startedAt); elapsed >= 2*time.Second {
		t.Fatalf("等待继承管道耗时 %s，未受 WaitDelay 约束", elapsed)
	}
}

func TestComponentVersionParserRejectsAmbiguousNumbers(t *testing.T) {
	for name, output := range map[string]string{
		wireGuardComponentName: "warning code 1 before wireguard-tools v1.0.0",
		"tailscale":            "warning 7\n1.82.5",
		"sing-box":             "warning 1\nsing-box version 1.11.4",
	} {
		if got := componentVersionFromOutput(name, output); got != "" {
			t.Errorf("%s parsed ambiguous token %q", name, got)
		}
	}
}

func TestRunningSingBoxCannotBeHiddenByNewDiskBinary(t *testing.T) {
	run := func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "systemctl":
			return []byte("77\n"), nil
		case "/proc/77/exe":
			return []byte("sing-box version 1.11.3\n"), nil
		case singBoxExecutablePath:
			return []byte("sing-box version 1.11.4\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
	got := collectComponentsWith(ComponentVersions{SingBox: "1.11.4"}, run)
	if len(got) != 1 || got[0].Actual != "1.11.3" || got[0].Error == "" || got[0].OK() {
		t.Fatalf("新磁盘文件遮住了旧运行 inode:%+v", got)
	}
	if !strings.Contains(got[0].Error, "旧 inode") {
		t.Fatalf("错误没有解释运行/磁盘差异:%+v", got[0])
	}
}

func TestTailscaleClientVersionCannotPretendToBeDaemonVersion(t *testing.T) {
	calls := 0
	got := collectComponentsWith(ComponentVersions{Tailscale: "1.82.5"}, func(string, ...string) ([]byte, error) {
		calls++
		return []byte("1.82.5\n"), nil
	})
	if calls != 0 || len(got) != 1 || got[0].Error == "" || got[0].OK() {
		t.Fatalf("tailscale client 冒充了 tailscaled:%+v calls=%d", got, calls)
	}
}

func TestComponentProbeCacheSingleflightsConcurrentStatusRequests(t *testing.T) {
	cfg := &Config{ExpectedComponents: ComponentVersions{WireGuard: "1.0.20250521"}}
	var calls atomic.Int32
	run := func(name string, args ...string) ([]byte, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return successfulWireGuardProbe(name, args...)
	}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := collectComponentsCachedWith(cfg, now, run)
			if len(got) != 1 || !got[0].OK() {
				t.Errorf("缓存探测异常:%+v", got)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 4 {
		t.Fatalf("并发状态请求执行了 %d 个命令，期望单次四项探测", got)
	}
	_ = collectComponentsCachedWith(cfg, now.Add(componentProbeTTL), run)
	if got := calls.Load(); got != 8 {
		t.Fatalf("缓存到期后执行次数=%d，期望 8", got)
	}
}

func TestWireGuardProbeUsesFixedBinaryAndPackageEvidence(t *testing.T) {
	pathWGCalled := false
	run := func(name string, args ...string) ([]byte, error) {
		if name == "wg" {
			pathWGCalled = true
			return []byte("wireguard-tools v99.0.0\n"), nil
		}
		return successfulWireGuardProbe(name, args...)
	}
	actual, err := probeWireGuardTools(run)
	if err != nil || actual != "1.0.20250521" {
		t.Fatalf("固定路径与包证据应通过:actual=%q err=%v", actual, err)
	}
	if pathWGCalled {
		t.Fatal("探测执行了 PATH 中的 wg")
	}
}

func TestWireGuardProbeRejectsPackageVersionMismatch(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" && len(args) > 0 && args[0] == "-W" {
			return []byte("install ok installed\t1.0.20210914-1ubuntu2\n"), nil
		}
		return successfulWireGuardProbe(name, args...)
	}
	actual, err := probeWireGuardTools(run)
	if actual != "1.0.20250521" || err == nil || !strings.Contains(err.Error(), "包版本") {
		t.Fatalf("包与工具版本不一致未判红:actual=%q err=%v", actual, err)
	}
}

func TestWireGuardProbeRejectsMissingCompanionFile(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" && len(args) > 0 && args[0] == "-L" {
			return []byte(wireGuardExecutable + "\n" + wireGuardQuick + "\n"), nil
		}
		return successfulWireGuardProbe(name, args...)
	}
	_, err := probeWireGuardTools(run)
	if err == nil || !strings.Contains(err.Error(), wireGuardReresolve) {
		t.Fatalf("缺配套文件未判红:%v", err)
	}
}

func TestWireGuardProbeRejectsMissingSystemdUnit(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" && len(args) > 0 && args[0] == "-L" {
			return []byte(strings.Join([]string{
				wireGuardExecutable, wireGuardQuick, wireGuardReresolve, "",
			}, "\n")), nil
		}
		return successfulWireGuardProbe(name, args...)
	}
	_, err := probeWireGuardTools(run)
	if err == nil || !strings.Contains(err.Error(), "wg-quick@.service") {
		t.Fatalf("缺 systemd unit 未判红:%v", err)
	}
}

func TestDebianUpstreamVersion(t *testing.T) {
	for input, want := range map[string]string{
		"1.0.20250521-1loom1~jammy1":   "1.0.20250521",
		"2:1.0.20250521-1loom1~noble1": "1.0.20250521",
		"1.0.20250521":                 "1.0.20250521",
	} {
		if got := debianUpstreamVersion(input); got != want {
			t.Errorf("debianUpstreamVersion(%q)=%q want %q", input, got, want)
		}
	}
}

func TestWireGuardSignedComponentNameRemainsBackwardCompatible(t *testing.T) {
	legacy := []ComponentStatus{{Name: "wireguard", Expected: "1", Actual: "1"}}
	if problems := validateComponentStatuses(legacy); len(problems) != 0 {
		t.Fatalf("已部署 reader 使用的 wireguard 线名被拒绝:%v", problems)
	}
	renamed := []ComponentStatus{{Name: "wireguard-tools", Expected: "1", Actual: "1"}}
	if problems := validateComponentStatuses(renamed); len(problems) == 0 {
		t.Fatal("未升级 canonical 版本却接受了 wireguard-tools 改名")
	}
}

func TestCappedBufferBoundsMemoryWithoutShortWrite(t *testing.T) {
	b := cappedBuffer{limit: 4}
	if n, err := b.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if got := b.String(); got != "abcd" || !b.truncated {
		t.Fatalf("buffer=%q truncated=%v", got, b.truncated)
	}
}

func TestAgentProtocolComesFromFreshAgentState(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	cfg := &Config{Node: "access", ExpectedComponents: ComponentVersions{Agent: "0.1.0"}}
	state := &AgentState{
		Node: "access", TS: now.Format(time.RFC3339), ComponentVersion: "0.0.9",
		Selections: []AgentSelection{{
			Declaration: "d", Selector: "s", Candidate: "c", UpdatedAt: now.Format(time.RFC3339),
			Health: &AgentCandidateHealth{Candidates: 1, Unknown: 1, SelectedState: "unknown"},
		}},
	}
	got := componentStatuses(cfg, state, now)
	if len(got) != 1 || got[0].Name != "agent-protocol" || got[0].Actual != "0.0.9" || got[0].OK() {
		t.Fatalf("did not use agent-owned protocol version: %+v", got)
	}
	state.ComponentVersion = ""
	got = componentStatuses(cfg, state, now)
	if len(got) != 1 || got[0].Error == "" || got[0].OK() {
		t.Fatalf("legacy agent state was treated as verified: %+v", got)
	}
}

func TestCollectCarriesAgentProtocolMismatchIntoStatusHealth(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	path := t.TempDir() + "/agent-state.json"
	body, err := json.Marshal(AgentState{
		Node: "access", TS: now.Format(time.RFC3339), ComponentVersion: "0.0.9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	st := Collect(&Config{
		Node: "access", AgentState: path,
		ExpectedComponents: ComponentVersions{Agent: "0.1.0"},
	}, now)
	if len(st.Components) != 1 || st.Components[0].Name != "agent-protocol" ||
		st.Components[0].Actual != "0.0.9" || st.Components[0].OK() {
		t.Fatalf("Collect 没有保留 Agent 协议漂移:%+v", st.Components)
	}
	// Collect 还可能报告测试主机没有 wg/systemd；清掉这些无关采集错误，
	// 证明组件漂移本身就足以让 Status 判红。
	st.Errors = nil
	st.Rollout, st.Publisher, st.Observation = nil, nil, nil
	st.Tunnels, st.Drift = nil, nil
	if st.OKAt(now) {
		t.Fatal("Agent 协议漂移进入 Status 后仍被判成健康")
	}
}
