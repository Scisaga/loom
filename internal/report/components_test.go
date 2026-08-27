package report

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCollectComponentsParsesKnownCommands(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		switch name {
		case "sing-box":
			return []byte("sing-box version 1.11.4\nEnvironment: go1.24 linux/amd64\n"), nil
		case "wg":
			return []byte("wireguard-tools v1.0.20250521 - https://www.wireguard.com/\n"), nil
		case "tailscale":
			return []byte("1.82.5\ntailscale commit: abc\n"), nil
		default:
			t.Fatalf("unexpected command %q %v", name, args)
			return nil, nil
		}
	}
	got := collectComponentsWith(ComponentVersions{
		SingBox: "1.11.4", WireGuard: "1.0.20250521", Tailscale: "1.82.5",
	}, run)
	wantNames := []string{"sing-box", "wireguard", "tailscale"}
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
	run := func(name string, _ ...string) ([]byte, error) {
		if name == "wg" {
			return []byte("permission denied\n"), errors.New("exit status 1")
		}
		return []byte("sing-box version 1.11.3\n"), nil
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
	run := func(name string, _ ...string) ([]byte, error) {
		if started.Add(1) == 3 {
			readyOnce.Do(func() { close(ready) })
		}
		select {
		case <-ready:
		case <-time.After(time.Second):
			return nil, errors.New("探测没有并发启动")
		}
		switch name {
		case "sing-box":
			return []byte("sing-box version 1.11.4\n"), nil
		case "wg":
			return []byte("wireguard-tools v1.0.20250521\n"), nil
		default:
			return []byte("1.82.5\n"), nil
		}
	}
	startedAt := time.Now()
	got := collectComponentsWith(ComponentVersions{
		SingBox: "1.11.4", WireGuard: "1.0.20250521", Tailscale: "1.82.5",
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
	_, err := runComponentCommand("/bin/sh", "-c", "sleep 10 &")
	if err == nil {
		t.Fatal("继承输出管道未关闭，却被当成成功")
	}
	if elapsed := time.Since(startedAt); elapsed >= 2*time.Second {
		t.Fatalf("等待继承管道耗时 %s，未受 WaitDelay 约束", elapsed)
	}
}

func TestComponentVersionParserRejectsAmbiguousNumbers(t *testing.T) {
	for name, output := range map[string]string{
		"wireguard": "warning code 1 before wireguard-tools v1.0.0",
		"tailscale": "warning 7\n1.82.5",
		"sing-box":  "warning 1\nsing-box version 1.11.4",
	} {
		if got := componentVersionFromOutput(name, output); got != "" {
			t.Errorf("%s parsed ambiguous token %q", name, got)
		}
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
