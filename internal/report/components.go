package report

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ComponentVersions 是节点应当运行的组件版本。字段只在该节点确实持有相应
// 角色时由 renderer 填入；空字段表示这台机器不负责该组件，而不是 latest。
type ComponentVersions struct {
	SingBox   string `json:"sing_box,omitempty"`
	WireGuard string `json:"wireguard,omitempty"`
	Tailscale string `json:"tailscale,omitempty"`
	Agent     string `json:"agent,omitempty"`
}

// ComponentStatus 把 SSOT 期望态和机器上实际读到的版本并排放置。命令执行或
// 输出解析失败必须留在 Error，不能把空 Actual 当作“没漂移”。
type ComponentStatus struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Actual   string `json:"actual,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (c ComponentStatus) OK() bool {
	return c.Expected != "" && c.Actual != "" && c.Error == "" &&
		normalizeComponentVersion(c.Actual) == normalizeComponentVersion(c.Expected)
}

type componentCommand func(name string, args ...string) ([]byte, error)

func collectComponents(expected ComponentVersions) []ComponentStatus {
	return collectComponentsWith(expected, runComponentCommand)
}

func componentStatuses(cfg *Config, agent *AgentState, now time.Time) []ComponentStatus {
	if cfg == nil {
		return nil
	}
	out := collectComponents(cfg.ExpectedComponents)
	if expected := cfg.ExpectedComponents.Agent; expected != "" {
		st := ComponentStatus{Name: "agent-protocol", Expected: expected}
		switch problems := validateAgentStateForConfig(agent, cfg, now); {
		case agent == nil:
			st.Error = "Agent 状态不存在，无法核对正在运行的协议版本"
		case len(problems) > 0:
			st.Error = "Agent 状态不可信或已过期:" + problems[0]
		case agent.ComponentVersion == "":
			st.Error = "Agent 未上报协议版本（旧版或尚未完成首轮状态写入）"
		default:
			st.Actual = agent.ComponentVersion
		}
		out = append(out, st)
	}
	return out
}

// collectComponentsWith 把命令执行作为参数注入，避免测试通过改全局 PATH 或
// package 变量影响并行用例。
func collectComponentsWith(expected ComponentVersions, run componentCommand) []ComponentStatus {
	type spec struct {
		name, expected, command string
		args                    []string
	}
	specs := []spec{
		{name: "sing-box", expected: expected.SingBox, command: "sing-box", args: []string{"version"}},
		{name: "wireguard", expected: expected.WireGuard, command: "wg", args: []string{"--version"}},
		{name: "tailscale", expected: expected.Tailscale, command: "tailscale", args: []string{"version"}},
	}
	enabled := make([]spec, 0, len(specs))
	for _, s := range specs {
		if s.expected != "" {
			enabled = append(enabled, s)
		}
	}
	// 版本命令彼此独立。串行执行会把三个独立的 3 秒失败预算叠成 9 秒，
	// 超过 /status 客户端的总期限；按固定槽位并行写入既缩短尾延迟，也保留
	// renderer 定义的稳定输出顺序。
	out := make([]ComponentStatus, len(enabled))
	var wg sync.WaitGroup
	for i := range enabled {
		i, s := i, enabled[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := ComponentStatus{Name: s.name, Expected: s.expected}
			b, err := run(s.command, s.args...)
			if err != nil {
				st.Error = fmt.Sprintf("读取版本失败:%v", err)
				if detail := firstNonEmptyLine(string(b)); detail != "" {
					st.Error += ":" + detail
				}
			} else if st.Actual = componentVersionFromOutput(s.name, string(b)); st.Actual == "" {
				st.Error = "无法从版本命令输出中识别版本"
			}
			out[i] = st
		}()
	}
	wg.Wait()
	return out
}

func componentVersionFromOutput(name, output string) string {
	fields := strings.Fields(firstNonEmptyLine(output))
	if len(fields) == 0 {
		return ""
	}
	switch name {
	case "sing-box":
		if len(fields) >= 3 && fields[0] == "sing-box" && fields[1] == "version" {
			return cleanVersionToken(fields[2])
		}
	case "wireguard":
		if len(fields) >= 2 && fields[0] == "wireguard-tools" {
			return cleanVersionToken(fields[1])
		}
	case "tailscale":
		if len(fields) == 1 {
			return cleanVersionToken(fields[0])
		}
	}
	return ""
}

func cleanVersionToken(s string) string {
	s = strings.TrimSpace(strings.Trim(s, ",;()[]{}"))
	s = strings.TrimPrefix(s, "v")
	if s == "" || !unicode.IsDigit(rune(s[0])) {
		return ""
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(".-+_", r) {
			continue
		}
		return ""
	}
	return s
}

func normalizeComponentVersion(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "v")
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if len(line) > 160 {
				return line[:160] + "…"
			}
			return line
		}
	}
	return ""
}

func sortComponentStatuses(xs []ComponentStatus) {
	sort.Slice(xs, func(i, j int) bool {
		a, b := xs[i], xs[j]
		for _, pair := range [][2]string{
			{a.Name, b.Name}, {a.Expected, b.Expected},
			{a.Actual, b.Actual}, {a.Error, b.Error},
		} {
			if n := cmp.Compare(pair[0], pair[1]); n != 0 {
				return n < 0
			}
		}
		return false
	})
}

func validateComponentStatuses(xs []ComponentStatus) []string {
	if len(xs) > 16 {
		return []string{"组件条目超过 16 个"}
	}
	allowed := map[string]bool{
		"sing-box": true, "wireguard": true, "tailscale": true, "agent-protocol": true,
	}
	seen := map[string]bool{}
	var out []string
	validText := func(s string, limit int) bool {
		return len(s) <= limit && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\r\n\x00")
	}
	for _, c := range xs {
		switch {
		case !allowed[c.Name]:
			out = append(out, "未知组件名:"+c.Name)
		case seen[c.Name]:
			out = append(out, "重复组件:"+c.Name)
		}
		seen[c.Name] = true
		if c.Expected == "" || !validText(c.Expected, 64) {
			out = append(out, "组件 "+c.Name+" 的 expected 非法")
		}
		if c.Actual != "" && !validText(c.Actual, 64) {
			out = append(out, "组件 "+c.Name+" 的 actual 非法")
		}
		if !validText(c.Error, 512) {
			out = append(out, "组件 "+c.Name+" 的 error 非法")
		}
		if c.Actual == "" && c.Error == "" {
			out = append(out, "组件 "+c.Name+" 既没有 actual 也没有 error")
		}
	}
	return out
}

const (
	componentCommandTimeout = 3 * time.Second
	componentCommandWait    = 250 * time.Millisecond
	componentOutputLimit    = 64 << 10
)

// runComponentCommand 对版本探测设置独立总期限和内存上限。report 是常驻
// 健康入口；一个损坏的外部程序不能让整次 /status 永久卡住或无限吃内存。
func runComponentCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), componentCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// CommandContext 能杀掉直接子进程，但它派生的进程可能继续持有 stdout /
	// stderr。WaitDelay 负责在直接子进程退出或超时后关闭这些管道，避免健康
	// 入口无限等待 EOF。
	cmd.WaitDelay = componentCommandWait
	var out cappedBuffer
	out.limit = componentOutputLimit
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.Bytes(), fmt.Errorf("超过 %s", componentCommandTimeout)
	}
	if out.truncated && err == nil {
		return out.Bytes(), fmt.Errorf("版本命令输出超过 %d 字节", componentOutputLimit)
	}
	return out.Bytes(), err
}

type cappedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := b.limit - b.Len()
	if remain <= 0 {
		b.truncated = true
		return n, nil
	}
	if len(p) > remain {
		_, _ = b.Buffer.Write(p[:remain])
		b.truncated = true
		return n, nil
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
