package report

import (
	"bytes"
	"cmp"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ComponentVersions 是节点应当运行的组件版本。字段只在该节点确实持有相应
// 角色时由 renderer 填入；空字段表示这台机器不负责该组件，而不是 latest。
type ComponentVersions struct {
	SingBox string `json:"sing_box,omitempty"`
	// WireGuard 的线字段保留 SSOT 名称，核验对象明确是 wireguard-tools。
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
type componentBuildVersion func(path string) (string, error)

type componentProbeCache struct {
	mu       sync.Mutex
	at       time.Time
	expected ComponentVersions
	statuses []ComponentStatus
}

func collectComponents(expected ComponentVersions) []ComponentStatus {
	return collectComponentsWith(expected, runComponentCommand)
}

const componentProbeTTL = 30 * time.Second

// 必须与 renderer 的 sing-box.service ExecStart 一致。探 PATH 中另一份文件
// 即使版本相同，也不能证明下一次 systemd 重启会执行的制品是正确的。
const singBoxExecutablePath = "/usr/local/bin/sing-box"

// 组件签名线协议中的名字已经由早期 reader 固定为 "wireguard"。探测对象
// 虽然是 Debian 的 wireguard-tools 包，但不能在同一个 canonical v5 下悄悄
// 改名；否则新旧 reader 会在滚动窗口里互相拒收观测。
const (
	wireGuardComponentName = "wireguard"
	wireGuardExecutable    = "/usr/bin/wg"
	wireGuardQuick         = "/usr/bin/wg-quick"
	wireGuardReresolve     = "/usr/share/doc/wireguard-tools/examples/reresolve-dns/reresolve-dns.sh"
	wireGuardUnitSuffix    = "/systemd/system/wg-quick@.service"
)

func collectComponentsCached(cfg *Config, now time.Time) []ComponentStatus {
	return collectComponentsCachedWith(cfg, now, runComponentCommand)
}

// collectComponentsCachedWith 在锁内完成一次探测：同一时刻无论页面、gossip
// 还是多个 /status 请求到达，都只有一个调用者会 fork，其他调用者复用结果。
func collectComponentsCachedWith(cfg *Config, now time.Time, run componentCommand) []ComponentStatus {
	if cfg == nil {
		return nil
	}
	c := &cfg.componentProbe
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && !now.Before(c.at) && now.Sub(c.at) < componentProbeTTL &&
		c.expected == cfg.ExpectedComponents {
		return append([]ComponentStatus(nil), c.statuses...)
	}
	got := collectComponentsWith(cfg.ExpectedComponents, run)
	c.at, c.expected = now, cfg.ExpectedComponents
	c.statuses = append(c.statuses[:0], got...)
	return append([]ComponentStatus(nil), got...)
}

func componentStatuses(cfg *Config, agent *AgentState, now time.Time) []ComponentStatus {
	if cfg == nil {
		return nil
	}
	out := collectComponentsCached(cfg, now)
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
	return collectComponentsWithReaders(expected, run, readSingBoxBuildVersion)
}

func collectComponentsWithReaders(expected ComponentVersions, run componentCommand,
	readBuildVersion componentBuildVersion) []ComponentStatus {
	type spec struct {
		name, expected string
	}
	specs := []spec{
		{name: "sing-box", expected: expected.SingBox},
		{name: wireGuardComponentName, expected: expected.WireGuard},
		{name: "tailscale", expected: expected.Tailscale},
	}
	enabled := make([]spec, 0, len(specs))
	for _, s := range specs {
		if s.expected != "" {
			enabled = append(enabled, s)
		}
	}
	// 版本命令彼此独立。串行执行会把三个独立的 1 秒失败预算叠成 3 秒，
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
			actual, err := probeComponentVersion(s.name, run, readBuildVersion)
			st.Actual = actual
			if err != nil {
				st.Error = err.Error()
			}
			out[i] = st
		}()
	}
	wg.Wait()
	return out
}

func probeComponentVersion(name string, run componentCommand, readBuildVersion componentBuildVersion) (string, error) {
	switch name {
	case "sing-box":
		return probeRunningSingBox(run, readBuildVersion)
	case wireGuardComponentName:
		return probeWireGuardTools(run)
	case "tailscale":
		// `tailscale version` 只证明 client，不能证明 tailscaled 的运行版本。
		// renderer/validator 当前不会产生这个期望；手写 report 配置也必须红，
		// 不能用 client 版本冒充 daemon workload。
		return "", fmt.Errorf("尚未实现 tailscaled 运行进程版本核验")
	default:
		return "", fmt.Errorf("未知组件:%s", name)
	}
}

// probeWireGuardTools 不接受 PATH 里碰巧存在的一份 wg 冒充已安装组件。它同时
// 核对固定路径的工具版本、dpkg 的安装状态/包版本、关键配套文件归属，以及
// dpkg 的文件摘要。四项独立并行，避免把单命令超时预算串成 /status 尾延迟。
func probeWireGuardTools(run componentCommand) (string, error) {
	type result struct {
		kind   string
		output []byte
		err    error
	}
	checks := []struct {
		kind string
		name string
		args []string
	}{
		{kind: "tool", name: wireGuardExecutable, args: []string{"--version"}},
		{kind: "package", name: "dpkg-query", args: []string{"-W", "-f=${Status}\t${Version}\n", "wireguard-tools"}},
		{kind: "files", name: "dpkg-query", args: []string{"-L", "wireguard-tools"}},
		{kind: "verify", name: "dpkg", args: []string{"--verify", "wireguard-tools"}},
	}
	ch := make(chan result, len(checks))
	for _, check := range checks {
		check := check
		go func() {
			b, err := run(check.name, check.args...)
			ch <- result{kind: check.kind, output: b, err: err}
		}()
	}
	results := make(map[string]result, len(checks))
	for range checks {
		r := <-ch
		results[r.kind] = r
	}

	tool := results["tool"]
	actual := componentVersionFromOutput(wireGuardComponentName, string(tool.output))
	if tool.err != nil {
		return "", commandVersionError("读取 wireguard-tools 固定路径版本", tool.output, tool.err)
	}
	if actual == "" {
		return "", fmt.Errorf("无法从 %s 版本命令首行识别 wireguard-tools 版本", wireGuardExecutable)
	}

	pkg := results["package"]
	if pkg.err != nil {
		return actual, commandVersionError("读取 wireguard-tools 包状态", pkg.output, pkg.err)
	}
	packageVersion, err := installedDebianPackageVersion(string(pkg.output))
	if err != nil {
		return actual, err
	}
	if normalizeComponentVersion(debianUpstreamVersion(packageVersion)) != normalizeComponentVersion(actual) {
		return actual, fmt.Errorf("wireguard-tools 包版本=%s，%s 报告=%s", packageVersion,
			wireGuardExecutable, actual)
	}

	files := results["files"]
	if files.err != nil {
		return actual, commandVersionError("读取 wireguard-tools 包文件", files.output, files.err)
	}
	owned := map[string]bool{}
	for _, line := range strings.Split(string(files.output), "\n") {
		owned[strings.TrimSpace(line)] = true
	}
	for _, path := range []string{wireGuardExecutable, wireGuardQuick, wireGuardReresolve} {
		if !owned[path] {
			return actual, fmt.Errorf("wireguard-tools 包未声明关键文件 %s", path)
		}
	}
	unitOwned := false
	for path := range owned {
		if strings.HasSuffix(path, wireGuardUnitSuffix) {
			unitOwned = true
			break
		}
	}
	if !unitOwned {
		return actual, fmt.Errorf("wireguard-tools 包未声明关键 unit *%s", wireGuardUnitSuffix)
	}

	verified := results["verify"]
	if verified.err != nil {
		return actual, commandVersionError("校验 wireguard-tools 包文件", verified.output, verified.err)
	}
	if detail := firstNonEmptyLine(string(verified.output)); detail != "" {
		return actual, fmt.Errorf("wireguard-tools 包文件摘要不一致:%s", detail)
	}
	return actual, nil
}

func installedDebianPackageVersion(output string) (string, error) {
	line := firstNonEmptyLine(output)
	const prefix = "install ok installed\t"
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("wireguard-tools 包未处于 installed 状态:%q", line)
	}
	version := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if version == "" || strings.ContainsAny(version, "\t ") {
		return "", fmt.Errorf("wireguard-tools 包版本非法:%q", version)
	}
	return version, nil
}

// Debian 版本可带 epoch 和发行版 revision，例如
// 1:1.0.20250521-1loom1~jammy1；组件期望仍使用上游版本坐标。
func debianUpstreamVersion(version string) string {
	if i := strings.IndexByte(version, ':'); i >= 0 {
		version = version[i+1:]
	}
	if i := strings.IndexByte(version, '-'); i >= 0 {
		version = version[:i]
	}
	return version
}

func probeRunningSingBox(run componentCommand, readBuildVersion componentBuildVersion) (string, error) {
	b, err := run("systemctl", "show", "--property=MainPID", "--value", "sing-box.service")
	if err != nil {
		return "", commandVersionError("读取 sing-box MainPID", b, err)
	}
	pidText := firstNonEmptyLine(string(b))
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 || strconv.Itoa(pid) != pidText {
		return "", fmt.Errorf("sing-box.service 没有有效 MainPID:%q", pidText)
	}

	// 同时核运行 inode 与 systemd ExecStart 的磁盘文件。只核后者会在“文件已替换、旧
	// 进程未重启”时假绿；只核运行态又会漏掉下一次重启将降级/失败的风险。
	type result struct {
		version string
		err     error
	}
	runningCh, installedCh := make(chan result, 1), make(chan result, 1)
	go func() {
		v, e := readBuildVersion("/proc/" + pidText + "/exe")
		runningCh <- result{v, e}
	}()
	go func() {
		v, e := readBuildVersion(singBoxExecutablePath)
		installedCh <- result{v, e}
	}()
	running, installed := <-runningCh, <-installedCh
	if installed.err != nil {
		return running.version, fmt.Errorf("读取磁盘 sing-box 版本:%w", installed.err)
	}
	if running.err != nil {
		// A capability-bearing sing-box process is non-dumpable.  The report
		// service intentionally lacks CAP_SYS_PTRACE, so hardened kernels deny
		// even read-only access to /proc/<pid>/exe.  Granting ptrace to the HTTP
		// status process would be a much larger security boundary than this
		// diagnostic warrants.  MainPID above still proves the workload is
		// running; use the on-disk Go build identity in this explicit case.
		// Deploy transactions independently restart and verify the service.
		// Limitation: a manual binary replacement without a restart cannot be
		// distinguished on such a host until the next service activation.
		if errors.Is(running.err, os.ErrPermission) {
			return installed.version, nil
		}
		return "", fmt.Errorf("读取 sing-box 运行进程版本:%w", running.err)
	}
	if normalizeComponentVersion(running.version) != normalizeComponentVersion(installed.version) {
		return running.version, fmt.Errorf("磁盘 sing-box=%s，运行进程=%s（旧 inode 尚未重启）",
			installed.version, running.version)
	}
	return running.version, nil
}

func readSingBoxBuildVersion(path string) (string, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读取 Go build info %s:%w", path, err)
	}
	const module = "github.com/sagernet/sing-box"
	if info.Main.Path != module {
		return "", fmt.Errorf("%s 主模块=%q,期望 %q", path, info.Main.Path, module)
	}
	version := cleanVersionToken(info.Main.Version)
	if version == "" {
		return "", fmt.Errorf("%s 的 %s build version=%q 无法识别", path, module, info.Main.Version)
	}
	return version, nil
}

func commandVersionError(prefix string, output []byte, err error) error {
	message := fmt.Sprintf("%s失败:%v", prefix, err)
	if detail := firstNonEmptyLine(string(output)); detail != "" {
		message += ":" + detail
	}
	return fmt.Errorf("%s", message)
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
	case wireGuardComponentName:
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
		"sing-box": true, wireGuardComponentName: true, "tailscale": true, "agent-protocol": true,
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
	componentCommandTimeout = time.Second
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
