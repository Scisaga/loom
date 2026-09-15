//go:build !windows

// 管理面快速发布只消费已构建制品，签名发布成功后才并行激活。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"loom/internal/model"
	"loom/internal/publish"
	"loom/internal/snapshot"
	"loom/internal/version"
)

type config struct {
	root, sshConfig, source, releaseDir, signingKey, history, pinDir, command string
	hosts                                                                     []string
	local                                                                     string
	outputs                                                                   []string
}

var defaults = map[string]string{
	"LOOM_DEPLOY_HOSTS": "", "LOOM_LOCAL_NODE": "", "LOOM_SSH_CONFIG": ".ssh_config",
	"LOOM_DEPLOY_SOURCE": "deploy/ssot.yaml", "LOOM_RELEASE_DIR": "deploy/released",
	"LOOM_SIGNING_KEY": "deploy/keys/platform-signing.key", "LOOM_PUBLISH_OUTPUTS": "",
	"LOOM_PUBLISH_HISTORY": "deploy/ssot-history", "LOOM_PIN_DIR": "deploy/pinned",
	"LOOM_DEPLOY_COMMAND": "/usr/local/bin/loom",
}

var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// 仅读取白名单赋值；其他应用的凭据既不展开，也不进入子进程环境。
func parseEnv(r io.Reader) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		s := strings.TrimSpace(scanner.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.HasPrefix(s, "export ") {
			s = strings.TrimSpace(strings.TrimPrefix(s, "export "))
		}
		key, value, ok := strings.Cut(s, "=")
		key = strings.TrimSpace(key)
		if !ok || !keyPattern.MatchString(key) {
			return nil, fmt.Errorf("[配置] .env 第 %d 行不是赋值", line)
		}
		if _, known := defaults[key]; !known {
			if strings.HasPrefix(key, "LOOM_DEPLOY_") || strings.HasPrefix(key, "LOOM_PUBLISH_") {
				return nil, fmt.Errorf("[配置] 未知发布参数 %s", key)
			}
			continue
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("[配置] 重复参数 %s", key)
		}
		value = strings.TrimSpace(value)
		if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
			if len(value) < 2 || value[len(value)-1] != value[0] {
				return nil, fmt.Errorf("[配置] .env 第 %d 行引号不完整", line)
			}
			value = value[1 : len(value)-1]
		}
		if strings.ContainsAny(value, "$`\x00\r\n") {
			return nil, fmt.Errorf("[配置] 参数 %s 含控制字符或 shell 展开", key)
		}
		values[key] = value
	}
	return values, scanner.Err()
}

func loadConfig(path string) (config, error) {
	var c config
	abs, err := filepath.Abs(path)
	if err != nil {
		return c, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return c, fmt.Errorf("[配置] 读取 .env：%w", err)
	}
	defer f.Close()
	values, err := parseEnv(f)
	if err != nil {
		return c, err
	}
	for key, value := range defaults {
		if _, ok := values[key]; !ok {
			values[key] = value
		}
	}
	c.root = filepath.Dir(abs)
	resolve := func(key string) string {
		value := values[key]
		if value == "" {
			return ""
		}
		if !filepath.IsAbs(value) {
			value = filepath.Join(c.root, value)
		}
		return filepath.Clean(value)
	}
	c.sshConfig, c.source = resolve("LOOM_SSH_CONFIG"), resolve("LOOM_DEPLOY_SOURCE")
	c.releaseDir, c.signingKey = resolve("LOOM_RELEASE_DIR"), resolve("LOOM_SIGNING_KEY")
	c.history, c.pinDir, c.command = resolve("LOOM_PUBLISH_HISTORY"), resolve("LOOM_PIN_DIR"), resolve("LOOM_DEPLOY_COMMAND")
	c.hosts, c.local = strings.Fields(values["LOOM_DEPLOY_HOSTS"]), values["LOOM_LOCAL_NODE"]
	for _, path := range []string{c.sshConfig, c.source, c.releaseDir, c.signingKey, c.history, c.pinDir, c.command} {
		if path == "" {
			return c, fmt.Errorf("[配置] 发布路径不允许为空")
		}
	}
	if err := json.Unmarshal([]byte(values["LOOM_PUBLISH_OUTPUTS"]), &c.outputs); err != nil || len(c.outputs) == 0 {
		return c, fmt.Errorf("[配置] LOOM_PUBLISH_OUTPUTS 必须是非空 JSON 字符串数组")
	}
	seen, localOutput := map[string]bool{}, false
	for i, output := range c.outputs {
		if output == "" {
			return c, fmt.Errorf("[配置] 分发目标不允许为空")
		}
		if !strings.HasPrefix(output, "ssh://") {
			if !filepath.IsAbs(output) {
				output = filepath.Join(c.root, output)
			}
			output = filepath.Clean(output)
			localOutput = true
		}
		if _, err := publish.ParseTarget(output, c.sshConfig); err != nil {
			return c, fmt.Errorf("[配置] 分发目标格式非法：%w", err)
		}
		if seen[output] {
			return c, fmt.Errorf("[配置] 重复分发目标")
		}
		seen[output], c.outputs[i] = true, output
	}
	if !localOutput {
		return c, fmt.Errorf("[配置] 至少配置一个本地分发目录以核对 signed current")
	}
	return c, nil
}

// 管理地址只从显式别名取得，SSOT 仅用于校验覆盖范围；不据 direction 选路。
func validateInventory(c config) error {
	ssot, err := model.LoadFile(c.source)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, node := range ssot.Nodes {
		if !node.Decommission && (node.Server != nil || node.Access != nil && node.Access.Platform.UsesLinuxLifecycle()) {
			want[node.ID] = true
		}
	}
	body, err := os.ReadFile(c.sshConfig)
	if err != nil {
		return err
	}
	aliases := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) > 1 && strings.EqualFold(fields[0], "Host") {
			for _, name := range fields[1:] {
				if aliasPattern.MatchString(name) {
					aliases[name] = true
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, host := range c.hosts {
		if !aliasPattern.MatchString(host) || seen[host] || !want[host] || host != c.local && !aliases[host] {
			return fmt.Errorf("[inventory] 节点别名非法、重复、未知或缺少 SSH 配置：%s", host)
		}
		seen[host] = true
	}
	if len(seen) == 0 || len(seen) != len(want) {
		return fmt.Errorf("[inventory] LOOM_DEPLOY_HOSTS 未精确覆盖当前 Linux/server 节点")
	}
	if c.local != "" && !seen[c.local] {
		return fmt.Errorf("[inventory] LOOM_LOCAL_NODE 不在发布节点中")
	}
	return nil
}

type runner func(context.Context, string, []string, string) (string, error)

func commandRunner(root string) runner {
	return func(ctx context.Context, name string, args []string, input string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir, cmd.Stdin = root, strings.NewReader(input)
		// SSH 可使用既有 agent，DNS token 等无关凭据不进入子进程。
		for _, key := range []string{"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "SSH_AUTH_SOCK"} {
			if value, ok := os.LookupEnv(key); ok {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
		}
		// partial clone 缺失对象时必须本地失败，plan 不可隐式 fetch。
		cmd.Env = append(cmd.Env, "GIT_NO_LAZY_FETCH=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return string(output), fmt.Errorf("[执行] %s 失败：%w\n%s", filepath.Base(name), err, strings.TrimSpace(string(output)))
		}
		return string(output), nil
	}
}

func validateCoordinate(coordinate version.Coordinate, commit string) error {
	if !commitPattern.MatchString(commit) || coordinate.Commit != commit || coordinate.Dirty {
		return fmt.Errorf("[制品] 必须来自指定完整 commit 的干净构建")
	}
	if coordinate.Platform != "linux/"+runtime.GOARCH {
		return fmt.Errorf("[制品] 当前快速发布要求与构建机同架构的 Linux 制品")
	}
	return nil
}

func run(args []string, output io.Writer) error {
	return runWith(args, output, commandRunner, publish.InspectBinary)
}

func runWith(args []string, output io.Writer, makeRunner func(string) runner, inspect func(publish.BinaryCandidate) (version.Coordinate, error)) error {
	fs := flag.NewFlagSet("deploy-code", flag.ContinueOnError)
	envPath := fs.String("env", ".env", "私有部署参数文件")
	commit := fs.String("commit", "", "待发布制品的完整源码 commit")
	binary := fs.String("binary", "", "已构建一次的待发布制品")
	reason := fs.String("reason", "", "本次发布理由")
	plan := fs.Bool("plan", false, "只检查本地输入并打印计划，不发布、不连接节点")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !commitPattern.MatchString(*commit) || *binary == "" || strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("[发布] 需要 --commit <完整 commit> --binary <制品> --reason <理由> [--plan]")
	}
	c, err := loadConfig(*envPath)
	if err != nil {
		return err
	}
	if err := validateInventory(c); err != nil {
		return err
	}
	candidate, err := publish.ReadBinaryCandidate(*binary)
	if err != nil {
		return err
	}
	coordinate, err := inspect(candidate)
	if err != nil {
		return err
	}
	if err := validateCoordinate(coordinate, *commit); err != nil {
		return err
	}
	runCommand := makeRunner(c.root)
	if _, err := runCommand(context.Background(), "git", []string{"cat-file", "-e", *commit + "^{commit}"}, ""); err != nil {
		return fmt.Errorf("[制品] 本地源码库不能追溯该 commit：%w", err)
	}
	pub, err := readPublicKey(c.signingKey)
	if err != nil {
		return err
	}
	if info, err := os.Stat(c.command); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("[发布] LOOM_DEPLOY_COMMAND 必须是可执行文件")
	}
	if *plan {
		return json.NewEncoder(output).Encode(struct {
			Mode   string   `json:"mode"`
			Commit string   `json:"commit"`
			SHA256 string   `json:"sha256"`
			Hosts  []string `json:"hosts"`
			Local  string   `json:"local_node,omitempty"`
			Steps  []string `json:"steps"`
		}{"plan", *commit, candidate.SHA256, c.hosts, c.local, []string{"loom release", "loom publish（一次）", "核对 signed current 与制品绑定", "并行复制、校验、原子替换、重启现有常驻服务"}})
	}
	// 从已验证字节创建私有稳定副本，后续 release/SCP 不重开原制品路径。
	if err := os.MkdirAll(c.releaseDir, 0o700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(c.releaseDir, ".deploy-code-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	stable := filepath.Join(dir, "loom")
	if err := os.WriteFile(stable, candidate.Body, 0o700); err != nil {
		return err
	}
	if err := authorize(c, stable, *reason, runCommand); err != nil {
		return err
	}
	// release/publish 自己获取这把锁；其返回后重取并复核，直到激活完成
	// 都不允许另一笔 release/pin/rollback 改变授权。先取锁再调用 CLI 会自锁。
	return withActivationLock(publish.LockPath, func() error {
		if err := verifyPin(c.pinDir, candidate.SHA256); err != nil {
			return err
		}
		release, _, err := publish.ReadRelease(c.releaseDir)
		if err != nil {
			return err
		}
		if release == nil || release.SHA256 != candidate.SHA256 || release.Commit != *commit || release.Dirty {
			return fmt.Errorf("[发布] 放行记录与本次制品不符，停止快速发布")
		}
		for _, target := range c.outputs {
			if !strings.HasPrefix(target, "ssh://") {
				if err := verifyDistribution(target, c.hosts, candidate, pub); err != nil {
					return err
				}
			}
		}
		return activateAll(c, stable, candidate.SHA256, runCommand, output)
	})
}

func withActivationLock(path string, action func() error) error {
	unlock, err := publish.AcquireLock(path)
	if err != nil {
		return err
	}
	defer unlock()
	return action()
}

func verifyPin(dir, checksum string) error {
	pin, _, err := publish.ReadPin(dir)
	if err != nil {
		return err
	}
	if pin != nil && pin.SHA256 != checksum {
		return fmt.Errorf("[发布] 当前 pin 已选择其他制品，停止快速发布")
	}
	return nil
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("[密钥] 平台签名私钥编码或长度非法")
	}
	return ed25519.PrivateKey(key).Public().(ed25519.PublicKey), nil
}

func authorize(c config, stable, reason string, command runner) error {
	if _, err := command(context.Background(), c.command, []string{"release", "-binary", stable, "-dir", c.releaseDir, "-reason", reason}, ""); err != nil {
		return err
	}
	args := []string{"publish", c.source, "-key", c.signingKey, "-release-dir", c.releaseDir,
		"-pin-dir", c.pinDir, "-ssot-history", c.history, "-ssh-config", c.sshConfig}
	for _, target := range c.outputs {
		args = append(args, "-o", target)
	}
	_, err := command(context.Background(), c.command, args, "")
	return err
}

// Pin 或节点 assignment 可能仍绑定旧版，publish 成功本身不授权直发新版。
func verifyDistribution(root string, hosts []string, candidate publish.BinaryCandidate, pub ed25519.PublicKey) error {
	body, err := os.ReadFile(filepath.Join(root, "current.json"))
	if err != nil {
		return err
	}
	current, err := publish.DecodeDeploymentCurrent(body)
	if err != nil {
		return err
	}
	if err := current.Verify(pub); err != nil {
		return err
	}
	for _, host := range hosts {
		id, err := current.Select(host)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(filepath.Join(root, id, "snapshot.json"))
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(filepath.Join(root, id, "snapshot.sig"))
		if err != nil {
			return err
		}
		if err := snapshot.VerifySignature(body, sig, pub); err != nil {
			return err
		}
		var manifest snapshot.Manifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			return err
		}
		matched, member := false, false
		for _, bundle := range manifest.Bundles {
			member = member || bundle.Owner == host
		}
		for _, binary := range manifest.Binaries {
			if binary.OS == "linux" && binary.Arch == runtime.GOARCH && binary.SHA256 == candidate.SHA256 && binary.Size == candidate.Size {
				matched = true
			}
		}
		if manifest.ID != id || !matched || !member {
			return fmt.Errorf("[发布] 节点 %s 的 signed current 未绑定本次制品与配置", host)
		}
	}
	bin, err := os.ReadFile(filepath.Join(root, "bin", candidate.SHA256))
	if err != nil {
		return err
	}
	if !bytes.Equal(bin, candidate.Body) {
		return fmt.Errorf("[发布] 分发制品与已验证候选不同")
	}
	return nil
}

func activationScript(temporary, checksum string) string {
	// 列表读取失败必须停止；不重启 oneshot，不触发 pull 或收敛轮询。
	return fmt.Sprintf(`set -euo pipefail
candidate='%s'
trap 'rm -f -- "$candidate"' EXIT
printf '%%s  %%s\n' '%s' "$candidate" | sha256sum -c -
chmod 0755 "$candidate"
running=$(systemctl list-units --type=service --state=running --no-legend --plain 'loom-*')
running_units=()
while read -r unit ignored; do
  case "$unit" in loom-*.service) ;; *) continue ;; esac
  [ "$unit" != loom-pull.service ] || continue
  kind=$(systemctl show --property=Type --value "$unit")
  case "$kind" in
    simple|exec|forking|notify|notify-reload|dbus|idle) running_units+=("$unit") ;;
    oneshot) ;;
    *) printf '无法确定常驻服务类型: %%s\n' "$unit" >&2; exit 1 ;;
  esac
done <<< "$running"
mv -f -- "$candidate" /usr/local/bin/loom
if (( ${#running_units[@]} > 0 )); then
  systemctl restart "${running_units[@]}"
fi
printf '已激活；重启服务: %%s\n' "${running_units[*]}"
`, temporary, checksum)
}

func activateAll(c config, stable, checksum string, command runner, output io.Writer) error {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	temporary := "/usr/local/bin/.loom-" + hex.EncodeToString(nonce) + ".tmp"
	script := activationScript(temporary, checksum)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for _, host := range c.hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			name, args := "scp", []string{"-F", c.sshConfig, "-o", "BatchMode=yes", stable, host + ":" + temporary}
			if host == c.local {
				name, args = "install", []string{"-m", "0755", stable, temporary}
			}
			_, err := command(ctx, name, args, "")
			var detail string
			if err == nil {
				name, args = "ssh", []string{"-F", c.sshConfig, "-o", "BatchMode=yes", host, "bash", "-s"}
				if host == c.local {
					name, args = "bash", []string{"-s"}
				}
				detail, err = command(ctx, name, args, script)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, host)
				fmt.Fprintf(output, "%s: 失败\n%v\n", host, err)
			} else {
				fmt.Fprintf(output, "%s: 已激活\n%s", host, detail)
			}
		}(host)
	}
	wg.Wait()
	if len(failures) != 0 {
		sort.Strings(failures)
		return fmt.Errorf("[激活] 以下节点命令失败：%s", strings.Join(failures, ", "))
	}
	return nil
}
