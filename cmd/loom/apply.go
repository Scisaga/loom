package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"loom/internal/deploy"
	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/report"
	"loom/internal/rollout"
)

const appliedSnapshotPath = "/var/lib/loom/applied"

// apply 把渲染好的配置包装到机器上(§14)。
//
// **主路径是节点自取**(§14.2.2、`loom pull`),这个命令是备用:分发点挂了、
// 或者一台机器还没 bootstrap 完时,从工作站 ssh 推。两条路径共用同一套安装
// 语义(internal/deploy)—— 先校验、失败就回滚、装完必须验证。
//
// 在它出现之前,这些步骤是一条条手打的,于是每次都可能漏掉一步。已经漏过
// 一次:没跑 sing-box check 就重启,配置非法导致崩溃重启循环,而只测了新
// 功能没看服务起没起来。
func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	in := fs.String("in", "", "已 hydrate 的产物目录(必需)")
	sshConf := fs.String("ssh-config", ".ssh_config", "ssh 配置文件")
	only := fs.String("node", "", "只装这一个节点(默认全部)")
	dry := fs.Bool("dry-run", false, "只打印会做什么,不连机器")
	timeout := fs.Duration("timeout", 3*time.Minute, "单个节点的超时")
	local := fs.String("local", "", "这个节点是本机,不走 ssh")

	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("需要 -in 指向 loom hydrate 的输出目录")
	}

	bundles, err := readBundles(*in)
	if err != nil {
		return err
	}
	nodes := make([]string, 0, len(bundles))
	for n := range bundles {
		if *only == "" || n == *only {
			nodes = append(nodes, n)
		}
	}
	sort.Strings(nodes)
	if len(nodes) == 0 {
		return fmt.Errorf("%s 里没有找到%s配置包", *in, nodeNote(*only))
	}
	// 先把所有将要安装的本地产物验完，再连接任何节点。若边装边验，前一台
	// 已经成功、后一台才发现 hydrate 目录残缺，会把一次纯本地输入错误变成
	// 不必要的半网发布。
	for _, n := range nodes {
		if err := validateHydratedBundle(n, bundles[n]); err != nil {
			return fmt.Errorf("%s 的 hydrate bundle 不完整，未连接任何节点:%w", n, err)
		}
	}

	// run id 只用于日志关联,不进任何被哈希的产物。
	runID := time.Now().UTC().Format("20060102-150405")
	fmt.Printf("apply run %s · %d 个节点\n", runID, len(nodes))

	var failed []string
	for _, n := range nodes {
		plan, unmapped := deploy.BuildPlan(n, bundles[n])
		bindManualApplyCoordinates(plan)
		fmt.Printf("\n%s(%d 个文件,涉及 %s)\n", n, len(plan.Files), strings.Join(plan.Verify, " "))
		// 装不了的必须说出来 —— 静默少装会让人以为整套都到位了。
		for _, u := range unmapped {
			fmt.Printf("   ! %s 没有约定的安装位置,不安装\n", u)
		}
		if *dry {
			script := deploy.Script(plan, runID)
			fmt.Printf("   (dry-run:脚本 %d 字节,预检 %d 项)\n", len(script), len(plan.PreCheck))
			fmt.Printf("   (dry-run 不连接节点；实际 apply 会从目标安装清单计算删除差集)\n")
			for _, c := range plan.PreCheck {
				fmt.Printf("   预检:%s\n", c)
			}
			continue
		}

		// 和 pull 一样，删除集合只能来自目标机的“上次安装清单”减去本次
		// desired。控制端不能从自己的 hydrate 目录猜目标机曾经装成功什么。
		inventory, err := readApplyInventory(n, *sshConf, *local == n, *timeout, render.ManifestPath)
		if err != nil {
			fmt.Printf("   ❌ 读取目标安装清单:%v\n", err)
			failed = append(failed, n)
			continue
		}
		bindInstalledInventory(plan, inventory, render.ManifestPath)
		for _, stale := range plan.Remove {
			fmt.Printf("   - 不再声明,将清掉:%s\n", stale)
		}

		script := deploy.Script(plan, runID)
		if err := runScript(n, script, *sshConf, *local == n, *timeout); err != nil {
			fmt.Printf("   ❌ %v\n", err)
			failed = append(failed, n)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d 个节点失败:%s(回滚是否完整以各节点输出为准)", len(failed), strings.Join(failed, " "))
	}
	return nil
}

// bindManualApplyCoordinates 防止备用的 SSH push 改了真实配置后，节点仍拿
// 旧 applied + Verified rollout 冒充“还在那个签名快照上”。deploy 脚本只
// 在 desired/Remove 确有变化时处理这些文件，并把删除纳入同一回滚事务；
// no-op reconcile 不会无端抹掉坐标，pull 的生产路径也不会提前写 applied。
func bindManualApplyCoordinates(plan *deploy.Plan) {
	plan.InvalidateOnChange = []string{appliedSnapshotPath, rollout.Path}
}

type applyInventory struct {
	files  []string
	sha256 string
	absent bool
}

func bindInstalledInventory(plan *deploy.Plan, inventory applyInventory, manifestPath string) {
	plan.Remove = plan.StaleFiles(inventory.files)
	plan.InventoryGuard = &deploy.InventoryGuard{
		Path:   manifestPath,
		SHA256: inventory.sha256,
		Absent: inventory.absent,
	}
}

// readApplyInventory 读取的必须是**目标节点本地**清单。缺少清单表示首次安装，
// 是合法的空 inventory；清单存在但读不出、JSON 坏了或 node 对不上则失败
// 关闭，不能在不知道 installed 集合时假装 apply 成功。
func readApplyInventory(node, sshConf string, isLocal bool, timeout time.Duration, manifestPath string) (applyInventory, error) {
	var body []byte
	if isLocal {
		b, err := os.ReadFile(manifestPath)
		if os.IsNotExist(err) {
			return applyInventory{absent: true}, nil
		}
		if err != nil {
			return applyInventory{}, err
		}
		body = b
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		quoted := quoteRemotePath(manifestPath)
		remote := "if [ ! -e " + quoted + " ]; then exit 44; fi; cat " + quoted
		cmd := exec.CommandContext(ctx, "ssh", "-F", sshConf, "-o", "BatchMode=yes",
			"-o", "ConnectTimeout=15", node, remote)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 44 {
				return applyInventory{absent: true}, nil
			}
			if ctx.Err() != nil {
				return applyInventory{}, fmt.Errorf("超过 %s 未读到 %s", timeout, manifestPath)
			}
			return applyInventory{}, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
		body = b
	}
	return parseApplyInventory(node, manifestPath, body)
}

func parseApplyInventory(node, manifestPath string, body []byte) (applyInventory, error) {
	var manifest report.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return applyInventory{}, fmt.Errorf("解析 %s:%w", manifestPath, err)
	}
	if manifest.Node != node {
		return applyInventory{}, fmt.Errorf("%s 属于节点 %s,不是 %s", manifestPath, manifest.Node, node)
	}
	files := make([]string, 0, len(manifest.Files))
	for abs := range manifest.Files {
		if !managedInstallPath(abs) {
			return applyInventory{}, fmt.Errorf("%s 含越界或非规范安装路径 %q", manifestPath, abs)
		}
		files = append(files, abs)
	}
	sort.Strings(files)
	sum := sha256.Sum256(body)
	return applyInventory{files: files, sha256: hex.EncodeToString(sum[:])}, nil
}

func managedInstallPath(abs string) bool {
	if !filepath.IsAbs(abs) || filepath.Clean(abs) != abs || !safeDeployPathAlphabet(abs) {
		return false
	}
	for _, mapping := range render.InstallRoots() {
		if strings.HasPrefix(abs, mapping[1]) && len(abs) > len(mapping[1]) {
			return true
		}
	}
	return false
}

func quoteRemotePath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'"'"'`) + "'"
}

// validateHydratedBundle 把 hydrate 写出的 manifest 当成文件清单，而不是
// 一张“有就参考一下”的表：除 manifest 自身（哈希不能自指）外，bundle
// 与清单必须一一对应，内容哈希也必须逐个相等。
func validateHydratedBundle(node string, files map[string]string) error {
	manifestBody, ok := files[manifestBundlePath]
	if !ok {
		return fmt.Errorf("缺少 %s", manifestBundlePath)
	}
	var manifest report.Manifest
	dec := json.NewDecoder(strings.NewReader(manifestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return fmt.Errorf("解析 %s:%w", manifestBundlePath, err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return fmt.Errorf("解析 %s:%w", manifestBundlePath, err)
	}
	if manifest.Node != node {
		return fmt.Errorf("%s 声明节点 %q，不是目录节点 %q", manifestBundlePath, manifest.Node, node)
	}
	if manifest.Files == nil {
		return fmt.Errorf("%s 缺少 files 清单", manifestBundlePath)
	}
	for abs, want := range manifest.Files {
		if !managedInstallPath(abs) {
			return fmt.Errorf("manifest 含越界或非规范安装路径 %q", abs)
		}
		if !validHexSHA256(want) {
			return fmt.Errorf("manifest 中 %s 的 sha256 %q 无效", abs, want)
		}
	}

	seen := make(map[string]string, len(manifest.Files))
	for bundlePath, content := range files {
		if bundlePath == manifestBundlePath {
			continue
		}
		if !validBundlePath(bundlePath) {
			return fmt.Errorf("含越界或非规范 bundle 路径 %q", bundlePath)
		}
		abs := render.InstallPath(bundlePath)
		if abs == "" || !managedInstallPath(abs) {
			return fmt.Errorf("%s 没有安全的安装位置，不在 manifest 可表达集合内", bundlePath)
		}
		if previous, duplicate := seen[abs]; duplicate {
			return fmt.Errorf("%s 与 %s 映射到同一安装路径 %s", previous, bundlePath, abs)
		}
		want, declared := manifest.Files[abs]
		if !declared {
			return fmt.Errorf("bundle 多出 manifest 未声明的文件 %s(%s)", bundlePath, abs)
		}
		if !validHexSHA256(want) {
			return fmt.Errorf("manifest 中 %s 的 sha256 %q 无效", abs, want)
		}
		sum := sha256.Sum256([]byte(content))
		got := hex.EncodeToString(sum[:])
		if got != want {
			return fmt.Errorf("%s 内容哈希不符(manifest %s，实际 %s)", bundlePath, want, got)
		}
		seen[abs] = bundlePath
	}

	var missing []string
	for abs := range manifest.Files {
		if _, ok := seen[abs]; !ok {
			missing = append(missing, abs)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("bundle 缺少 manifest 声明的文件:%s", strings.Join(missing, " "))
	}
	return nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("JSON 后还有第二个值")
	}
	return err
}

func validBundlePath(p string) bool {
	return p != "" && !path.IsAbs(p) && path.Clean(p) == p && path.Clean(p) != "." &&
		path.Clean(p) != ".." && !strings.HasPrefix(p, "../") &&
		safeDeployPathAlphabet(p)
}

// deploy 脚本的路径最终会进入 shell 和用 | 分隔的回滚清单。
// 即使所有命令都做了 shell quote，这个磁盘协议也不该接受
// 需要转义的路径。现有 render 只生成这个字符集。
func safeDeployPathAlphabet(p string) bool {
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '.', r == '_', r == '-', r == '@':
		default:
			return false
		}
	}
	return true
}

func validHexSHA256(s string) bool {
	if len(s) != sha256.Size*2 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func nodeNote(only string) string {
	if only == "" {
		return ""
	}
	return " " + only + " 的"
}

// runScript 把脚本交给节点执行。脚本从 stdin 进 sh,不落盘 —— 它内嵌了
// 配置内容,其中含秘密。
func runScript(node, script, sshConf string, isLocal bool, timeout time.Duration) error {
	return runScriptWithGrace(node, script, sshConf, isLocal, timeout, 5*time.Second)
}

func runScriptWithGrace(node, script, sshConf string, isLocal bool, timeout, grace time.Duration) error {
	var cmd *exec.Cmd
	if isLocal {
		cmd = exec.Command("sh", "-s")
	} else {
		cmd = exec.Command("ssh", "-F", sshConf, "-o", "BatchMode=yes",
			"-o", fmt.Sprintf("ConnectTimeout=%d", 15), node, "sh -s")
	}
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	// 独立进程组让 TERM/KILL 同时到达 sh 与它正在等待的 systemctl/sleep；
	// 只杀最外层 ssh/sh 会把孙进程留在后台继续改配置。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { done <- cmd.Wait() }()

	printOutput := func() {
		for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "Warning:") {
				fmt.Printf("   %s\n", strings.TrimSpace(line))
			}
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		printOutput()
		return err
	case <-timer.C:
		// 先 TERM，生成脚本会把它转成非零 EXIT，给 active 事务一次完整恢复
		// 的机会。只有超过短 grace 才 KILL；无论哪条都 Wait，避免僵尸和
		// bytes.Buffer 与仍在写输出的 goroutine 竞态。
		_ = signalProcessGroup(cmd, syscall.SIGTERM)
		graceTimer := time.NewTimer(grace)
		defer graceTimer.Stop()
		select {
		case err := <-done:
			printOutput()
			if exitCode(err) == deploy.RollbackIncompleteExitCode {
				return fmt.Errorf("超过 %s；终止后回滚不完整，active 标记与材料已保留", timeout)
			}
			return fmt.Errorf("超过 %s；已请求终止，脚本退出:%v", timeout, err)
		case <-graceTimer.C:
			_ = signalProcessGroup(cmd, syscall.SIGKILL)
			<-done
			printOutput()
			return fmt.Errorf("超过 %s；TERM 后 %s 仍未退出，已强制终止。不能确认已回滚；若已进入 active，下一次持锁部署会先恢复", timeout, grace)
		}
	}
}

func signalProcessGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, sig); err != nil {
		return cmd.Process.Signal(sig)
	}
	return nil
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 0
}

// readBundles 读回 hydrate 的输出:<目录>/<节点>/<包内路径>。
func readBundles(root string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			return nil, fmt.Errorf("hydrate 根目录含非节点目录 %q", e.Name())
		}
		node := e.Name()
		if !model.ValidNodeID(node) {
			return nil, fmt.Errorf("hydrate 根目录含非法节点目录 %q", node)
		}
		files := map[string]string{}
		if err := walkInto(root+"/"+node, "", files); err != nil {
			return nil, err
		}
		if len(files) > 0 {
			out[node] = files
		}
	}
	return out, nil
}

func walkInto(dir, prefix string, into map[string]string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("hydrate bundle 含符号链接 %s%s", prefix, e.Name())
		}
		if e.IsDir() {
			if err := walkInto(dir+"/"+e.Name(), prefix+e.Name()+"/", into); err != nil {
				return err
			}
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("hydrate bundle 含非普通文件 %s%s", prefix, e.Name())
		}
		b, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			return err
		}
		into[prefix+e.Name()] = string(b)
	}
	return nil
}
