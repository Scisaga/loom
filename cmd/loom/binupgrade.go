package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"loom/internal/snapshot"
)

// upgradeBinary 按签名过的 manifest 把本机的 Agent 二进制换成配套的那个(§15.4)。
//
// **顺序是先二进制、后配置。** 配对失败的方向不对称:新版通常读得懂旧配置,
// 旧版读不懂新配置 —— 发布器就是这么崩过一次的(旧二进制遇到新增字段,
// 直接拒绝发布)。先换二进制,这一步之后无论配置新旧都能读。
//
// binaryUpgradeCandidate 在 deploy.lock 外完成不可信网络读取、哈希和自检；
// staged 与 binPath 在同一目录，锁内可用 rename 原子激活。
type binaryUpgradeCandidate struct {
	want   snapshot.BinaryRef
	staged string
}

func (c *binaryUpgradeCandidate) cleanup() {
	if c != nil && c.staged != "" {
		_ = os.Remove(c.staged)
	}
}

func prepareBinaryUpgrade(c *http.Client, base string, man *snapshot.Manifest, binPath string, dry bool) (*binaryUpgradeCandidate, error) {
	var want *snapshot.BinaryRef
	for i := range man.Binaries {
		if man.Binaries[i].OS == runtime.GOOS && man.Binaries[i].Arch == runtime.GOARCH {
			want = &man.Binaries[i]
		}
	}
	if want == nil {
		// 快照没带这个平台的二进制。不是错误 —— 只是这次不管二进制。
		return nil, nil
	}
	candidate := &binaryUpgradeCandidate{want: *want}

	have, err := fileSum(binPath)
	if err != nil {
		return nil, fmt.Errorf("算不出本机二进制的哈希:%w", err)
	}
	if have == want.SHA256 {
		return candidate, nil
	}
	fmt.Printf("  二进制要换:%s → %s(%.1f MB)\n", short(have), short(want.SHA256), float64(want.Size)/(1<<20))
	if dry {
		return candidate, nil
	}

	// 二进制走 getBlob,不走 getBytes —— 后者那个 60 秒总超时装不下 12 MB。
	body, err := getBlob(c, base+"/"+want.Path(), int64(want.Size)+1<<20, blobStall)
	if err != nil {
		return nil, fmt.Errorf("下载二进制:%w", err)
	}
	// 内容寻址,但仍然自己算一遍 —— 路径由 manifest 给出,而 manifest 已经
	// 验过签;这一步确认下下来的字节确实是那个哈希,而不是被截断的。
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != want.SHA256 {
		return nil, fmt.Errorf("下载的二进制哈希对不上(签名说 %s,实际 %s)", short(want.SHA256), short(got))
	}
	if len(body) != want.Size {
		return nil, fmt.Errorf("下载的二进制大小对不上(%d vs %d)", len(body), want.Size)
	}

	// 冒烟测试:用同目录唯一临时文件，不能让并发预取互相覆盖固定 .new。
	// **一个跑不起来的二进制装上去,
	// 这台机器就再也拉不到修复了** —— 那是最糟的失败模式。
	f, err := os.CreateTemp(filepath.Dir(binPath), ".loom-binary-candidate-*")
	if err != nil {
		return nil, err
	}
	stage := f.Name()
	keep := false
	defer func() {
		_ = f.Close()
		if !keep {
			_ = os.Remove(stage)
		}
	}()
	if err := f.Chmod(0o755); err != nil {
		return nil, err
	}
	if _, err := f.Write(body); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	out, err := exec.Command(stage, "selfcheck").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("新二进制没通过自检,不安装:%w\n%s", err, strings.TrimSpace(string(out)))
	}
	candidate.staged = stage
	keep = true
	return candidate, nil
}

// requireSignedCurrentBinary prevents a signed-current-aware node from
// activating (or continuing to run) a binary that can no longer enforce its
// release floor. Prefer the staged candidate because that is the code about to
// take over; when no replacement is staged, the installed binary is the one
// that must prove it.
func requireSignedCurrentBinary(candidate *binaryUpgradeCandidate, binPath string) error {
	path := binPath
	if candidate != nil && candidate.staged != "" {
		path = candidate.staged
	}
	if path == "" {
		return fmt.Errorf("没有可检查 capability %s 的 Agent 二进制", signedCurrentCapability)
	}
	out, err := selfcheckBinaryCandidate(path, true)
	if err != nil {
		return fmt.Errorf("Agent 二进制 %s 不具备必须的 capability %s:%w\n%s",
			path, signedCurrentCapability, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// activateBinary 只做本机 mutation，调用方必须持有 deploy.lock。
func activateBinary(candidate *binaryUpgradeCandidate, binPath string, dry bool) (bool, error) {
	if candidate == nil {
		return false, nil
	}
	want := &candidate.want
	have, err := fileSum(binPath)
	if err != nil {
		return false, fmt.Errorf("持锁重读本机二进制:%w", err)
	}
	if have == want.SHA256 {
		stale, err := staleUnits(binPath)
		if err != nil {
			return false, err
		}
		if len(stale) == 0 || dry {
			return false, nil
		}
		fmt.Printf("  %s 还跑着旧二进制,重启并复核\n", strings.Join(stale, " "))
		if err := restartBinaryUnits(binPath, stale); err != nil {
			return false, fmt.Errorf("磁盘二进制已是目标版本，但旧进程收敛失败:%w", err)
		}
		return false, nil
	}
	if dry {
		return true, nil
	}
	if candidate.staged == "" {
		return false, fmt.Errorf("等待部署锁期间二进制从目标版本变成 %s；没有可激活候选，留给下一轮重试", short(have))
	}
	got, err := fileSum(candidate.staged)
	if err != nil {
		return false, fmt.Errorf("锁外自检后的二进制候选无法复核:%w", err)
	}
	if got != want.SHA256 {
		return false, fmt.Errorf("锁外自检后的二进制候选发生变化(hash=%s, want=%s)", short(got), short(want.SHA256))
	}
	st, err := os.Stat(candidate.staged)
	if err != nil {
		return false, fmt.Errorf("读取二进制候选大小:%w", err)
	}
	if st.Size() != int64(want.Size) {
		return false, fmt.Errorf("二进制候选大小在激活前变化(%d vs %d)", st.Size(), want.Size)
	}

	// 留一份旧的。后面任何一个服务起不来就换回去。
	prev := binPath + ".prev"
	old, err := os.ReadFile(binPath)
	if err != nil {
		return false, fmt.Errorf("保存升级前二进制:%w", err)
	}
	// 不能先删旧 .prev 再直写:此时被 kill 会把唯一回退入口留成半个
	// 文件。先完整写同目录临时文件,最后 rename 覆盖。
	if err := writeFileAtomicDurable(prev, old, 0o755); err != nil {
		return false, fmt.Errorf("持久化升级前二进制:%w", err)
	}
	// install 会 unlink 再建,所以正在跑的进程不受影响 —— 它们继续用旧的
	// inode,直到各自重启。
	if err := os.Rename(candidate.staged, binPath); err != nil {
		return false, err
	}
	candidate.staged = ""
	if err := syncDirectory(filepath.Dir(binPath)); err != nil {
		return false, fmt.Errorf("持久化新二进制目录项:%w", err)
	}

	// 常驻服务要重启才会用上新二进制。**不重启 loom-pull** —— 那是正在
	// 跑的这个,重启它等于在一次升级里再套一次升级。
	units := []string{"loom-report", "loom-agent", "loom-publisher"}
	if restartErr := restartBinaryUnits(binPath, units); restartErr != nil {
		fmt.Printf("  !! 换二进制之后服务未收敛,换回旧版\n")
		if restoreErr := restorePreviousBinary(binPath); restoreErr != nil {
			return false, fmt.Errorf("新二进制服务验证失败(%v)，而且恢复旧版失败:%w", restartErr, restoreErr)
		}
		return false, fmt.Errorf("新二进制服务验证失败，已换回旧版:%w", restartErr)
	}
	fmt.Printf("  ✅ 二进制已换,相关常驻服务已重启并复核进程 inode\n")
	return true, nil
}

// upgradeBinary 保留为组合入口供单元调用；pull 主路径显式拆成 prepare /
// activate，确保不可信网络不会占着 deploy.lock。
func upgradeBinary(c *http.Client, base string, man *snapshot.Manifest, binPath string, dry bool) (bool, error) {
	candidate, err := prepareBinaryUpgrade(c, base, man, binPath, dry)
	if err != nil {
		return false, err
	}
	defer candidate.cleanup()
	return activateBinary(candidate, binPath, dry)
}

// restorePreviousBinary 把 upgradeBinary 留下的 .prev 原子换回去,并让所有
// 常驻服务重新打开它。applied 状态没有在二进制阶段提前更新,所以下一个
// timer 仍会看到 manifest 的目标哈希不同并重试 —— 回退不会堵死自修复入口。
func restorePreviousBinary(binPath string) error {
	if err := restorePreviousFile(binPath); err != nil {
		return err
	}
	if err := restartBinaryUnits(binPath, managedBinaryUnits); err != nil {
		return fmt.Errorf("旧二进制已恢复,但服务未重新收敛:%w", err)
	}
	return nil
}

func restorePreviousFile(binPath string) error {
	prev := binPath + ".prev"
	st, err := os.Stat(prev)
	if err != nil {
		return fmt.Errorf("找不到可回退的 %s:%w", prev, err)
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return fmt.Errorf("可回退的 %s 不是非空普通文件", prev)
	}
	if err := os.Rename(prev, binPath); err != nil {
		return fmt.Errorf("恢复 %s → %s:%w", prev, binPath, err)
	}
	if err := syncDirectory(filepath.Dir(binPath)); err != nil {
		return fmt.Errorf("恢复后持久化目录项:%w", err)
	}
	return nil
}

func fileSum(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

var managedBinaryUnits = []string{"loom-report", "loom-agent", "loom-publisher"}

type binarySystemctl func(args ...string) (string, error)

func runBinarySystemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func unitExistsStrict(u string, ctl binarySystemctl) (bool, error) {
	unitFile := u
	if !strings.Contains(filepath.Base(unitFile), ".") {
		unitFile += ".service"
	}
	// unit file 不是 systemd 仍在管理这个进程的唯一证据。文件被人工删掉后，
	// 已 loaded/active 的 unit 及其旧 inode 进程仍可能继续存在；只看
	// list-unit-files 会把它当成“不存在”，让二进制升级假绿。两份集合都要
	// 成功读到，再取并集；任何一份查询不确定都失败关闭。
	loadedOut, err := ctl("list-units", "--all", "--plain", "--no-legend", "--no-pager", unitFile)
	if err != nil {
		return false, fmt.Errorf("查询 %s 是否 loaded:%w(%s)", unitFile, err, loadedOut)
	}
	loaded, err := listingContainsExactUnit(loadedOut, unitFile, "list-units")
	if err != nil {
		return false, err
	}
	installedOut, err := ctl("list-unit-files", "--no-legend", "--no-pager", unitFile)
	if err != nil {
		return false, fmt.Errorf("查询 %s 是否安装:%w(%s)", unitFile, err, installedOut)
	}
	installed, err := listingContainsExactUnit(installedOut, unitFile, "list-unit-files")
	if err != nil {
		return false, err
	}
	return loaded || installed, nil
}

func listingContainsExactUnit(out, unitFile, source string) (bool, error) {
	found := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] != unitFile {
			return false, fmt.Errorf("%s 查询 %s 返回意外单元 %q", source, unitFile, fields[0])
		}
		found = true
	}
	return found, nil
}

func activeStateStrict(u string, ctl binarySystemctl) (string, error) {
	out, err := ctl("is-active", u)
	switch out {
	case "active":
		if err != nil {
			return "", fmt.Errorf("%s 报 active 但查询失败:%w", u, err)
		}
		return out, nil
	case "inactive", "failed", "activating", "deactivating", "reloading":
		// systemctl 对非 active 状态按约定返回非零；状态文本才是这里需要的值。
		return out, nil
	default:
		return "", fmt.Errorf("无法确认 %s 的 active 状态(%q):%w", u, out, err)
	}
}

func mainPIDStrict(u string, ctl binarySystemctl) (int, error) {
	out, err := ctl("show", "-p", "MainPID", "--value", u)
	if err != nil {
		return 0, fmt.Errorf("查询 %s MainPID:%w(%s)", u, err, out)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("%s active 但 MainPID=%q", u, out)
	}
	return pid, nil
}

func processUsesBinary(binPath, procRoot string, pid int) (bool, error) {
	live, err := os.Stat(binPath)
	if err != nil {
		return false, fmt.Errorf("stat 当前二进制:%w", err)
	}
	exePath := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
	running, err := os.Stat(exePath)
	if err != nil {
		return false, fmt.Errorf("stat %s:%w", exePath, err)
	}
	return os.SameFile(live, running), nil
}

// staleUnits 找出"跑着的二进制已经不是磁盘上那个"的服务。
//
// 判据是 /proc/<pid>/exe 与磁盘目标的 inode 是否相同：替换文件时旧进程
// 仍持有旧 inode，即使 is-active 还是 active 也不能算升级成功。这比只看
// 符号链接文本或进程状态可靠。
func staleUnits(binPath string) ([]string, error) {
	return staleUnitsWith(binPath, "/proc", managedBinaryUnits, runBinarySystemctl)
}

func staleUnitsWith(binPath, procRoot string, units []string, ctl binarySystemctl) ([]string, error) {
	var out []string
	for _, u := range units {
		exists, err := unitExistsStrict(u, ctl)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		state, err := activeStateStrict(u, ctl)
		if err != nil {
			return nil, err
		}
		switch state {
		case "inactive":
			continue
		case "active":
			pid, err := mainPIDStrict(u, ctl)
			if err != nil {
				return nil, err
			}
			matches, err := processUsesBinary(binPath, procRoot, pid)
			if err != nil {
				return nil, fmt.Errorf("复核 %s 运行镜像:%w", u, err)
			}
			if !matches {
				out = append(out, u)
			}
		default:
			return nil, fmt.Errorf("%s 当前是 %s，拒绝把二进制状态当作已收敛", u, state)
		}
	}
	return out, nil
}

func restartBinaryUnits(binPath string, units []string) error {
	return restartBinaryUnitsWith(binPath, "/proc", units, runBinarySystemctl, func() { time.Sleep(5 * time.Second) })
}

// restartBinaryUnitsWith 对所有可处理单元 best-effort 执行，再统一验证。单个
// restart 失败不能挡住其他进程切换；但任何命令错误、过渡态、非 active 或
// 仍指向旧 inode 都让整次升级失败关闭。
func restartBinaryUnitsWith(binPath, procRoot string, units []string, ctl binarySystemctl, wait func()) error {
	var failures []string
	var verify []string
	seen := map[string]bool{}
	for _, u := range units {
		if seen[u] {
			continue
		}
		seen[u] = true
		exists, err := unitExistsStrict(u, ctl)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if !exists {
			continue
		}
		state, err := activeStateStrict(u, ctl)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		switch state {
		case "inactive":
			// 不把原本没运行的可选服务意外启动；它下次 start 会自然使用新文件。
			continue
		case "active", "failed":
			verify = append(verify, u)
			if out, err := ctl("restart", u); err != nil {
				failures = append(failures, fmt.Sprintf("restart %s:%v(%s)", u, err, out))
			}
		default:
			failures = append(failures, fmt.Sprintf("%s 正处于 %s，拒绝竞态重启", u, state))
		}
	}
	if len(verify) > 0 {
		wait()
	}
	for _, u := range verify {
		state, err := activeStateStrict(u, ctl)
		if err != nil || state != "active" {
			failures = append(failures, fmt.Sprintf("%s 重启后状态=%q err=%v", u, state, err))
			continue
		}
		pid, err := mainPIDStrict(u, ctl)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		matches, err := processUsesBinary(binPath, procRoot, pid)
		if err != nil || !matches {
			failures = append(failures, fmt.Sprintf("%s 重启后仍未运行磁盘上的目标二进制(err=%v)", u, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func writeFileAtomicDurable(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".loom-binary-backup-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// binarySHA 取快照里本平台那个二进制的 sha。没有就返回空串。
func binarySHA(man *snapshot.Manifest) string {
	for i := range man.Binaries {
		if man.Binaries[i].OS == runtime.GOOS && man.Binaries[i].Arch == runtime.GOARCH {
			return man.Binaries[i].SHA256
		}
	}
	return ""
}

// contEnv 标记"我是被续跑起来的子进程"。
//
// 防的是无限套娃:正常情况下子进程看到二进制哈希已经对上,不会再换,
// 于是深度天然是 1。但**"正常情况"是个假设**,而这个假设错了的话
// 代价是 fork 炸弹。所以显式挡一道。
const (
	contEnv         = "LOOM_PULL_CONTINUATION"
	contStatusEnv   = "LOOM_PULL_CONTINUATION_STATUS"
	contSnapshotEnv = "LOOM_PULL_CONTINUATION_SNAPSHOT"

	continuationProtocolVersion = 1
)

type continuationPhase string

const (
	// pre_config 只能由续跑子进程在初始化阶段写出。看到它说明子进程还
	// 没进入配置安装事务，父进程可以安全恢复旧二进制。
	continuationPreConfig continuationPhase = "pre_config"
	// configuring 在启动 deploy.Script **之前**原子写出。自此即使子进程
	// 被 kill，父进程也不能再假设配置已经回滚。
	continuationConfiguring continuationPhase = "configuring"
	// committed 表示 deploy.Script 已成功返回；后续 applied 写失败也不能
	// 把二进制退回去，否则会得到旧代码 + 新配置。
	continuationCommitted continuationPhase = "committed"
)

// continuationStatus 是新旧进程之间的结构化提交协议。错误文本会变，也会
// 被多层包装，不能拿字符串猜“配置装到哪一步了”。状态文件由父进程创建唯一
// 路径，子进程每次用同目录临时文件 + rename 单调推进。
type continuationStatus struct {
	Version  int               `json:"version"`
	Phase    continuationPhase `json:"phase"`
	Snapshot string            `json:"snapshot"`
}

type continuationReporter struct {
	path     string
	snapshot string
}

func continuationReporterFromEnv() (*continuationReporter, error) {
	if os.Getenv(contEnv) == "" {
		return nil, nil
	}
	path := os.Getenv(contStatusEnv)
	snapshot := os.Getenv(contSnapshotEnv)
	if path == "" || snapshot == "" {
		return nil, fmt.Errorf("续跑标记缺少结构化状态通道或目标快照，拒绝绕过 pull 锁")
	}
	r := &continuationReporter{path: path, snapshot: snapshot}
	if err := r.mark(continuationPreConfig); err != nil {
		return nil, fmt.Errorf("初始化续跑状态:%w", err)
	}
	return r, nil
}

func (r *continuationReporter) mark(phase continuationPhase) error {
	if r == nil {
		return nil
	}
	status := continuationStatus{
		Version: continuationProtocolVersion, Phase: phase, Snapshot: r.snapshot,
	}
	b, err := json.Marshal(&status)
	if err != nil {
		return err
	}
	// 不能原地截断状态文件：进程恰好在写 configuring 时被 kill，父进程
	// 若还读到旧的 pre_config 就会错误回退。先写 sibling，再 rename。
	tmp := r.path + ".next"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, r.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (r *continuationReporter) requireSnapshot(got string) error {
	if r == nil || got == r.snapshot {
		return nil
	}
	return fmt.Errorf("续跑期间分发点从快照 %s 变成 %s，拒绝把前一版二进制与后一版配置混装",
		short(r.snapshot), short(got))
}

func readContinuationStatus(path, snapshot string) (continuationStatus, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return continuationStatus{}, err
	}
	var status continuationStatus
	if err := json.Unmarshal(b, &status); err != nil {
		return continuationStatus{}, err
	}
	if status.Version != continuationProtocolVersion || status.Snapshot != snapshot {
		return continuationStatus{}, fmt.Errorf("续跑状态协议或快照不匹配(version=%d,snapshot=%q)",
			status.Version, status.Snapshot)
	}
	switch status.Phase {
	case continuationPreConfig, continuationConfiguring, continuationCommitted:
		return status, nil
	default:
		return continuationStatus{}, fmt.Errorf("未知续跑阶段 %q", status.Phase)
	}
}

// continuePull 用**刚装好的那个二进制**跑完这一轮剩下的活。
//
// # 为什么是子进程,不是 exec
//
// exec 把当前进程替换掉,而当前进程是唯一还知道"旧二进制在 .prev、
// 出事了怎么退回去"的东西。子进程留住了这个能力,代价只是一个进程。
//
// 父进程在这里等着,不做别的 —— 它存在的意义就是看着子进程的结果。
func continuePull(binPath string, args []string, snapshot string, lock *nodeDeployLock) (continuationStatus, error) {
	if os.Getenv(contEnv) != "" {
		return continuationStatus{}, fmt.Errorf("续跑的子进程又要换二进制 —— 这不该发生,停下来免得套娃")
	}
	fmt.Printf("  用新二进制续跑同一个快照(不等下一轮)\n")

	// 文件只承载三个枚举阶段，不承载错误文字。空文件/坏 JSON/旧版子进程
	// 没实现协议都按 unknown 处理：unknown 永远不能授权回退。
	f, err := os.CreateTemp(filepath.Dir(binPath), ".loom-pull-continuation-*")
	if err != nil {
		return continuationStatus{}, fmt.Errorf("创建续跑状态通道:%w", err)
	}
	statusPath := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(statusPath)
		return continuationStatus{}, err
	}
	defer os.Remove(statusPath)
	defer os.Remove(statusPath + ".next")

	cmd := exec.Command(binPath, append([]string{"pull"}, args...)...)
	cmd.Env = append(os.Environ(),
		contEnv+"=1",
		contStatusEnv+"="+statusPath,
		contSnapshotEnv+"="+snapshot,
	)
	if _, err := lock.inheritTo(cmd); err != nil {
		return continuationStatus{
			Version: continuationProtocolVersion, Phase: continuationPreConfig, Snapshot: snapshot,
		}, fmt.Errorf("把部署锁交给续跑进程:%w", err)
	}
	cmd.Stdout, cmd.Stderr = prefixWriter{"  "}, prefixWriter{"  "}
	if err := cmd.Start(); err != nil {
		// 子进程根本没开始，配置当然尚未触碰；这是无需依赖协议就能证明的
		// 唯一失败路径。
		return continuationStatus{
			Version: continuationProtocolVersion, Phase: continuationPreConfig, Snapshot: snapshot,
		}, err
	}
	waitErr := cmd.Wait()
	status, statusErr := readContinuationStatus(statusPath, snapshot)
	if waitErr == nil {
		// 成功路径不需要回退判断。兼容还不认识本协议的历史二进制：只要它
		// 完整跑完，缺少阶段文件不把一次成功变成失败。
		return status, nil
	}
	if statusErr != nil {
		return continuationStatus{}, fmt.Errorf("%w；且续跑阶段不可确认:%v", waitErr, statusErr)
	}
	return status, waitErr
}

// handleContinuationFailure 只有拿到子进程的 pre_config 证明时才恢复旧版。
// configuring/committed/unknown 全部保留新二进制：新版读旧配置通常安全，
// 但旧版读新配置是本流程明确要禁止的组合。
func handleContinuationFailure(binPath string, status continuationStatus, cause error,
	restore func(string) error) error {
	canRestore := status.Version == continuationProtocolVersion &&
		status.Phase == continuationPreConfig && status.Snapshot != ""
	if !canRestore {
		phase := string(status.Phase)
		if phase == "" {
			phase = "unknown"
		}
		return fmt.Errorf("换完二进制之后续跑失败(阶段 %s)；配置可能已经开始或提交，"+
			"为避免旧二进制 + 新配置，保留新二进制并由下一轮继续收敛:%w", phase, cause)
	}
	if err := restore(binPath); err != nil {
		return fmt.Errorf("换完二进制之后续跑在配置提交前失败:%v；恢复旧版流程不完整:%w", cause, err)
	}
	return fmt.Errorf("换完二进制之后续跑在配置提交前失败，已恢复旧版、保留下一轮自修复入口:%w", cause)
}
