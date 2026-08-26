package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// runScript 真跑一遍生成出来的脚本,systemctl 用桩子顶掉。
//
// 现有测试全是对脚本**文本**的断言,而 trap 这类东西文本对了不代表行为
// 对 —— 只有真让一条命令失败,才知道回滚有没有发生。
//
// allowedTargetRoot 是这条测试唯一允许脚本修改的目标根。生成脚本之前会逐项
// 检查；staging/previous/lock 则无条件放在另一个 t.TempDir() 里。这里的
// 护栏是故意重复的：即使以后有人给测试计划塞进 /etc/...，也会在 shell
// 启动之前失败，而不是再次污染测试机。
func runScript(t *testing.T, p *Plan, stubExit int, allowedTargetRoot string) (string, error) {
	t.Helper()
	failOp := ""
	if stubExit != 0 {
		// 文件已经就位后的 daemon-reload 失败，能稳定覆盖 EXIT trap 回滚，
		// 同时不干扰 is-active/is-enabled 这两类状态查询。
		failOp = "daemon-reload"
	}
	r := executeScript(t, p, scriptRunOptions{
		allowedTargetRoot: allowedTargetRoot,
		failOperation:     failOp,
	})
	return r.output, r.err
}

type scriptRunOptions struct {
	allowedTargetRoot string
	targetRoot        string
	failOperation     string
	failUnit          string
	failOnce          bool
	failRemovePath    string
	beforeRun         func(scriptPaths)
	inactiveUnits     []string
	disabledUnits     []string
	enabledStates     map[string]string
	activeStates      map[string]string
	restartCounts     map[string]string
	loadConfig        map[string]string
	crashOnSleep      []string
	restartOnSleep    []string
}

type scriptRunResult struct {
	output    string
	err       error
	log       string
	paths     scriptPaths
	unitState string
}

func executeScript(t *testing.T, p *Plan, opts scriptRunOptions) scriptRunResult {
	t.Helper()
	stateRoot := t.TempDir()
	paths := scriptPaths{
		stageRoot:    filepath.Join(stateRoot, "staging"),
		previousRoot: filepath.Join(stateRoot, "previous"),
		lockPath:     filepath.Join(stateRoot, "deploy.lock"),
		targetRoot:   opts.targetRoot,
	}
	for _, statePath := range []string{paths.stageRoot, paths.previousRoot, paths.lockPath} {
		assertWithin(t, statePath, stateRoot)
	}
	for abs := range p.Files {
		assertWithin(t, paths.target(abs), opts.allowedTargetRoot)
	}
	for _, abs := range p.Remove {
		assertWithin(t, paths.target(abs), opts.allowedTargetRoot)
	}
	for _, abs := range p.InvalidateOnChange {
		assertWithin(t, paths.target(abs), opts.allowedTargetRoot)
	}
	if p.InventoryGuard != nil {
		assertWithin(t, paths.target(p.InventoryGuard.Path), opts.allowedTargetRoot)
	}
	if opts.beforeRun != nil {
		opts.beforeRun(paths)
	}

	bin := t.TempDir()
	logPath := filepath.Join(stateRoot, "systemctl.log")
	unitState := filepath.Join(stateRoot, "systemctl-state")
	if err := os.MkdirAll(unitState, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, unit := range opts.inactiveUnits {
		if err := os.WriteFile(unitStatePath(unitState, unit, "inactive"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, unit := range opts.disabledUnits {
		if err := os.WriteFile(unitStatePath(unitState, unit, "disabled"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for unit, state := range opts.enabledStates {
		if err := os.WriteFile(unitStatePath(unitState, unit, "enabled-state"), []byte(state+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for unit, state := range opts.activeStates {
		if err := os.WriteFile(unitStatePath(unitState, unit, "active-state"), []byte(state+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for unit, count := range opts.restartCounts {
		if err := os.WriteFile(unitStatePath(unitState, unit, "restarts"), []byte(count+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	loadMap := filepath.Join(stateRoot, "load-config")
	var loadLines []string
	for unit, path := range opts.loadConfig {
		loadLines = append(loadLines, unit+"|"+path)
	}
	if err := os.WriteFile(loadMap, []byte(strings.Join(loadLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := `#!/bin/sh
set -eu
op=$1
shift || true
unit=
now=0
for arg in "$@"; do
  case "$arg" in
    --now) now=1 ;;
    -*) ;;
    *) unit=$arg ;;
  esac
done
printf '%s|%s\n' "$op" "$unit" >> "$LOOM_SYSTEMCTL_LOG"
key=$(printf '%s' "$unit" | tr '/ ' '__')
inactive="$LOOM_SYSTEMCTL_STATE/$key.inactive"
disabled="$LOOM_SYSTEMCTL_STATE/$key.disabled"
enabled_state="$LOOM_SYSTEMCTL_STATE/$key.enabled-state"
active_state="$LOOM_SYSTEMCTL_STATE/$key.active-state"
restarts="$LOOM_SYSTEMCTL_STATE/$key.restarts"
failed_once="$LOOM_SYSTEMCTL_STATE/fail-once"
if [ -n "${LOOM_SYSTEMCTL_FAIL_OP:-}" ] && [ "$op" = "$LOOM_SYSTEMCTL_FAIL_OP" ] &&
   { [ -z "${LOOM_SYSTEMCTL_FAIL_UNIT:-}" ] || [ "$unit" = "$LOOM_SYSTEMCTL_FAIL_UNIT" ]; }; then
  if [ "${LOOM_SYSTEMCTL_FAIL_ONCE:-0}" = 0 ] || [ ! -e "$failed_once" ]; then
    : > "$failed_once"
    exit 1
  fi
fi
case "$op" in
  is-active)
    if [ -e "$active_state" ]; then cat "$active_state"; [ "$(cat "$active_state")" = active ]; exit $?; fi
    if [ -e "$inactive" ]; then echo inactive; exit 3; fi
    echo active ;;
  is-enabled)
    if [ -e "$enabled_state" ]; then cat "$enabled_state"; [ "$(cat "$enabled_state")" = enabled ]; exit $?; fi
    if [ -e "$disabled" ]; then echo disabled; exit 1; fi
    echo enabled ;;
  show) if [ -e "$restarts" ]; then cat "$restarts"; else echo 0; fi ;;
  stop) : > "$inactive"; printf 'inactive\n' > "$active_state" ;;
  start|restart)
    rm -f "$inactive"; printf 'active\n' > "$active_state"
    while IFS='|' read -r load_unit load_path; do
      if [ "$load_unit" = "$unit" ]; then cp "$load_path" "$LOOM_SYSTEMCTL_STATE/$key.loaded"; fi
    done < "$LOOM_SYSTEMCTL_LOAD_MAP" ;;
  disable)
    : > "$disabled"
    printf 'disabled\n' > "$enabled_state"
    [ "$now" = 0 ] || : > "$inactive" ;;
  enable)
    rm -f "$disabled"
    if printf '%s\n' "$*" | grep -q -- --runtime; then printf 'enabled-runtime\n' > "$enabled_state"; else printf 'enabled\n' > "$enabled_state"; fi
    [ "$now" = 0 ] || rm -f "$inactive" ;;
  daemon-reload|reset-failed) ;;
  *) echo "unexpected systemctl operation:$op" >&2; exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	sleepStub := `#!/bin/sh
for unit in $LOOM_CRASH_ON_SLEEP; do
  key=$(printf '%s' "$unit" | tr '/ ' '__')
  printf 'failed\n' > "$LOOM_SYSTEMCTL_STATE/$key.active-state"
done
for unit in $LOOM_RESTART_ON_SLEEP; do
  key=$(printf '%s' "$unit" | tr '/ ' '__')
  restarts="$LOOM_SYSTEMCTL_STATE/$key.restarts"
  count=0
  [ ! -e "$restarts" ] || count=$(cat "$restarts")
  printf '%s\n' "$((count + 1))" > "$restarts"
done
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "sleep"), []byte(sleepStub), 0o755); err != nil {
		t.Fatal(err)
	}
	if opts.failRemovePath != "" {
		rmStub := "#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = \"$LOOM_RM_FAIL_PATH\" ] && exit 1; done\nexec /usr/bin/rm \"$@\"\n"
		if err := os.WriteFile(filepath.Join(bin, "rm"), []byte(rmStub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script(p, "test-run", paths))
	cmd.Env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"),
		"LOOM_SYSTEMCTL_LOG="+logPath,
		"LOOM_SYSTEMCTL_STATE="+unitState,
		"LOOM_SYSTEMCTL_FAIL_OP="+opts.failOperation,
		"LOOM_SYSTEMCTL_FAIL_UNIT="+opts.failUnit,
		"LOOM_SYSTEMCTL_FAIL_ONCE="+map[bool]string{false: "0", true: "1"}[opts.failOnce],
		"LOOM_SYSTEMCTL_LOAD_MAP="+loadMap,
		"LOOM_RM_FAIL_PATH="+opts.failRemovePath,
		"LOOM_CRASH_ON_SLEEP="+strings.Join(opts.crashOnSleep, " "),
		"LOOM_RESTART_ON_SLEEP="+strings.Join(opts.restartOnSleep, " "),
	)
	out, err := cmd.CombinedOutput()
	log, _ := os.ReadFile(logPath)
	return scriptRunResult{output: string(out), err: err, log: string(log), paths: paths, unitState: unitState}
}

func unitStatePath(root, unit, state string) string {
	key := strings.NewReplacer("/", "_", " ", "_").Replace(unit)
	return filepath.Join(root, key+"."+state)
}

func assertWithin(t *testing.T, path, root string) {
	t.Helper()
	if root == "" {
		t.Fatalf("测试没有声明允许修改的目标根，拒绝生成会触碰 %s 的脚本", path)
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		t.Fatalf("测试脚本路径越界：%s 不在 %s 内", path, root)
	}
}

// **本文件存在的主要理由。**
//
// 脚本是 set -eu 的,install / daemon-reload / systemctl restart 失败时
// shell 立刻退出。以前只有验证阶段走 `|| fail`,所以这些路径上一失败就
// 停在装了一半的状态 —— 而回滚代码明明是有的,只是够不着。
func TestRollbackHappensWhenSystemctlFails(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(tgt, []byte("旧内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{tgt: "新内容\n"},
		Triggers: map[string][]string{tgt: {"app.service"}},
	}
	out, err := runScript(t, p, 1, dir)
	if err == nil {
		t.Fatalf("systemctl 失败了,脚本应该非零退出:\n%s", out)
	}
	got, _ := os.ReadFile(tgt)
	if string(got) != "旧内容\n" {
		t.Fatalf("没回滚 —— 文件是 %q,应该被还原成\"旧内容\"\n%s", got, out)
	}
	if !strings.Contains(out, "回滚") {
		t.Errorf("回滚要说出来,输出里没有:\n%s", out)
	}
}

// 成功时不能回滚 —— trap 撤得干净不干净,只有这条能验。
func TestNoRollbackOnSuccess(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(tgt, []byte("旧内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{tgt: "新内容\n"},
		Triggers: map[string][]string{tgt: {"app.service"}},
		Verify:   []string{"app.service"},
	}
	out, err := runScript(t, p, 0, dir)
	if err != nil {
		t.Fatalf("一切正常时不该失败:%v\n%s", err, out)
	}
	got, _ := os.ReadFile(tgt)
	if string(got) != "新内容\n" {
		t.Fatalf("成功了却没装上,文件是 %q\n%s", got, out)
	}
	if strings.Contains(out, "回滚中") {
		t.Errorf("成功时不该回滚 —— trap 没撤干净:\n%s", out)
	}
}

// 什么都没变时不该扰动任何东西,也不该触发回滚。
func TestUnchangedIsAQuietNoop(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(tgt, []byte("一样的内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{tgt: "一样的内容\n"},
		Triggers: map[string][]string{tgt: {"app.service"}},
	}
	out, err := runScript(t, p, 1, dir) // daemon-reload 会失败,但根本不该被调到
	if err != nil {
		t.Fatalf("无变化时不该走到任何 systemctl:%v\n%s", err, out)
	}
	if !strings.Contains(out, "无变化") {
		t.Errorf("应报告无变化:\n%s", out)
	}
	if strings.Contains(out, "回滚中") {
		t.Errorf("无变化时回滚是错的:\n%s", out)
	}
}

// 不再声明的文件要被真的删掉 —— 而且**先停服务再删文件**。
//
// SSOT 里删掉一条隧道之后,渲染输出里就没那个 conf 了,但节点上的文件和
// wg-quick@ 服务都还在跑。以为删了、实际还连着,这是安全问题。
func TestStaleFileIsRemovedAndItsUnitStopped(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep.conf")
	stale := filepath.Join(dir, "stale.conf")
	for _, f := range []string{keep, stale} {
		if err := os.WriteFile(f, []byte("内容\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{keep: "新内容\n"},
		Triggers: map[string][]string{keep: {"app.service"}},
		Remove:   []string{stale},
	}
	out, err := runScript(t, p, 0, dir)
	if err != nil {
		t.Fatalf("不该失败:%v\n%s", err, out)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("不再声明的文件应被删掉,它还在:\n%s", out)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("仍在声明里的文件不该被碰:%v", err)
	}
}

// 删除是一种变更:只有删除、没有文件改动时,也不能走"无变化"早退。
func TestRemovalAloneCountsAsAChange(t *testing.T) {
	dir := t.TempDir()
	same := filepath.Join(dir, "same.conf")
	stale := filepath.Join(dir, "stale.conf")
	if err := os.WriteFile(same, []byte("一样\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("要删\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:   "n1",
		Files:  map[string]string{same: "一样\n"}, // 内容没变
		Remove: []string{stale},
	}
	out, err := runScript(t, p, 0, dir)
	if err != nil {
		t.Fatalf("不该失败:%v\n%s", err, out)
	}
	if strings.Contains(out, "无变化") {
		t.Errorf("有东西要删就不算无变化:\n%s", out)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("该删的没删:\n%s", out)
	}
}

// **删除也要能回滚。** 删完之后验证失败的话,文件必须放回去 ——
// 否则一次失败的部署会永久毁掉一条还在用的隧道配置。
func TestRemovalIsRolledBackOnFailure(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	stale := filepath.Join(dir, "stale.conf")
	if err := os.WriteFile(tgt, []byte("旧内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("被删的内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{tgt: "新内容\n"},
		Triggers: map[string][]string{tgt: {"app.service"}},
		Remove:   []string{stale},
	}
	out, err := runScript(t, p, 1, dir)
	if err == nil {
		t.Fatalf("应该失败:\n%s", out)
	}
	got, rerr := os.ReadFile(stale)
	if rerr != nil {
		t.Fatalf("回滚应把删掉的文件放回来,它不在了:%v\n%s", rerr, out)
	}
	if string(got) != "被删的内容\n" {
		t.Errorf("放回来的内容不对:%q", got)
	}
}

// 没有 Remove 时脚本里不该出现清理段 —— 免得每次部署都 daemon-reload。
func TestNoRemovalSectionWhenNothingToRemove(t *testing.T) {
	p := &Plan{Node: "n1", Files: map[string]string{"/tmp/x": "y"}}
	if strings.Contains(Script(p, "r"), "清掉不再声明的东西") {
		t.Error("没东西要删时不该生成清理段")
	}
}

// 上一轮成功后遗留的 .manifest 不能被下一轮的**暂存或预检失败**拿来用。
// 这条回归测试故意在 previous 里伪造一份旧事务；新事务还没碰线上文件就
// 失败，健康目标必须原封不动。
func TestStaleManifestCannotRollbackPrecheckFailure(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(tgt, []byte("当前健康内容\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:     "n1",
		Files:    map[string]string{tgt: "尚未通过预检的新内容\n"},
		PreCheck: []string{"false"},
	}
	r := executeScript(t, p, scriptRunOptions{
		allowedTargetRoot: dir,
		beforeRun: func(paths scriptPaths) {
			if err := os.MkdirAll(paths.previousRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(paths.previousRoot, "d000"), []byte("上一轮的旧内容\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			line := tgt + "|d000\n"
			if err := os.WriteFile(filepath.Join(paths.previousRoot, ".manifest"), []byte(line), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	})
	if r.err == nil {
		t.Fatalf("预检失败应返回非零：\n%s", r.output)
	}
	got, err := os.ReadFile(tgt)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "当前健康内容\n" {
		t.Fatalf("预检失败错误使用上一轮 manifest 回滚了健康文件：%q\n%s", got, r.output)
	}
	if strings.Contains(r.output, "回滚中") {
		t.Fatalf("线上尚未修改时不应进入真实回滚：\n%s", r.output)
	}
	if _, err := os.Stat(r.paths.previousRoot); !os.IsNotExist(err) {
		t.Fatalf("失败后的事务元数据未清理：%v", err)
	}
}

func TestSuccessfulRunCleansTransactionMetadata(t *testing.T) {
	dir := t.TempDir()
	tgt := filepath.Join(dir, "app.conf")
	p := &Plan{Node: "n1", Files: map[string]string{tgt: "new\n"}}
	r := executeScript(t, p, scriptRunOptions{allowedTargetRoot: dir})
	if r.err != nil {
		t.Fatalf("安装不该失败：%v\n%s", r.err, r.output)
	}
	for _, path := range []string{r.paths.stageRoot, r.paths.previousRoot} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("成功后事务目录 %s 仍存在：%v", path, err)
		}
	}
}

func TestConcurrentDeploymentIsRejectedBeforeTouchingTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(target, []byte("healthy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var held *os.File
	r := executeScript(t, &Plan{Node: "n1", Files: map[string]string{target: "candidate\n"}}, scriptRunOptions{
		allowedTargetRoot: dir,
		beforeRun: func(paths scriptPaths) {
			var err error
			held, err = os.OpenFile(paths.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
		},
	})
	if held != nil {
		_ = syscall.Flock(int(held.Fd()), syscall.LOCK_UN)
		_ = held.Close()
	}
	if r.err == nil || !strings.Contains(r.output, "另一次部署正在运行") {
		t.Fatalf("持锁时新部署没有被明确拒绝：%v\n%s", r.err, r.output)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "healthy\n" {
		t.Fatalf("锁冲突时仍碰了目标：%q %v\n%s", got, err, r.output)
	}
}

func TestInventoryGuardRejectsConcurrentManifestChangeBeforeTouchingTargets(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.json")
	target := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(manifest, []byte("new inventory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("healthy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Plan{
		Node:  "n1",
		Files: map[string]string{target: "candidate\n"},
		InventoryGuard: &InventoryGuard{
			Path:   manifest,
			SHA256: strings.Repeat("0", 64), // 控制端读完后，清单已被另一轮部署改写。
		},
	}
	r := executeScript(t, p, scriptRunOptions{allowedTargetRoot: dir})
	if r.err == nil {
		t.Fatalf("清单乐观锁不匹配时必须失败：\n%s", r.output)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "healthy\n" {
		t.Fatalf("清单变化后仍碰了线上目标：%q %v\n%s", got, err, r.output)
	}
	if !strings.Contains(r.output, "并发操作中变化") {
		t.Fatalf("错误没有解释需要重试：\n%s", r.output)
	}
}

// 用真实的 /etc/wireguard 路径做 UnitFor 映射，但通过 targetRoot 把所有
// 文件操作重定向进 TempDir。stop 或 disable 任一步失败都必须在 rm 之前
// 中止，配置文件和原 unit 状态都要保住。
func TestMappedUnitStopOrDisableFailureNeverDeletesConfig(t *testing.T) {
	for _, failOp := range []string{"stop", "disable"} {
		t.Run(failOp, func(t *testing.T) {
			targetRoot := t.TempDir()
			logical := "/etc/wireguard/wg-old.conf"
			actual := filepath.Join(targetRoot, "etc/wireguard/wg-old.conf")
			if err := os.MkdirAll(filepath.Dir(actual), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(actual, []byte("old tunnel\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			p := &Plan{Node: "n1", Files: map[string]string{}, Remove: []string{logical}}
			r := executeScript(t, p, scriptRunOptions{
				allowedTargetRoot: targetRoot,
				targetRoot:        targetRoot,
				failOperation:     failOp,
			})
			if r.err == nil {
				t.Fatalf("systemctl %s 失败时部署必须失败：\n%s", failOp, r.output)
			}
			got, err := os.ReadFile(actual)
			if err != nil || string(got) != "old tunnel\n" {
				t.Fatalf("systemctl %s 失败后配置没保住：%q %v\n%s", failOp, got, err, r.output)
			}
			if !strings.Contains(r.log, failOp+"|wg-quick@wg-old") {
				t.Fatalf("没有走真实 unit mapping，systemctl 日志：\n%s", r.log)
			}
		})
	}
}

func TestRemovalRollbackRestoresPreviousUnitState(t *testing.T) {
	unit := "wg-quick@wg-old"
	for _, tc := range []struct {
		name     string
		inactive bool
		disabled bool
	}{
		{name: "active-enabled"},
		{name: "inactive-disabled", inactive: true, disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targetRoot := t.TempDir()
			logical := "/etc/wireguard/wg-old.conf"
			actual := filepath.Join(targetRoot, "etc/wireguard/wg-old.conf")
			if err := os.MkdirAll(filepath.Dir(actual), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(actual, []byte("old tunnel\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := scriptRunOptions{
				allowedTargetRoot: targetRoot,
				targetRoot:        targetRoot,
				failOperation:     "daemon-reload",
			}
			if tc.inactive {
				opts.inactiveUnits = []string{unit}
			}
			if tc.disabled {
				opts.disabledUnits = []string{unit}
			}
			r := executeScript(t, &Plan{Node: "n1", Files: map[string]string{}, Remove: []string{logical}}, opts)
			if r.err == nil {
				t.Fatalf("注入 daemon-reload 失败后部署应失败：\n%s", r.output)
			}
			got, err := os.ReadFile(actual)
			if err != nil || string(got) != "old tunnel\n" {
				t.Fatalf("回滚没有恢复删除文件：%q %v\n%s", got, err, r.output)
			}
			inactive := fileExists(unitStatePath(r.unitState, unit, "inactive"))
			disabled := fileExists(unitStatePath(r.unitState, unit, "disabled"))
			if inactive != tc.inactive || disabled != tc.disabled {
				t.Fatalf("unit 状态未恢复：inactive=%v disabled=%v，期望 %v/%v\nsystemctl:\n%s",
					inactive, disabled, tc.inactive, tc.disabled, r.log)
			}
		})
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readState(t *testing.T, root, unit, kind string) string {
	t.Helper()
	b, err := os.ReadFile(unitStatePath(root, unit, kind))
	if err != nil {
		t.Fatalf("读取 %s/%s 状态:%v", unit, kind, err)
	}
	return strings.TrimSpace(string(b))
}

func observedUnitState(t *testing.T, root, unit, kind string) string {
	t.Helper()
	path := unitStatePath(root, unit, kind+"-state")
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b))
	}
	switch kind {
	case "enabled":
		if fileExists(unitStatePath(root, unit, "disabled")) {
			return "disabled"
		}
		return "enabled"
	case "active":
		if fileExists(unitStatePath(root, unit, "inactive")) {
			return "inactive"
		}
		return "active"
	default:
		t.Fatalf("未知 unit 状态维度:%s", kind)
		return ""
	}
}

func TestPendingActiveTransactionIsRecoveredBeforeNewPrecheck(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(target, []byte("半装的新内容\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Plan{Node: "n1", Files: map[string]string{target: "下一版\n"}, PreCheck: []string{"false"}}
	r := executeScript(t, p, scriptRunOptions{
		allowedTargetRoot: dir,
		beforeRun: func(paths scriptPaths) {
			if err := os.MkdirAll(paths.previousRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				".state":    "active\n",
				".manifest": target + "|f000\n",
				".units":    "",
				"f000":      "旧的健康内容\n",
			} {
				if err := os.WriteFile(filepath.Join(paths.previousRoot, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		},
	})
	if r.err == nil {
		t.Fatalf("新一轮预检应失败:\n%s", r.output)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "旧的健康内容\n" {
		t.Fatalf("没有先恢复被 SIGKILL 留下的 active 事务:%q err=%v\n%s", got, err, r.output)
	}
	if !strings.Contains(r.output, "上一份部署已完整恢复") {
		t.Fatalf("恢复动作没有明确记录:\n%s", r.output)
	}
}

func TestPendingCommittedTransactionIsCleanedWithoutRollback(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(target, []byte("已提交的新内容\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Plan{Node: "n1", Files: map[string]string{target: "下一版\n"}, PreCheck: []string{"false"}}
	r := executeScript(t, p, scriptRunOptions{
		allowedTargetRoot: dir,
		beforeRun: func(paths scriptPaths) {
			if err := os.MkdirAll(paths.previousRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				".state":    "committed\n",
				".manifest": target + "|f000\n",
				".units":    "",
				"f000":      "不该恢复的旧内容\n",
			} {
				if err := os.WriteFile(filepath.Join(paths.previousRoot, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		},
	})
	if r.err == nil {
		t.Fatalf("新一轮预检应失败:\n%s", r.output)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "已提交的新内容\n" {
		t.Fatalf("明确 committed 的新状态被错误回退:%q err=%v\n%s", got, err, r.output)
	}
}

func TestRollbackRestartsEarlierUnitWithRestoredConfig(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.conf")
	b := filepath.Join(dir, "b.conf")
	for _, path := range []string{a, b} {
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := &Plan{
		Node:  "n1",
		Files: map[string]string{a: "new-a\n", b: "new-b\n"},
		Triggers: map[string][]string{
			a: {"a"},
			b: {"b"},
		},
	}
	r := executeScript(t, p, scriptRunOptions{
		allowedTargetRoot: dir,
		failOperation:     "restart",
		failUnit:          "b",
		failOnce:          true,
		loadConfig:        map[string]string{"a": a, "b": b},
	})
	if r.err == nil {
		t.Fatalf("第二个 unit restart 失败时部署必须失败:\n%s", r.output)
	}
	for _, path := range []string{a, b} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "old\n" {
			t.Fatalf("%s 没恢复旧文件:%q err=%v\n%s", path, got, err, r.output)
		}
	}
	loaded := unitStatePath(r.unitState, "a", "loaded")
	got, err := os.ReadFile(loaded)
	if err != nil || string(got) != "old\n" {
		t.Fatalf("a 虽恢复了文件却仍运行新配置:%q err=%v\nsystemctl:\n%s", got, err, r.log)
	}
	if strings.Contains(r.output, "回滚不完整") {
		t.Fatalf("一次性故障后应完整恢复:\n%s", r.output)
	}
}

func TestConfigAndServiceFileRemovalShareCanonicalUnitState(t *testing.T) {
	targetRoot := t.TempDir()
	logicalConfig := "/etc/loom/sing-box/config.json"
	logicalUnit := "/etc/systemd/system/sing-box.service"
	actualConfig := filepath.Join(targetRoot, strings.TrimPrefix(logicalConfig, "/"))
	actualUnit := filepath.Join(targetRoot, strings.TrimPrefix(logicalUnit, "/"))
	for _, path := range []string{actualConfig, actualUnit} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := executeScript(t, &Plan{Node: "n1", Files: map[string]string{}, Remove: []string{logicalConfig, logicalUnit}}, scriptRunOptions{
		allowedTargetRoot: targetRoot,
		targetRoot:        targetRoot,
		failOperation:     "daemon-reload",
		failOnce:          true,
	})
	if r.err == nil {
		t.Fatalf("注入失败后部署应失败:\n%s", r.output)
	}
	for _, path := range []string{actualConfig, actualUnit} {
		if got, err := os.ReadFile(path); err != nil || string(got) != "old\n" {
			t.Fatalf("同删回滚没有恢复 %s:%q err=%v\n%s", path, got, err, r.output)
		}
	}
	if got := strings.Count(r.log, "is-enabled|sing-box\n"); got == 0 {
		t.Fatalf("没有用 canonical sing-box 查询状态:\n%s", r.log)
	}
	if strings.Contains(r.log, "sing-box.service") {
		t.Fatalf("同一 unit 仍以两个别名进入事务:\n%s", r.log)
	}
}

func TestUnchangedDeploymentConvergesSafeUnitDriftAndRejectsUnrestorableState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    scriptRunOptions
		wantErr bool
	}{
		{name: "disabled", opts: scriptRunOptions{disabledUnits: []string{"app"}}},
		{name: "inactive", opts: scriptRunOptions{inactiveUnits: []string{"app"}}},
		{name: "failed", opts: scriptRunOptions{activeStates: map[string]string{"app": "failed"}}, wantErr: true},
		{name: "historical-restart", opts: scriptRunOptions{restartCounts: map[string]string{"app": "4"}}},
		{name: "restarting-now", opts: scriptRunOptions{
			restartCounts:  map[string]string{"app": "4"},
			restartOnSleep: []string{"app"},
		}, wantErr: true},
		{name: "invalid-restart-counter", opts: scriptRunOptions{
			restartCounts: map[string]string{"app": "unknown"},
		}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "app.conf")
			if err := os.WriteFile(target, []byte("same\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.opts.allowedTargetRoot = dir
			r := executeScript(t, &Plan{
				Node: "n1", Files: map[string]string{target: "same\n"}, Verify: []string{"app"},
			}, tc.opts)
			if (r.err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got=%v\n%s", tc.wantErr, r.err, r.output)
			}
			if !tc.wantErr {
				if observedUnitState(t, r.unitState, "app", "enabled") != "enabled" ||
					observedUnitState(t, r.unitState, "app", "active") != "active" {
					t.Fatalf("安全可恢复的 drift 没收敛:\n%s", r.log)
				}
			}
		})
	}
}

func TestOrdinaryStaleRemoveFailureIsNotSwallowed(t *testing.T) {
	targetRoot := t.TempDir()
	logical := "/etc/loom/other/stale.conf"
	actual := filepath.Join(targetRoot, strings.TrimPrefix(logical, "/"))
	if err := os.MkdirAll(filepath.Dir(actual), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actual, []byte("keep-on-failure\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := executeScript(t, &Plan{Node: "n1", Files: map[string]string{}, Remove: []string{logical}}, scriptRunOptions{
		allowedTargetRoot: targetRoot,
		targetRoot:        targetRoot,
		failRemovePath:    actual,
	})
	if r.err == nil {
		t.Fatalf("rm 失败不能假装部署成功:\n%s", r.output)
	}
	got, err := os.ReadFile(actual)
	if err != nil || string(got) != "keep-on-failure\n" {
		t.Fatalf("rm 失败后原文件没保住:%q err=%v\n%s", got, err, r.output)
	}
}

func TestRemovalPreservesRichUnitStatesOrFailsBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name, enabled, active string
		wantErr               bool
	}{
		{name: "masked-inactive", enabled: "masked", active: "inactive"},
		{name: "failed-disabled", enabled: "disabled", active: "failed"},
		{name: "linked-active", enabled: "linked", active: "active", wantErr: true},
		{name: "deactivating", enabled: "enabled", active: "deactivating", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targetRoot := t.TempDir()
			logical := "/etc/loom/agent/config.json"
			actual := filepath.Join(targetRoot, strings.TrimPrefix(logical, "/"))
			if err := os.MkdirAll(filepath.Dir(actual), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(actual, []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			r := executeScript(t, &Plan{Node: "n1", Files: map[string]string{}, Remove: []string{logical}}, scriptRunOptions{
				allowedTargetRoot: targetRoot,
				targetRoot:        targetRoot,
				enabledStates:     map[string]string{"loom-agent": tc.enabled},
				activeStates:      map[string]string{"loom-agent": tc.active},
			})
			if (r.err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got=%v\n%s", tc.wantErr, r.err, r.output)
			}
			if tc.wantErr {
				if got, err := os.ReadFile(actual); err != nil || string(got) != "old\n" {
					t.Fatalf("异常状态下仍删除配置:%q err=%v\n%s", got, err, r.output)
				}
			} else if _, err := os.Stat(actual); !os.IsNotExist(err) {
				t.Fatalf("稳定且无需修改的状态应允许删除:%v\n%s", err, r.output)
			}
			if readState(t, r.unitState, "loom-agent", "enabled-state") != tc.enabled ||
				readState(t, r.unitState, "loom-agent", "active-state") != tc.active {
				t.Fatalf("unit 丰富状态发生漂移:\n%s", r.log)
			}
		})
	}
}

func TestInvalidateOnChangeSharesRollbackAndIgnoresNoop(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(map[bool]string{false: "noop", true: "changed"}[change], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "app.conf")
			coordinate := filepath.Join(dir, "applied")
			if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(coordinate, []byte("snapshot-old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			content := "old\n"
			if change {
				content = "new\n"
			}
			r := executeScript(t, &Plan{
				Node: "n1", Files: map[string]string{target: content}, InvalidateOnChange: []string{coordinate},
			}, scriptRunOptions{allowedTargetRoot: dir})
			if r.err != nil {
				t.Fatalf("不该失败:%v\n%s", r.err, r.output)
			}
			_, err := os.Stat(coordinate)
			if change && !os.IsNotExist(err) {
				t.Fatalf("真实变更成功后 applied 应失效:%v", err)
			}
			if !change && err != nil {
				t.Fatalf("no-op 不应清 applied:%v", err)
			}
		})
	}
}

func TestUnitOnlyChangeRestartsLongRunningService(t *testing.T) {
	targetRoot := t.TempDir()
	logical := "/etc/systemd/system/loom-agent.service"
	actual := filepath.Join(targetRoot, strings.TrimPrefix(logical, "/"))
	if err := os.MkdirAll(filepath.Dir(actual), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actual, []byte("old unit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, _ := BuildPlan("n1", map[string]string{"systemd/loom-agent.service": "new unit\n"})
	r := executeScript(t, p, scriptRunOptions{
		allowedTargetRoot: targetRoot,
		targetRoot:        targetRoot,
	})
	if r.err != nil {
		t.Fatalf("unit-only 部署不该失败:%v\n%s", r.err, r.output)
	}
	if !strings.Contains(r.log, "restart|loom-agent\n") {
		t.Fatalf("unit-only 变化只 daemon-reload、没有让新运行语义生效:\n%s", r.log)
	}
}

func TestNoopInactiveRepairWaitsForDelayedCrashBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(target, []byte("same\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := executeScript(t, &Plan{
		Node: "n1", Files: map[string]string{target: "same\n"}, Verify: []string{"app"},
	}, scriptRunOptions{
		allowedTargetRoot: dir,
		inactiveUnits:     []string{"app"},
		crashOnSleep:      []string{"app"},
	})
	if r.err == nil {
		t.Fatalf("no-op 修复后延迟崩溃不能被 committed:\n%s", r.output)
	}
	if observedUnitState(t, r.unitState, "app", "active") != "inactive" {
		t.Fatalf("失败回滚没有恢复原 inactive 状态:\n%s", r.log)
	}
}

func TestTransactionManifestQuotesTargetPaths(t *testing.T) {
	dir := t.TempDir()
	changed := filepath.Join(dir, "app's.conf")
	removed := filepath.Join(dir, "stale's.conf")
	for _, path := range []string{changed, removed} {
		if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := executeScript(t, &Plan{
		Node: "n1", Files: map[string]string{changed: "new\n"}, Remove: []string{removed},
	}, scriptRunOptions{
		allowedTargetRoot: dir,
		failRemovePath:    removed,
	})
	if r.err == nil {
		t.Fatalf("注入删除失败后脚本应回滚:\n%s", r.output)
	}
	for _, path := range []string{changed, removed} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "old\n" {
			t.Fatalf("带单引号的路径没有安全写入/解析事务清单:%s got=%q err=%v\n%s", path, got, err, r.output)
		}
	}
}

func TestChangedVerifiedUnitWithUnrestorableEnablementFailsBeforeOnlineMutation(t *testing.T) {
	targetRoot := t.TempDir()
	logical := "/etc/loom/agent/config.json"
	actual := filepath.Join(targetRoot, strings.TrimPrefix(logical, "/"))
	if err := os.MkdirAll(filepath.Dir(actual), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actual, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ := BuildPlan("n1", map[string]string{"agent/config.json": "new\n"})
	r := executeScript(t, p, scriptRunOptions{
		allowedTargetRoot: targetRoot,
		targetRoot:        targetRoot,
		enabledStates:     map[string]string{"loom-agent": "masked"},
		activeStates:      map[string]string{"loom-agent": "active"},
	})
	if r.err == nil {
		t.Fatalf("masked active unit 不能先覆盖文件再尝试回滚:\n%s", r.output)
	}
	if got, err := os.ReadFile(actual); err != nil || string(got) != "old\n" {
		t.Fatalf("失败关闭前线上配置已变化:got=%q err=%v\n%s", got, err, r.output)
	}
	if strings.Contains(r.log, "restart|loom-agent\n") {
		t.Fatalf("不可无损收敛的 unit 仍被扰动:\n%s", r.log)
	}
}

func TestRemoveWithMissingManagedFileAndLiveUnitFailsBeforeMutation(t *testing.T) {
	targetRoot := t.TempDir()
	logical := "/etc/wireguard/wg-old.conf"
	coordinate := filepath.Join(targetRoot, "var/lib/loom/applied")
	if err := os.MkdirAll(filepath.Dir(coordinate), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(coordinate, []byte("snapshot-old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := executeScript(t, &Plan{
		Node: "n1", Files: map[string]string{}, Remove: []string{logical},
		InvalidateOnChange: []string{"/var/lib/loom/applied"},
	}, scriptRunOptions{
		allowedTargetRoot: targetRoot,
		targetRoot:        targetRoot,
	})
	if r.err == nil {
		t.Fatalf("缺配置的 active/enabled unit 无法精确回滚，必须失败关闭:\n%s", r.output)
	}
	unit := "wg-quick@wg-old"
	if observedUnitState(t, r.unitState, unit, "active") != "active" ||
		observedUnitState(t, r.unitState, unit, "enabled") != "enabled" {
		t.Fatalf("失败关闭前 unit 原态已被扰动:\n%s", r.log)
	}
	if got, err := os.ReadFile(coordinate); err != nil || string(got) != "snapshot-old\n" {
		t.Fatalf("失败关闭前 applied 已被改动:got=%q err=%v", got, err)
	}
	if strings.Contains(r.log, "stop|"+unit+"\n") || strings.Contains(r.log, "disable|"+unit+"\n") {
		t.Fatalf("不可回滚的残留在安全门前仍被 stop/disable:\n%s", r.log)
	}
	if _, err := os.Stat(r.paths.previousRoot); !os.IsNotExist(err) {
		t.Fatalf("pre-mutation 失败留下 active 事务材料:%v", err)
	}
}

func TestRemoveWithMissingManagedFileAllowsAlreadyOffUnit(t *testing.T) {
	targetRoot := t.TempDir()
	logical := "/etc/wireguard/wg-old.conf"
	unit := "wg-quick@wg-old"
	r := executeScript(t, &Plan{
		Node: "n1", Files: map[string]string{}, Remove: []string{logical},
	}, scriptRunOptions{
		allowedTargetRoot: targetRoot,
		targetRoot:        targetRoot,
		inactiveUnits:     []string{unit},
		disabledUnits:     []string{unit},
	})
	if r.err != nil {
		t.Fatalf("文件与 unit 都已经收敛到 off 时应允许完成:%v\n%s", r.err, r.output)
	}
	if observedUnitState(t, r.unitState, unit, "active") != "inactive" ||
		observedUnitState(t, r.unitState, unit, "enabled") != "disabled" {
		t.Fatalf("已 off unit 被无端改变:\n%s", r.log)
	}
}
