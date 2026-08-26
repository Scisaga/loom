package deploy

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// Mode 决定文件在机器上的权限。
//
// 含秘密的一律 0600。判据是路径而不是"内容里有没有密码" —— 后者要靠猜,
// 而猜错的方向是把秘密设成 0644,没有任何症状。
func Mode(abs string) string {
	switch {
	case strings.HasPrefix(abs, "/etc/wireguard/"):
		return "0600" // 私钥引用 + 对端公钥
	case abs == "/etc/loom/sing-box/config.json":
		return "0600" // 凭据明文在里面
	case abs == "/etc/loom/agent/config.json":
		return "0600" // 控制端点与探测入口的口令
	default:
		return "0644"
	}
}

// Script 生成在节点上执行的安装脚本。
//
// 一次 ssh 传完:文件用 base64 内嵌,不另开 scp。这样"传了一半断线"只会
// 让脚本没跑起来,而不会留下半套文件。
//
// 五个不变量,顺序不能换:
//
//  1. 先写暂存,不碰线上文件
//  2. 在暂存上跑预检(sing-box check)—— 检查失败时线上还是好的
//  3. 把要被替换的那份存进 previous
//  4. 就位、重启
//  5. 验证;任何一步失败就从 previous 恢复并重启回去
func Script(p *Plan, runID string) string {
	return script(p, runID, productionScriptPaths())
}

// ScriptWithInheritedLock 生成给已经持有 DeployLockPath 的进程使用的脚本。
// inheritedFD 必须是随安装 shell 继承的那个文件描述符。pull 用它把验签后的
// 下线、二进制替换、配置安装和 applied 更新包在同一把锁里；apply 仍调用
// Script，让脚本自己取锁。
func ScriptWithInheritedLock(p *Plan, runID string, inheritedFD int) string {
	if inheritedFD < 3 {
		panic(fmt.Sprintf("deploy script inherited lock fd is unsafe: %d", inheritedFD))
	}
	layout := productionScriptPaths()
	layout.lockFD = inheritedFD
	return script(p, runID, layout)
}

// scriptPaths 把安装脚本会触碰的三类节点本地路径集中起来。
//
// 生产入口 Script 始终使用 /var/lib/loom；真正执行 shell 的测试则传入
// t.TempDir() 下的路径，并把计划里的绝对目标路径映射到同一个临时根。
// 这样测试仍然覆盖 /etc/wireguard/... → wg-quick@... 这类真实映射，却不可能
// 写到测试机自己的 /etc 或 /var/lib/loom。
type scriptPaths struct {
	stageRoot    string
	previousRoot string
	lockPath     string
	targetRoot   string
	// lockFD > 0 表示调用方已经持有 lockPath，并把同一 open file
	// description 传给了 shell。脚本只验证这把锁，不另开一个会和自己冲突
	// 的 fd。
	lockFD int
}

func productionScriptPaths() scriptPaths {
	return scriptPaths{
		stageRoot:    StagingRoot,
		previousRoot: PreviousRoot,
		lockPath:     DeployLockPath,
	}
}

func (p scriptPaths) stage(abs string) string {
	return withTrailingSlash(p.stageRoot) + strings.ReplaceAll(strings.TrimPrefix(abs, "/"), "/", "%")
}

func (p scriptPaths) target(abs string) string {
	if p.targetRoot == "" {
		return abs
	}
	return strings.TrimRight(p.targetRoot, "/") + "/" + strings.TrimPrefix(abs, "/")
}

func (p scriptPaths) preCheck(command string) string {
	return strings.ReplaceAll(command, StagingRoot, withTrailingSlash(p.stageRoot))
}

func withTrailingSlash(path string) string {
	return strings.TrimRight(path, "/") + "/"
}

func script(p *Plan, runID string, layout scriptPaths) string {
	validateScriptPaths(layout)
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }

	paths := make([]string, 0, len(p.Files))
	for k := range p.Files {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	w("set -eu")
	w("umask 077")
	w("STAGE=%s; PREV=%s; LOCK=%s; TXN=\"$PREV/.state\"",
		shq(withTrailingSlash(layout.stageRoot)), shq(withTrailingSlash(layout.previousRoot)), shq(layout.lockPath))
	w("mkdir -p \"$STAGE\" \"$PREV\" \"$(dirname \"$LOCK\")\"")
	// apply 在脚本这一层取锁；pull 在验签之后就已取锁，并把同一 open file
	// description 传进来。后者使锁覆盖 decommission / binary / config /
	// applied，也使父 pull 被 kill 后仍在运行的安装 shell 继续持锁。
	if layout.lockFD > 0 {
		w("flock -n %d || { echo '!! 继承的部署锁无效' >&2; exit 75; }", layout.lockFD)
	} else {
		w("exec 9>\"$LOCK\"")
		w("flock -n 9 || { echo '!! 另一次部署正在运行' >&2; exit 75; }")
	}
	w("")
	w("fail() { echo \"!! $*\" >&2; exit 1; }")
	w("RESTART=' '")
	w("mark() { case \"$RESTART\" in *\" $1 \"*) ;; *) RESTART=\"$RESTART$1 \";; esac; }")
	w("marked() { case \"$RESTART\" in *\" $1 \"*) return 0;; *) return 1;; esac; }")
	w("REMEMBERED=' '; RETIRED=' '; RETIRE_NEEDED=' '; MUTATED=0")
	w("")
	// systemctl 的状态不是两个 bool。enabled-runtime、linked、masked、failed
	// 与 disabled/inactive 的恢复动作完全不同；压成 bool 会在失败回滚时改坏
	// 原状态。未知/过渡态保留原字符串，并在需要修改它时失败关闭。
	w("read_unit_state() {")
	w("  UNIT_ENABLED=$(systemctl is-enabled \"$1\" 2>/dev/null || :)")
	w("  case \"$UNIT_ENABLED\" in")
	w("    enabled|enabled-runtime|linked|linked-runtime|alias|disabled|static|indirect|generated|transient|masked|masked-runtime|not-found) ;;")
	w("    *) fail \"无法确认 $1 的 enabled 状态(${UNIT_ENABLED:-空})\" ;;")
	w("  esac")
	w("  UNIT_ACTIVE=$(systemctl is-active \"$1\" 2>/dev/null || :)")
	w("  case \"$UNIT_ACTIVE\" in")
	w("    active|inactive|failed|activating|deactivating|reloading) ;;")
	w("    unknown) [ \"$UNIT_ENABLED\" = not-found ] || fail \"$1 的 active 状态异常(unknown)\" ;;")
	w("    *) fail \"无法确认 $1 的 active 状态(${UNIT_ACTIVE:-空})\" ;;")
	w("  esac")
	w("}")
	w("remember_unit() {")
	w("  case \"$REMEMBERED\" in *\" $1 \"*) return 0;; esac")
	w("  read_unit_state \"$1\"")
	w("  printf '%%s|%%s|%%s\\n' \"$1\" \"$UNIT_ENABLED\" \"$UNIT_ACTIVE\" >> \"$PREV/.units\"")
	w("  REMEMBERED=\"$REMEMBERED$1 \"")
	w("}")
	w("load_remembered() {")
	w("  SAVED_ENABLED=; SAVED_ACTIVE=")
	w("  while IFS='|' read -r saved_unit saved_enabled saved_active; do")
	w("    if [ \"$saved_unit\" = \"$1\" ]; then SAVED_ENABLED=$saved_enabled; SAVED_ACTIVE=$saved_active; break; fi")
	w("  done < \"$PREV/.units\"")
	w("  [ -n \"$SAVED_ENABLED\" ] && [ -n \"$SAVED_ACTIVE\" ] || fail \"没有 $1 的可恢复状态\"")
	w("}")
	w("assert_unit_unchanged() {")
	w("  load_remembered \"$1\"; read_unit_state \"$1\"")
	w("  [ \"$UNIT_ENABLED\" = \"$SAVED_ENABLED\" ] && [ \"$UNIT_ACTIVE\" = \"$SAVED_ACTIVE\" ] ||")
	w("    fail \"$1 在备份后自行从 $SAVED_ENABLED/$SAVED_ACTIVE 变成 $UNIT_ENABLED/$UNIT_ACTIVE\"")
	w("}")
	w("write_txn_state() {")
	w("  printf '%%s\\n' \"$1\" > \"$TXN.next\" || return 1")
	w("  sync \"$TXN.next\" || return 1")
	w("  mv -f \"$TXN.next\" \"$TXN\" || return 1")
	w("  sync -f \"$PREV\" || return 1")
	w("}")
	w("begin_txn() {")
	w("  if [ ! -e \"$TXN\" ]; then")
	w("    sync -f \"$PREV\" || fail '无法持久化回滚材料'")
	w("    write_txn_state active || fail '无法持久化 active 事务标记'")
	w("  fi")
	w("  [ \"$(cat \"$TXN\" 2>/dev/null || :)\" = active ] || fail '事务状态不是 active，拒绝修改线上状态'")
	w("  MUTATED=1")
	w("}")
	w("retire_unit() {")
	w("  case \"$RETIRED\" in *\" $1 \"*) return 0;; esac")
	w("  assert_unit_unchanged \"$1\"")
	w("  case \"$SAVED_ACTIVE\" in")
	w("    activating|deactivating|reloading) fail \"$1 正处于过渡态 $SAVED_ACTIVE，拒绝删除配置\" ;;")
	w("    active) case \"$SAVED_ENABLED\" in masked|masked-runtime|not-found) fail \"$1 状态矛盾($SAVED_ENABLED/active)\";; esac ;;")
	w("    inactive|failed|unknown) ;;")
	w("  esac")
	w("  case \"$SAVED_ENABLED\" in")
	w("    linked|linked-runtime|alias) fail \"$1 是 $SAVED_ENABLED，无法无损 disable/恢复，拒绝删除配置\" ;;")
	w("  esac")
	w("  if [ \"$SAVED_ACTIVE\" = active ]; then")
	w("    systemctl stop \"$1\" || fail \"停止 $1 失败\"")
	w("    now=$(systemctl is-active \"$1\" 2>/dev/null || :)")
	w("    [ \"$now\" = inactive ] || fail \"$1 停止后是 ${now:-未知}，不是 inactive\"")
	w("  fi")
	w("  case \"$SAVED_ENABLED\" in")
	w("    enabled) systemctl disable \"$1\" || fail \"禁用 $1 失败\" ;;")
	w("    enabled-runtime) systemctl disable --runtime \"$1\" || fail \"运行时禁用 $1 失败\" ;;")
	w("  esac")
	w("  RETIRED=\"$RETIRED$1 \"")
	w("}")
	w("")
	// 删除收敛不能以配置文件仍存在为前提。文件可能已被人工删掉，但
	// systemd unit / WireGuard 接口仍然 active 或 enabled；这种漂移若不计入
	// changed，脚本会走 no-op 成功并让 applied 推进，留下“暗连”。这里在
	// mutation 前保存并校验原状态，同时把需要退休的 unit 作为事务变化计数。
	w("mark_retire_needed() {")
	w("  case \"$RETIRE_NEEDED\" in *\" $1 \"*) return 0;; esac")
	w("  RETIRE_NEEDED=\"$RETIRE_NEEDED$1 \"")
	w("  changed=$((changed+1))")
	w("}")
	w("retire_needed() { case \"$RETIRE_NEEDED\" in *\" $1 \"*) return 0;; *) return 1;; esac; }")
	w("prepare_retire_unit() {")
	w("  remember_unit \"$1\"; load_remembered \"$1\"")
	w("  case \"$SAVED_ACTIVE\" in")
	w("    activating|deactivating|reloading) fail \"$1 正处于过渡态 $SAVED_ACTIVE，拒绝把残留单元当作已下线\" ;;")
	w("    active) case \"$SAVED_ENABLED\" in masked|masked-runtime|not-found) fail \"$1 状态矛盾($SAVED_ENABLED/active)\";; esac ;;")
	w("    inactive|failed|unknown) ;;")
	w("  esac")
	w("  case \"$SAVED_ENABLED\" in")
	w("    linked|linked-runtime|alias) fail \"$1 是 $SAVED_ENABLED，无法无损 disable/恢复，拒绝删除配置\" ;;")
	w("  esac")
	w("  case \"$SAVED_ACTIVE\" in active|activating|deactivating|reloading) mark_retire_needed \"$1\" ;; esac")
	w("  case \"$SAVED_ENABLED\" in enabled|enabled-runtime) mark_retire_needed \"$1\" ;; esac")
	// active unit 的配置已经丢失时，stop 之后无法保证 rollback 能 restart 回
	// 原态。与其制造一个永久 active 的回滚事务，先于任何 mutation 明确失败；
	// timer 会继续重试，操作者也能先处理这份预存漂移。文件仍在的正常删除
	// 路径继续保有完整原态回滚。
	w("  if [ \"$2\" = 0 ] && retire_needed \"$1\"; then")
	w("    fail \"$1 的受管配置已缺失但 unit 仍为 $SAVED_ENABLED/$SAVED_ACTIVE；无法在保证原态回滚的同时自动停用，请先修复该漂移\"")
	w("  fi")
	w("}")
	w("")
	// wg-quick 不能用 systemctl restart:down 与 up 之间有竞态。enable 是
	// 独立的期望状态，由 ensure_enabled 验证，不能塞在 restart 里吞错误。
	w("restart_one() {")
	w("  case \"$1\" in")
	w("    *.timer) systemctl restart \"$1\" ;;")
	w("    wg-quick@*)")
	w("      iface=${1#wg-quick@}")
	w("      systemctl stop \"$1\"")
	w("      ip link del \"$iface\" 2>/dev/null || :")
	w("      systemctl start \"$1\" ;;")
	w("    *)")
	w("      systemctl reset-failed \"$1\" 2>/dev/null || :")
	w("      systemctl restart \"$1\" ;;")
	w("  esac")
	w("}")
	w("")
	w("prepare_restart_unit() {")
	w("  remember_unit \"$1\"; load_remembered \"$1\"")
	w("  case \"$SAVED_ACTIVE\" in")
	w("    active|inactive|unknown) ;;")
	w("    *) fail \"$1 原状态是 $SAVED_ACTIVE，无法保证失败后精确恢复，拒绝替换配置\" ;;")
	w("  esac")
	w("  if [ \"$2\" = 1 ]; then")
	w("    case \"$SAVED_ENABLED\" in")
	w("      enabled|disabled|enabled-runtime|not-found) : ;;")
	w("      *) fail \"$1 原 enabled 状态是 $SAVED_ENABLED，无法无损收敛为持久 enabled，拒绝替换配置\" ;;")
	w("    esac")
	w("  fi")
	w("}")
	w("")
	w("ensure_enabled() {")
	w("  remember_unit \"$1\"; read_unit_state \"$1\"")
	w("  case \"$UNIT_ENABLED\" in")
	w("    enabled) return 0 ;;")
	w("    disabled|enabled-runtime|not-found)")
	w("      begin_txn")
	w("      systemctl enable \"$1\" || fail \"enable $1 失败\"")
	w("      now=$(systemctl is-enabled \"$1\" 2>/dev/null || :)")
	w("      [ \"$now\" = enabled ] || fail \"$1 enable 后是 ${now:-未知}，不是 enabled\" ;;")
	w("    linked|linked-runtime|alias|masked|masked-runtime|static|indirect|generated|transient)")
	w("      fail \"$1 的 enabled 状态是 $UNIT_ENABLED，无法无损收敛为 enabled\" ;;")
	w("  esac")
	w("}")
	w("")
	w("ensure_running() {")
	w("  remember_unit \"$1\"; read_unit_state \"$1\"")
	w("  case \"$UNIT_ACTIVE\" in")
	w("    active) return 0 ;;")
	w("    inactive)")
	w("      begin_txn")
	w("      systemctl start \"$1\" || fail \"启动 $1 失败\"")
	w("      now=$(systemctl is-active \"$1\" 2>/dev/null || :)")
	w("      [ \"$now\" = active ] || fail \"$1 启动后是 ${now:-未知}，不是 active\" ;;")
	w("    failed|activating|deactivating|reloading|unknown)")
	w("      fail \"$1 的 active 状态是 $UNIT_ACTIVE，无法保证失败后精确恢复\" ;;")
	w("  esac")
	w("}")
	w("")
	// 单元恢复逐项 best-effort，最后再统一判失败。第一项恢复失败不能挡住
	// 后面的文件/单元；但只要有一项没恢复，就保留 active 标记和全部材料，
	// 下一次持锁部署会重试，且绝不宣称“已回滚”。
	w("restore_unit_exact() {")
	w("  unit=$1; was_enabled=$2; was_active=$3; unit_failed=0")
	w("  case \"$was_enabled\" in")
	w("    enabled) systemctl enable \"$unit\" >/dev/null 2>&1 || unit_failed=1 ;;")
	w("    enabled-runtime)")
	w("      systemctl disable \"$unit\" >/dev/null 2>&1 || unit_failed=1")
	w("      systemctl enable --runtime \"$unit\" >/dev/null 2>&1 || unit_failed=1 ;;")
	w("    disabled) systemctl disable \"$unit\" >/dev/null 2>&1 || unit_failed=1 ;;")
	w("    linked|linked-runtime|alias|static|indirect|generated|transient|masked|masked-runtime|not-found) : ;;")
	w("    *) unit_failed=1 ;;")
	w("  esac")
	w("  case \"$was_active\" in")
	// start 一个已经 active 的服务是 no-op；若它刚用新配置 restart 成功、
	// 随后别的单元失败，回滚文件后必须再次 restart 才真正加载旧配置。
	w("    active) restart_one \"$unit\" >/dev/null 2>&1 || unit_failed=1 ;;")
	w("    inactive) systemctl stop \"$unit\" >/dev/null 2>&1 || unit_failed=1 ;;")
	w("    failed|activating|deactivating|reloading|unknown) : ;;")
	w("    *) unit_failed=1 ;;")
	w("  esac")
	w("  got_enabled=$(systemctl is-enabled \"$unit\" 2>/dev/null || :)")
	w("  got_active=$(systemctl is-active \"$unit\" 2>/dev/null || :)")
	w("  [ \"$got_enabled\" = \"$was_enabled\" ] || unit_failed=1")
	w("  [ \"$got_active\" = \"$was_active\" ] || unit_failed=1")
	w("  if [ \"$unit_failed\" != 0 ]; then")
	w("    echo \"   ! $unit 未恢复到 $was_enabled/$was_active(现在 ${got_enabled:-未知}/${got_active:-未知})\" >&2")
	w("    return 1")
	w("  fi")
	w("  return 0")
	w("}")
	w("")
	w("recover_active() {")
	w("  rollback_failed=0")
	w("  [ -f \"$PREV/.manifest\" ] || { echo '   ! active 事务缺少文件清单' >&2; rollback_failed=1; }")
	w("  [ -f \"$PREV/.units\" ] || { echo '   ! active 事务缺少单元清单' >&2; rollback_failed=1; }")
	w("  if [ -f \"$PREV/.manifest\" ]; then")
	w("    while IFS='|' read -r tgt saved extra; do")
	w("      if [ -z \"$tgt\" ] || [ -z \"$saved\" ] || [ -n \"$extra\" ]; then rollback_failed=1; continue; fi")
	w("      if [ \"$saved\" = NEW ]; then")
	w("        rm -f \"$tgt\" || { echo \"   ! 无法删除新文件 $tgt\" >&2; rollback_failed=1; }")
	w("      else")
	w("        cp -p \"$PREV/$saved\" \"$tgt\" || { echo \"   ! 无法恢复 $tgt\" >&2; rollback_failed=1; }")
	w("      fi")
	w("    done < \"$PREV/.manifest\"")
	w("  fi")
	w("  systemctl daemon-reload >/dev/null 2>&1 || { echo '   ! 回滚时 daemon-reload 失败' >&2; rollback_failed=1; }")
	w("  if [ -f \"$PREV/.units\" ]; then")
	w("    while IFS='|' read -r unit was_enabled was_active extra; do")
	w("      if [ -z \"$unit\" ] || [ -z \"$was_enabled\" ] || [ -z \"$was_active\" ] || [ -n \"$extra\" ]; then rollback_failed=1; continue; fi")
	w("      restore_unit_exact \"$unit\" \"$was_enabled\" \"$was_active\" || rollback_failed=1")
	w("    done < \"$PREV/.units\"")
	w("  fi")
	w("  [ \"$rollback_failed\" = 0 ]")
	w("}")
	w("")
	w("recover_pending() {")
	w("  if [ ! -e \"$TXN\" ]; then")
	w("    # 旧版可能留下无状态 .manifest；它不能授权回滚健康线上文件。")
	w("    # 丢掉这类 stale 元数据，再从一份空事务开始。")
	w("    rm -rf \"$STAGE\" \"$PREV\" || fail '无法清理无状态旧事务'")
	w("    mkdir -p \"$STAGE\" \"$PREV\"")
	w("    return 0")
	w("  fi")
	w("  old_state=$(cat \"$TXN\" 2>/dev/null || :) ")
	w("  case \"$old_state\" in")
	w("    active)")
	w("      echo '   发现未完成的 active 部署，先恢复上一份' >&2")
	w("      if recover_active; then")
	w("        echo '   ✅ 上一份部署已完整恢复' >&2")
	w("        rm -rf \"$STAGE\" \"$PREV\" || fail '恢复成功但无法清理事务材料'")
	w("        mkdir -p \"$STAGE\" \"$PREV\"")
	w("      else")
	w("        echo '!! 上一份部署恢复不完整；保留 active 标记和回滚材料，拒绝继续' >&2")
	w("        exit %d", RollbackIncompleteExitCode)
	w("      fi ;;")
	w("    committed)")
	w("      echo '   清理上一份已 committed 的事务(不回退新状态)' >&2")
	w("      rm -rf \"$STAGE\" \"$PREV\" || fail '无法清理 committed 事务'")
	w("      mkdir -p \"$STAGE\" \"$PREV\" ;;")
	w("    *)")
	w("      echo \"!! 无法识别部署事务状态(${old_state:-空})；保留现场并拒绝继续\" >&2")
	w("      exit %d ;;", RollbackIncompleteExitCode)
	w("  esac")
	w("}")
	w("recover_pending")
	w(": > \"$PREV/.manifest\"")
	w(": > \"$PREV/.units\"")
	w("")
	w("on_exit() {")
	w("  rc=$?")
	w("  trap - EXIT HUP INT TERM")
	w("  state=$(cat \"$TXN\" 2>/dev/null || :)")
	w("  case \"$state\" in")
	w("    active)")
	w("      echo '   回滚 active 部署…' >&2")
	w("      if recover_active; then")
	w("        echo '   ✅ 回滚完整完成' >&2")
	w("        rm -rf \"$STAGE\" \"$PREV\" || exit %d", RollbackIncompleteExitCode)
	w("      else")
	w("        echo '!! 回滚不完整；保留 active 标记和材料供下次重试' >&2")
	w("        exit %d", RollbackIncompleteExitCode)
	w("      fi ;;")
	w("    committed) rm -rf \"$STAGE\" \"$PREV\" || exit %d ;;", RollbackIncompleteExitCode)
	w("    '') rm -rf \"$STAGE\" \"$PREV\" || exit %d ;;", RollbackIncompleteExitCode)
	w("    *) echo \"!! 异常事务状态 ${state}，保留现场\" >&2; exit %d ;;", RollbackIncompleteExitCode)
	w("  esac")
	w("  exit \"$rc\"")
	w("}")
	// TERM/HUP/INT 先转成正常的非零退出，再由 EXIT trap 恢复。若最终仍被
	// SIGKILL，active 标记和回滚材料会留给下一次持锁部署。
	w("trap on_exit EXIT")
	w("trap 'exit 129' HUP")
	w("trap 'exit 130' INT")
	w("trap 'exit 143' TERM")
	w("")
	// NRestarts 是累计计数，历史上发生过一次自动重启不能让节点永久失败。
	// 在服务已经启动后取基线，经过同一稳定窗口再比较增量；窗口内增加才
	// 说明当前仍在崩溃重启。Timer 没有这个 Service 属性。
	w("snapshot_restarts() { :")
	restartIndex := 0
	for _, s := range p.Verify {
		if strings.HasSuffix(s, ".timer") {
			continue
		}
		w("  RESTART_BASE_%d=$(systemctl show -p NRestarts --value %s 2>/dev/null || :)", restartIndex, shq(s))
		w("  case \"$RESTART_BASE_%d\" in ''|*[!0-9]*) fail %s ;; esac", restartIndex, shq(s+" 的 NRestarts 基线不可读"))
		restartIndex++
	}
	w("}")
	w("verify_desired() { :")
	restartIndex = 0
	for _, s := range p.Verify {
		w("  [ \"$(systemctl is-enabled %s 2>/dev/null || :)\" = enabled ] || fail %s", shq(s), shq(s+" 没有持久 enable"))
		w("  [ \"$(systemctl is-active %s 2>/dev/null || :)\" = active ] || fail %s", shq(s), shq(s+" 没起来"))
		if !strings.HasSuffix(s, ".timer") {
			w("  restart_now=$(systemctl show -p NRestarts --value %s 2>/dev/null || :)", shq(s))
			w("  case \"$restart_now\" in ''|*[!0-9]*) fail %s ;; esac", shq(s+" 的 NRestarts 无法复核"))
			w("  [ \"$restart_now\" = \"$RESTART_BASE_%d\" ] || fail %s", restartIndex, shq(s+" 在稳定窗口内发生自动重启"))
			restartIndex++
		}
	}
	w("}")
	w("finish_success() {")
	w("  if [ \"$MUTATED\" = 1 ]; then")
	w("    write_txn_state committed || fail '线上状态已验证，但无法持久化 committed 标记'")
	w("  fi")
	w("  trap - EXIT HUP INT TERM")
	w("  rm -rf \"$STAGE\" \"$PREV\" || { echo '!! 已 committed，但清理事务材料失败' >&2; exit 1; }")
	w("}")
	w("")
	if p.InventoryGuard != nil {
		guardPath := layout.target(p.InventoryGuard.Path)
		w("# apply 清单乐观锁:持有部署锁后确认差集依据没有被并发 pull 改写")
		if p.InventoryGuard.Absent {
			w("[ ! -e %s ] || fail '目标安装清单已在并发操作中出现,请重试'", shq(guardPath))
		} else {
			w("[ -f %s ] || fail '目标安装清单已在并发操作中消失,请重试'", shq(guardPath))
			w("guard_sum=$(sha256sum %s | awk '{print $1}')", shq(guardPath))
			w("[ \"$guard_sum\" = %s ] || fail '目标安装清单已在并发操作中变化,请重试'", shq(p.InventoryGuard.SHA256))
		}
		w("")
	}

	w("# 1. 写暂存")
	for _, abs := range paths {
		st := layout.stage(abs)
		w("base64 -d > %s <<'LOOM_B64'", shq(st))
		w("%s", chunk(base64.StdEncoding.EncodeToString([]byte(p.Files[abs])), 76))
		w("LOOM_B64")
	}
	w("")

	if len(p.PreCheck) > 0 {
		w("# 2. 预检(在暂存上跑,线上文件还没动)")
		for _, c := range p.PreCheck {
			c = layout.preCheck(c)
			w("%s >/dev/null 2>&1 || fail %s", c, shq("预检失败:"+c))
		}
		w("")
	}

	w("# 3. 备份现状,同时记下这次要重启哪些服务")
	w("changed=0")
	for i, abs := range paths {
		st := layout.stage(abs)
		tgt := layout.target(abs)
		saved := fmt.Sprintf("f%03d", i)
		w("if [ -f %s ] && cmp -s %s %s; then :; else", shq(tgt), shq(tgt), shq(st))
		w("  changed=$((changed+1))")
		w("  if [ -f %s ]; then cp -p %s \"$PREV/%s\"; printf '%%s\\n' %s >> \"$PREV/.manifest\";",
			shq(tgt), shq(tgt), saved, shq(tgt+"|"+saved))
		w("  else printf '%%s\\n' %s >> \"$PREV/.manifest\"; fi", shq(tgt+"|NEW"))
		// 只有真的变了的文件才会触发它关联的服务。
		for _, s := range p.Triggers[abs] {
			w("  mark %s", shq(s))
			requireEnabled := 0
			for _, verified := range p.Verify {
				if verified == s {
					requireEnabled = 1
					break
				}
			}
			w("  prepare_restart_unit %s %d", shq(s), requireEnabled)
		}
		w("fi")
	}
	// 要删的也走同一套备份 —— **删除是一种变更**,回滚时要能放回去。
	// $PREV/.manifest 里存的是原文件,restore 会 cp 回原位。
	for i, abs := range p.Remove {
		tgt := layout.target(abs)
		saved := fmt.Sprintf("d%03d", i)
		w("remove_file_present=0")
		w("if [ -e %s ]; then", shq(tgt))
		w("  remove_file_present=1")
		w("  changed=$((changed+1))")
		w("  cp -p %s \"$PREV/%s\"; printf '%%s\\n' %s >> \"$PREV/.manifest\"", shq(tgt), saved, shq(tgt+"|"+saved))
		w("fi")
		if u := UnitFor(abs); u != "" {
			// 即使文件已经不在，也必须检查 unit 的真实状态。prepare 会在
			// active/enabled 残留时把它计作一次事务变化，并对无法精确回滚
			// 的丰富状态在任何线上 mutation 前失败关闭。
			w("prepare_retire_unit %s \"$remove_file_present\"", shq(u))
		}
	}
	// applied/rollout 这类坐标不决定 changed；只有配置真的变化时才把它们
	// 纳入同一份 manifest。active 前先备份，失败与配置一起恢复。
	for i, abs := range p.InvalidateOnChange {
		tgt := layout.target(abs)
		saved := fmt.Sprintf("i%03d", i)
		w("if [ \"$changed\" != 0 ] && [ -e %s ]; then", shq(tgt))
		w("  [ -f %s ] || fail %s", shq(tgt), shq("待失效坐标 "+abs+" 不是普通文件"))
		w("  cp -p %s \"$PREV/%s\"; printf '%%s\\n' %s >> \"$PREV/.manifest\"", shq(tgt), saved, shq(tgt+"|"+saved))
		w("fi")
	}
	w("echo \"   %d 个文件,其中 $changed 个有变化\"", len(paths))
	w("")
	// 文件无变化也必须核对 enabled / active / NRestarts。以前这里在验证前
	// 早退，同快照上的 disabled、failed 和崩溃循环会永久假绿。
	w("if [ \"$changed\" = 0 ]; then")
	w("  echo '   文件无变化，核对服务状态'")
	for _, s := range p.Verify {
		w("  ensure_enabled %s", shq(s))
		w("  ensure_running %s", shq(s))
	}
	if len(p.Verify) > 0 {
		w("  snapshot_restarts")
		w("  sleep 5")
	}
	w("  verify_desired")
	w("  finish_success")
	w("  printf '%%s\\n' %s", shq("   ✅ "+p.Node+" 完成(run "+runID+")"))
	w("  exit 0")
	w("fi")
	w("")
	// 所有回滚文件和原始 unit 状态已落盘。active 必须先于第一处线上修改
	// 持久化；SIGKILL 即使绕过 EXIT trap，下一轮也能在同一把锁下恢复。
	w("begin_txn")
	for _, abs := range p.InvalidateOnChange {
		tgt := layout.target(abs)
		w("if [ -e %s ]; then rm -f %s || fail %s; fi", shq(tgt), shq(tgt), shq("失效坐标 "+abs+" 失败"))
	}

	if len(p.Remove) > 0 {
		w("# 3.5 清掉不再声明的东西")
		w("#")
		w("# dpkg 的模型:包的文件清单存在机器上,卸载时按清单删。这里的清单")
		w("# 是节点本地的自检清单,**只删自己装过的** —— 清单里没有的一律不碰。")
		w("#")
		w("# 顺序是先停服务再删文件:反过来的话 wg-quick stop 找不到配置,")
		w("# 接口会留在内核里,而那正是\"以为删了其实还连着\"的形状。")
		for _, abs := range p.Remove {
			tgt := layout.target(abs)
			if u := UnitFor(abs); u != "" {
				// unit 状态与文件存在性是两条独立事实。先总是收敛 unit，
				// 再按需删除文件；否则“文件已丢、进程仍活”会被跳过。
				w("printf '%%s\\n' %s", shq("   停用 "+u))
				// 先读出明确状态：active/enabled 才需要 stop/disable；查询未知、
				// 必要操作失败或操作后状态没收敛，任何一种都在 rm 前失败关闭。
				w("retire_unit %s", shq(u))
				w("if [ -e %s ]; then rm -f %s || fail %s; fi", shq(tgt), shq(tgt), shq("删除 "+abs+" 失败"))
			} else {
				w("if [ -e %s ]; then printf '%%s\\n' %s; rm -f %s || fail %s; fi",
					shq(tgt), shq("   删除 "+abs), shq(tgt), shq("删除 "+abs+" 失败"))
			}
		}
		w("systemctl daemon-reload")
		w("")
	}

	w("# 4. 就位")
	for _, abs := range paths {
		tgt := layout.target(abs)
		w("mkdir -p %s", shq(dir(tgt)))
		w("install -m %s %s %s", Mode(abs), shq(layout.stage(abs)), shq(tgt))
	}
	w("systemctl daemon-reload")
	// enable 的结果是期望状态的一部分，失败不能吞。文件就位之后执行，
	// 才能支持首次安装时原先尚不存在的 unit。
	for _, s := range p.Verify {
		w("ensure_enabled %s", shq(s))
	}
	w("echo \"   重启:$RESTART\"")
	for _, s := range p.Services() {
		w("if marked %s; then restart_one %s || fail %s; fi", shq(s), shq(s), shq("重启 "+s+" 失败"))
	}
	for _, s := range p.Verify {
		w("ensure_running %s", shq(s))
	}
	w("")

	w("# 5. 验证:持久 enable、active，而且稳定窗口内没有新增自动重启")
	w("# 等一会儿再看 —— 崩溃循环的第一次崩溃通常在启动后一两秒。")
	if len(p.Verify) > 0 {
		w("snapshot_restarts")
		w("sleep 5")
	}
	w("verify_desired")
	// committed 必须先于清理回滚材料。两者之间被 kill 时，下一轮看到
	// committed 只做清理，绝不会把已经明确提交的新状态退掉。
	w("finish_success")
	w("printf '%%s\\n' %s", shq("   ✅ "+p.Node+" 完成(run "+runID+")"))
	return b.String()
}

func validateScriptPaths(layout scriptPaths) {
	for name, path := range map[string]string{
		"stage":    layout.stageRoot,
		"previous": layout.previousRoot,
		"lock":     layout.lockPath,
	} {
		if !strings.HasPrefix(path, "/") || strings.Trim(path, "/") == "" {
			panic(fmt.Sprintf("deploy script %s path is unsafe: %q", name, path))
		}
	}
	if layout.targetRoot != "" && (!strings.HasPrefix(layout.targetRoot, "/") || strings.Trim(layout.targetRoot, "/") == "") {
		panic(fmt.Sprintf("deploy script target root is unsafe: %q", layout.targetRoot))
	}
}

func dir(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

// shq 用单引号包裹并转义,避免路径或服务名里的特殊字符被 shell 解释。
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func chunk(s string, n int) string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	if s != "" {
		out = append(out, s)
	}
	return strings.Join(out, "\n")
}
