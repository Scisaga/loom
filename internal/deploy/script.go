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
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }

	paths := make([]string, 0, len(p.Files))
	for k := range p.Files {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	w("set -eu")
	w("umask 077")
	w("STAGE=%s; PREV=%s", shq(StagingRoot), shq(PreviousRoot))
	w("rm -rf \"$STAGE\"; mkdir -p \"$STAGE\" \"$PREV\"")
	w("")
	w("RESTART=' '")
	w("mark() { case \"$RESTART\" in *\" $1 \"*) ;; *) RESTART=\"$RESTART$1 \";; esac; }")
	w("marked() { case \"$RESTART\" in *\" $1 \"*) return 0;; *) return 1;; esac; }")
	w("")
	// wg-quick 不能用 systemctl restart:down 与 up 之间有竞态,失败信息是
	// "`wg-xxx' already exists",而接口其实还在,于是 unit 留在 failed 状态
	// 而隧道看起来是好的 —— 最难查的那种。显式停、确认接口没了、再起。
	// 新装的单元必须 enable,否则重启一次机器就全没了 —— 而且这件事
	// 只有在真的重启那天才会发现。
	w("restart_one() {")
	w("  case \"$1\" in")
	w("    *.timer)")
	w("      systemctl enable --now \"$1\"")
	w("      systemctl restart \"$1\" ;;")
	w("    wg-quick@*)")
	w("      systemctl enable \"$1\" 2>/dev/null || true")
	w("      iface=${1#wg-quick@}")
	w("      systemctl stop \"$1\" 2>/dev/null || true")
	w("      ip link del \"$iface\" 2>/dev/null || true")
	w("      systemctl start \"$1\" ;;")
	w("    *)")
	w("      systemctl reset-failed \"$1\" 2>/dev/null || true")
	w("      systemctl restart \"$1\" ;;")
	w("  esac")
	w("}")
	w("")
	w("fail() { echo \"!! $*\" >&2; restore; exit 1; }")
	w("")
	// 恢复只碰这次真的换过的文件。previous 里有什么就恢复什么;这次新增的
	// 文件在 previous 里没有对应项,恢复时删掉。
	// 回滚只碰这次真的动过的东西。预检阶段失败时什么都没装、什么都没标记,
	// 这时"回滚"必须是彻底的空操作 —— 否则它会去重启一堆本来好好的服务,
	// 把一次干净的拒绝变成一次真实的扰动。
	w("restore() {")
	w("  [ -s \"$PREV/.manifest\" ] || { echo '   (什么都没改,无需回滚)' >&2; return 0; }")
	w("  echo '   回滚中…' >&2")
	w("  while IFS='|' read -r tgt saved; do")
	w("    if [ \"$saved\" = NEW ]; then rm -f \"$tgt\"; else cp -p \"$PREV/$saved\" \"$tgt\"; fi")
	w("  done < \"$PREV/.manifest\"")
	w("  systemctl daemon-reload || true")
	for _, s := range p.Services() {
		w("  if marked %s; then restart_one %s || true; fi", shq(s), shq(s))
	}
	w("}")
	w("")

	w("# 1. 写暂存")
	for _, abs := range paths {
		st := stagingPath(abs)
		w("base64 -d > %s <<'LOOM_B64'", shq(st))
		w("%s", chunk(base64.StdEncoding.EncodeToString([]byte(p.Files[abs])), 76))
		w("LOOM_B64")
	}
	w("")

	if len(p.PreCheck) > 0 {
		w("# 2. 预检(在暂存上跑,线上文件还没动)")
		for _, c := range p.PreCheck {
			w("%s >/dev/null 2>&1 || fail '预检失败:%s'", c, c)
		}
		w("")
	}

	w("# 3. 备份现状,同时记下这次要重启哪些服务")
	w(": > \"$PREV/.manifest\"")
	w("changed=0")
	for i, abs := range paths {
		st := stagingPath(abs)
		saved := fmt.Sprintf("f%03d", i)
		w("if [ -f %s ] && cmp -s %s %s; then :; else", shq(abs), shq(abs), shq(st))
		w("  changed=$((changed+1))")
		w("  if [ -f %s ]; then cp -p %s \"$PREV/%s\"; echo '%s|%s' >> \"$PREV/.manifest\";",
			shq(abs), shq(abs), saved, abs, saved)
		w("  else echo '%s|NEW' >> \"$PREV/.manifest\"; fi", abs)
		// 只有真的变了的文件才会触发它关联的服务。
		for _, s := range p.Triggers[abs] {
			w("  mark %s", shq(s))
		}
		w("fi")
	}
	w("echo \"   %d 个文件,其中 $changed 个有变化\"", len(paths))
	w("")
	// **enable 是期望状态的一部分,不是文件内容的一部分。**
	// 只在文件变化时才 enable,会留下"现在能用、重启就没了"的机器 ——
	// 而这件事只有在真的重启那天才会发现。所以每轮都确认一遍,幂等。
	w("# 确认该开机自启的都自启(与文件有没有变化无关)")
	for _, s := range p.Verify {
		w("systemctl is-enabled %s >/dev/null 2>&1 || { echo '   enable %s'; systemctl enable %s 2>/dev/null || true; }",
			shq(s), s, shq(s))
	}
	w("")
	w("if [ \"$changed\" = 0 ]; then echo '   无变化,不重启任何服务'; rm -f \"$PREV/.manifest\"; rm -rf \"$STAGE\"; exit 0; fi")
	w("")

	w("# 4. 就位")
	for _, abs := range paths {
		w("mkdir -p %s", shq(dir(abs)))
		w("install -m %s %s %s", Mode(abs), shq(stagingPath(abs)), shq(abs))
	}
	w("systemctl daemon-reload")
	w("echo \"   重启:$RESTART\"")
	for _, s := range p.Services() {
		w("if marked %s; then restart_one %s || fail '重启 %s 失败'; fi", shq(s), shq(s), s)
	}
	w("")

	w("# 5. 验证:起来了,而且没在崩溃重启循环里")
	w("# 等一会儿再看 —— 崩溃循环的第一次崩溃通常在启动后一两秒。")
	w("sleep 5")
	for _, s := range p.Verify {
		w("[ \"$(systemctl is-active %s)\" = active ] || fail '%s 没起来'", shq(s), s)
		// NRestarts 是 Service 的属性,Timer 没有 —— 对 timer 查它会拿到
		// 空串,而 [ "" = 0 ] 恒假,于是每次部署都"失败并回滚"。
		if !strings.HasSuffix(s, ".timer") {
			w("[ \"$(systemctl show -p NRestarts --value %s)\" = 0 ] || fail '%s 在重启循环里'", shq(s), s)
		}
	}
	w("rm -rf \"$STAGE\"")
	w("echo '   ✅ %s 完成(run %s)'", p.Node, runID)
	return b.String()
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
