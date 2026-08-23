package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"loom/internal/deploy"
	"loom/internal/netx"
	"loom/internal/publish"
	"loom/internal/render"
	"loom/internal/report"
	"loom/internal/secret"
	"loom/internal/snapshot"
)

// pull 是节点侧的控制通道(§14.2):自己去分发点取配置,而不是等人来推。
//
// 六步,每一步都在**信任更少的东西**:
//
//  1. 取 current.json,拿到快照 id
//  2. 已经装的就是它 → 什么都不做
//  3. 取 manifest 与签名,**用本地钉住的公钥验签**
//  4. 取自己那份配置包,算哈希与 manifest 里的对比
//  5. 用**本机**秘密层填占位符
//  6. 走 apply 的五步:暂存 → 预检 → 就位 → 验证,失败回滚
//
// 第 3、4 步之后,分发点是什么、经过了谁,都不重要了 —— 内容动过一个字节
// 就通不过。所以分发点可以是任意一台机器上的一个静态目录。
//
// 第 5 步在节点上做,是这套设计里最关键的一条:**凭据从不离开它该在的机器**。
func cmdPull(args []string) error {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	url := fs.String("url", "", "分发点根地址(必需)")
	pubPath := fs.String("pubkey", "/etc/loom/trust/platform.pub", "钉住的平台公钥")
	node := fs.String("node", "", "本节点 id(默认取 /etc/loom/node-id)")
	secretsPath := fs.String("secrets", "/etc/loom/secrets/node.env", "本机秘密层")
	statePath := fs.String("state", "/var/lib/loom/applied", "记录已安装的快照 id")
	dnsSrv := fs.String("dns", "", "解析分发点用的 DNS 服务器(留空则用系统解析器)")
	binPath := fs.String("bin", "/usr/local/bin/loom", "本机 Agent 二进制的位置")
	dry := fs.Bool("dry-run", false, "只取和验,不安装")
	timeout := fs.Duration("timeout", 60*time.Second, "取配置的超时")

	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("需要 -url 指向分发点")
	}
	id := *node
	if id == "" {
		b, err := os.ReadFile("/etc/loom/node-id")
		if err != nil {
			return fmt.Errorf("没有 -node,也读不到 /etc/loom/node-id:%w", err)
		}
		id = strings.TrimSpace(string(b))
	}
	// 互斥:定时器触发的那次和手工跑的那次撞在一起,会互相清掉对方的
	// 回滚清单,机器停在装了一半的状态。实测踩过(通过重启 loom-pull
	// 自己套自己),那个具体路径已经堵上了,但用锁把整类问题一并挡住。
	unlock, err := lockPull(*statePath)
	if err != nil {
		return err
	}
	if unlock == nil {
		fmt.Println("另一个 loom pull 正在跑,本次跳过")
		return nil
	}
	defer unlock()

	base := strings.TrimRight(*url, "/")
	c := netx.Client(*dnsSrv, *timeout)

	// 1. 当前快照
	var cur publish.Current
	if err := getJSON(c, base+"/current.json", &cur); err != nil {
		return err
	}
	if cur.Snapshot == "" {
		return fmt.Errorf("current.json 里没有快照 id")
	}

	// 2. 记下之前装的是哪个,但**不因为一样就跳过**。
	//
	// 快照 id 只说明"配置来自哪一版",不说明机器现在是不是那个样子。
	// 靠它早退会让漂移永远修不了 —— cn-b 的 loom-pull.timer 一度是
	// active 但没 enable,重启就没了,而 pull 每次都说"已是最新,无事可做"。
	//
	// 安装脚本本身是幂等的:逐文件比哈希,没变就什么都不做。跑一遍很便宜,
	// 而且顺带把 enable、服务状态这些**不在文件里**的期望状态也拉回来。
	prev, _ := os.ReadFile(*statePath)
	same := strings.TrimSpace(string(prev)) == cur.Snapshot
	fmt.Printf("节点 %s · 分发点给出快照 %s%s\n", id, short(cur.Snapshot),
		map[bool]string{true: "(与本机记录一致,仍要核对机器状态)", false: ""}[same])

	// 3. 验签。**先验签再看内容** —— 顺序反了的话,恶意 manifest 里的
	//    路径和哈希已经影响了后面的行为。
	root := base + "/" + cur.Snapshot
	manBytes, err := getBytes(c, root+"/"+manifestFile)
	if err != nil {
		return err
	}
	sig, err := getBytes(c, root+"/"+sigFile)
	if err != nil {
		return err
	}
	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("读不到钉住的公钥 %s:%w", *pubPath, err)
	}
	if err := snapshot.VerifySignature(manBytes, sig, ed25519.PublicKey(pub)); err != nil {
		return fmt.Errorf("验签失败,拒绝安装:%w", err)
	}
	var man snapshot.Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return err
	}
	if man.ID != cur.Snapshot {
		return fmt.Errorf("current.json 说 %s,manifest 里却是 %s —— 分发点在乱指",
			short(cur.Snapshot), short(man.ID))
	}
	fmt.Printf("  ✅ 验签通过(%d 个节点的包)\n", len(man.Bundles))

	// 3.5 停机指令。**它必须在取配置之前处理** —— 一台正在下线的机器不该
	//     再去装任何东西。
	for _, dead := range man.Decommissioned {
		if dead != id {
			continue
		}
		fmt.Printf("  ⛔ 本节点已被标记下线(指令来自签名过的快照)\n")
		if *dry {
			return nil
		}
		return decommission(id, *statePath)
	}

	// 3.6 二进制。**在配置之前** —— 新版读得懂旧配置,旧版读不懂新配置
	//     (§15.4、D46)。
	// 用 base 不是 root:二进制是**内容寻址**的,放在树的顶层跨快照共享。
	// 回滚到旧快照时旧二进制还在,不用重新下载。
	if swapped, err := upgradeBinary(c, base, &man, *binPath, *dry); err != nil {
		return err
	} else if swapped && !*dry {
		// 换过二进制之后就此结束这一轮:配置交给下一次(几分钟后)。
		// 继续用**当前进程里的旧代码**去装新配置,正是要避免的那种配对。
		fmt.Println("  二进制已更新,配置留给下一轮(几分钟后)")
		return nil
	}

	// 4. 取自己那份,与签名覆盖到的哈希比对
	var d publish.Bundle
	if err := getJSON(c, root+"/nodes/"+id+".json", &d); err != nil {
		return fmt.Errorf("取 %s 的配置包:%w", id, err)
	}
	want := ""
	for _, b := range man.Bundles {
		if b.Owner == id {
			want = b.Hash
		}
	}
	if want == "" {
		// **缺席是歧义的**:可能是被删了,也可能是有人渲染时漏了一个节点。
		// 对歧义信号采取不可逆动作是危险的 —— 所以这里只报错、只告警,
		// 停机要靠 manifest 里那条明确的 decommission(§14.4)。
		return fmt.Errorf("这个签名过的快照里没有 %s 的配置包。"+
			"如果是有意下线,应当先标 decommission 让本机自己停;"+
			"缺席只当作异常处理,本机维持现状不动", id)
	}
	got := bundleHash(d.Files)
	if got != want {
		return fmt.Errorf("配置包哈希对不上(签名说 %s,取到的是 %s),拒绝安装",
			short(want), short(got))
	}
	fmt.Printf("  ✅ 配置包哈希与签名一致(%d 个文件)\n", len(d.Files))

	// 5. 本机填秘密
	secrets, err := secret.Load(*secretsPath)
	if err != nil {
		return fmt.Errorf("读本机秘密层:%w", err)
	}
	hydrated := map[string]string{}
	var allMissing []string
	filled := 0
	for p, content := range d.Files {
		h, missing := secret.Hydrate(content, secrets)
		filled += len(secret.Refs(content)) - len(missing)
		allMissing = append(allMissing, missing...)
		hydrated[p] = h
	}
	if len(allMissing) > 0 {
		sort.Strings(allMissing)
		return fmt.Errorf("本机秘密层缺这些引用,放弃安装:%s", strings.Join(dedupe(allMissing), " "))
	}
	fmt.Printf("  ✅ 本机填入 %d 处秘密\n", filled)

	// 5.5 自检清单。**必须由装文件的这一步产出。**
	//
	// 清单原本只有 `loom hydrate` 会写,而节点自取根本不经过它 —— 于是
	// 每次 pull 之后,机器上的文件更新了而清单没有,配置自检永远误报
	// "被改过"。实测踩过:五台机器同时报 report/config.json 漂移,
	// 而它们装的恰恰是刚发下来的正确版本。
	//
	// 清单不能包含它自己(哈希无法自指),所以最后算、单独塞进去。
	hydrated[manifestBundlePath] = buildManifest(id, hydrated)

	// 6. 安装
	plan, unmapped := deploy.BuildPlan(id, hydrated)
	for _, u := range unmapped {
		fmt.Printf("  ! %s 没有约定的安装位置,不安装\n", u)
	}
	if *dry {
		fmt.Printf("  (dry-run:%d 个文件,涉及 %s)\n", len(plan.Files), strings.Join(plan.Verify, " "))
		return nil
	}
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(deploy.Script(plan, cur.Snapshot))
	cmd.Stdout, cmd.Stderr = prefixWriter{"  "}, prefixWriter{"  "}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("安装失败(已回滚):%w", err)
	}

	if err := os.MkdirAll(filepath.Dir(*statePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(*statePath, []byte(cur.Snapshot+"\n"), 0o644)
}

// bundleHash 必须与 render.Bundle.Hash 完全一致,否则永远对不上。
func bundleHash(files map[string]string) string {
	b := render.Bundle{}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		b.Files = append(b.Files, render.File{Path: p, Content: files[p]})
	}
	return b.Hash()
}

func getBytes(c *http.Client, url string) ([]byte, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s → HTTP %d", url, resp.StatusCode)
	}
	// 上限防止分发点(或中间人)用一个无限流把节点的内存吃光。
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

func getJSON(c *http.Client, url string, into any) error {
	b, err := getBytes(c, url)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

type prefixWriter struct{ p string }

func (w prefixWriter) Write(b []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			fmt.Printf("%s%s\n", w.p, strings.TrimSpace(line))
		}
	}
	return len(b), nil
}

// lockPull 取一把排他锁。拿不到时返回 nil(不是错误)—— 另一个 pull 正在
// 干这件事,本次跳过是正确行为,不该让定时器记一次失败。
func lockPull(statePath string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, nil
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// decommission 执行一条经过认证的停机指令(§14.4)。
//
// 停服务、禁自启,**不销毁任何秘密**。销毁不可逆,而误签一次就全没了 ——
// 它要停,不要自毁。凭据的轮换是人的事,而且必须做:一台下线的服务器手上
// 那些 `cred/...` 是**跨节点共享**的,不轮换就等于留了一把配好的钥匙。
func decommission(node, statePath string) error {
	units := []string{"loom-pull.timer", "loom-agent", "loom-report", "sing-box", "loom-wg-reresolve.timer"}
	// 隧道接口也停:对端已经不再配它了,留着只是徒劳重试。
	if ents, err := os.ReadDir("/etc/wireguard"); err == nil {
		for _, e := range ents {
			if n := strings.TrimSuffix(e.Name(), ".conf"); n != e.Name() && strings.HasPrefix(n, "wg-") {
				units = append(units, "wg-quick@"+n)
			}
		}
	}
	var script strings.Builder
	script.WriteString("set -u\n")
	for _, u := range units {
		fmt.Fprintf(&script, "systemctl disable --now %q 2>/dev/null || true\n", u)
	}
	// 留一份痕迹:下次有人登上来,一眼看得出这台机器是被下线的,
	// 而不是"不知道为什么什么都没跑"。
	fmt.Fprintf(&script, "mkdir -p %q\n", filepath.Dir(statePath))
	fmt.Fprintf(&script, "printf '%%s\\n' '本节点已下线(decommission),服务已停并禁用自启。' > %q\n",
		filepath.Dir(statePath)+"/DECOMMISSIONED")
	fmt.Fprintf(&script, "rm -f %q\n", statePath)

	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script.String())
	cmd.Stdout, cmd.Stderr = prefixWriter{"  "}, prefixWriter{"  "}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("停机过程出错:%w", err)
	}
	fmt.Printf("  已停止并禁用:%s\n", strings.Join(units, " "))
	fmt.Printf("  **秘密未销毁**(不可逆的事不自动做)。这台机器上还有:\n")
	fmt.Printf("    /etc/loom/secrets/node.env   ← 里面的凭据是跨节点共享的,必须轮换\n")
	fmt.Printf("    /etc/wireguard/node.key      ← 对端已不再配它,实际已失效\n")
	fmt.Printf("    /etc/loom/tls/node.key       ← 应当从内部 CA 吊销\n")
	return nil
}

// manifestBundlePath 是自检清单在配置包里的位置。它映射到
// render.ManifestPath,由 render.InstallPath 决定实际落点。
const manifestBundlePath = "report/manifest.json"

// buildManifest 按将要安装的内容算出自检清单。
func buildManifest(node string, files map[string]string) string {
	m := report.Manifest{Node: node, Files: map[string]string{}}
	for bundlePath, content := range files {
		if bundlePath == manifestBundlePath {
			continue // 不能包含自己
		}
		abs := render.InstallPath(bundlePath)
		if abs == "" {
			continue // 没有约定安装位置的不进清单(它也不会被安装)
		}
		h := sha256.Sum256([]byte(content))
		m.Files[abs] = hex.EncodeToString(h[:])
	}
	b, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		// Manifest 全是具体类型,序列化不会失败。
		return "{}"
	}
	return string(b) + "\n"
}
