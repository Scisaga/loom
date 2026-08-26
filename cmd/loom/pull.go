package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"loom/internal/deploy"
	"loom/internal/model"
	"loom/internal/netx"
	"loom/internal/publish"
	"loom/internal/render"
	"loom/internal/report"
	"loom/internal/rollout"
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
func cmdPull(args []string) (retErr error) {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	rolloutPath := fs.String("rollout", rollout.Path,
		"记 rollout 阶段的地方 —— 只记录,不改变行为(D78)")
	url := fs.String("url", "", "分发点根地址(必需)")
	pubPath := fs.String("pubkey", "/etc/loom/trust/platform.pub", "钉住的平台公钥")
	node := fs.String("node", "", "本节点 id(默认取 /etc/loom/node-id)")
	secretsPath := fs.String("secrets", "/etc/loom/secrets/node.env", "本机秘密层")
	statePath := fs.String("state", "/var/lib/loom/applied", "记录已安装的快照 id")
	deployLockPath := fs.String("deploy-lock", deploy.DeployLockPath,
		"串行化本机 apply/pull 的部署锁")
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
	if !model.ValidNodeID(id) {
		return fmt.Errorf("本节点 id %q 格式非法", id)
	}
	continuation, err := continuationReporterFromEnv()
	if err != nil {
		return err
	}
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
	if err := continuation.requireSnapshot(cur.Snapshot); err != nil {
		return err
	}

	fmt.Printf("节点 %s · 分发点给出快照 %s\n", id, short(cur.Snapshot))

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
	decommissioned := false
	for _, dead := range man.Decommissioned {
		if dead == id {
			decommissioned = true
			break
		}
	}

	// 大二进制的网络读取可能被慢分发点无限续命，不能占住 deploy.lock。
	// 验签后先在锁外下载到与 live binary 同目录的唯一临时文件、验哈希并
	// selfcheck；锁内只重读 live hash、rename、重启和复核进程 inode。
	// 下线节点完全不需要预取，必须优先执行签名过的 decommission 指令。
	var binaryCandidate *binaryUpgradeCandidate
	if !decommissioned {
		binaryCandidate, err = prepareBinaryUpgrade(c, base, &man, *binPath, *dry)
		if err != nil {
			return err
		}
		defer binaryCandidate.cleanup()
	}

	// 从这一刻开始，后面的每一步都会改变本机状态：decommission、二进制、
	// 配置和 applied 必须处在同一把 deploy.lock 里。网络下载、验签与二进制
	// 候选自检在锁外；进入锁后不再让不可信大流量阻塞人工 apply。
	var transactionLock *nodeDeployLock
	if !*dry {
		if continuation != nil {
			transactionLock, err = inheritNodeDeployLock(*deployLockPath)
			if err != nil {
				return fmt.Errorf("续跑没有继承有效的部署锁:%w", err)
			}
		} else {
			var busy bool
			transactionLock, busy, err = acquireNodeDeployLock(*deployLockPath)
			if err != nil {
				return fmt.Errorf("取得部署锁:%w", err)
			}
			if busy {
				// 这是正常互斥，不是一次失败 rollout；本轮尚未读取或改写
				// applied/rollout，也不会留下 Staging 冒充卡住。
				fmt.Println("另一个 apply/pull 正持有部署锁,本次跳过")
				return nil
			}
		}
		defer transactionLock.Close()
	}

	// applied 与 rollout 是部署事务坐标，必须在 deploy.lock 之后读取。
	// 否则并发 apply 可在锁外读与锁内写之间失效它们，pull 随后却拿 stale
	// Verified 当 LastGood 或把真实重装误判成 no-op。
	if *dry {
		*rolloutPath = ""
	}
	var applied string
	var prevRec, rec *rollout.Record
	if !*dry {
		applied, prevRec, err = readPullCoordinates(*statePath, *rolloutPath)
		if err != nil {
			return err
		}
		if shouldTrackRollout(prevRec, cur.Snapshot, applied) {
			rec = rollout.Begin(prevRec, cur.Snapshot, "", time.Now())
		}
	}
	saveRec := func() {
		if rec == nil {
			return
		}
		if err := rec.Write(*rolloutPath); err != nil {
			fmt.Printf("  ! 写 rollout 状态失败:%v(不影响安装)\n", err)
		}
	}
	enterRec := func(stage rollout.Stage) {
		if rec != nil {
			rec.Enter(stage, time.Now())
			saveRec()
		}
	}
	defer func() {
		if retErr != nil && !*dry && *rolloutPath != "" {
			// 同快照 no-op 失败也必须懒开 Failed，不能留下旧 Verified 假绿。
			rec = failRollout(rec, prevRec, cur.Snapshot, retErr, time.Now())
			saveRec()
		}
	}()
	saveRec()

	// 快照 id 只说明配置来自哪一版，不说明机器现在是不是那个样子。即使
	// applied 相同也继续核对 enabled/active/NRestarts；可安全恢复的漂移
	// 会收敛，failed/过渡态等无法精确回退的状态则失败关闭并落 Failed。
	same := applied == cur.Snapshot
	if same {
		fmt.Println("  本机记录相同，仍核对文件与服务状态")
	}

	// 3.5 停机指令。**它必须在取配置之前处理** —— 一台正在下线的机器不该
	//     再去装任何东西。
	if decommissioned {
		fmt.Printf("  ⛔ 本节点已被标记下线(指令来自签名过的快照)\n")
		if *dry {
			return nil
		}
		if err := decommission(id, *statePath); err != nil {
			return err
		}
		enterRec(rollout.Decommissioned)
		return nil
	}

	// 3.6 二进制。**在配置之前** —— 新版读得懂旧配置,旧版读不懂新配置
	//     (§15.4、D46)。
	// 用 base 不是 root:二进制是**内容寻址**的,放在树的顶层跨快照共享。
	// 回滚到旧快照时旧二进制还在,不用重新下载。
	enterRec(rollout.Activating)
	if swapped, err := activateBinary(binaryCandidate, *binPath, *dry); err != nil {
		return err
	} else if swapped && !*dry {
		if rec != nil {
			rec.Binary = binarySHA(&man)
			saveRec()
		}
		// **用新二进制续跑同一个快照,不等下一个定时器**(D80)。
		//
		// 安全原则没变:继续用当前进程里的**旧代码**去装新配置,正是要
		// 避免的那种配对。变的只是怎么实现它 —— 以前靠"就此 return,
		// 10 分钟后 timer 再来一次",实测那个空档是 10 分 11 秒。
		// 现在把剩下的活交给刚装好的那个二进制,立刻。
		status, err := continuePull(*binPath, args, cur.Snapshot, transactionLock)
		if err != nil {
			return handleContinuationFailure(*binPath, status, err, restorePreviousBinary)
		}
		// 子进程已经把记录写到 verified 了。父进程别拿自己那份停在
		// activating 的旧记录覆盖回去 —— 清空路径让 defer 变成 no-op。
		*rolloutPath = ""
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
	// 删除收敛(dpkg 模型):上次装了、这次不装了的,清掉。
	//
	// SSOT 里删掉一条隧道之后,渲染输出里就没那个 wg-xxx.conf 了,但节点
	// 上的文件和 wg-quick@xxx 服务都还在跑 —— 以为删了,实际还连着。
	manifestPath := render.InstallPath(manifestBundlePath)
	inventory, err := readApplyInventory(id, "", true, 0, manifestPath)
	if err != nil {
		// 存在但损坏/不可读的清单不能再按“空清单”继续：本轮若覆盖掉它，
		// 上一轮 installed 集合会永久丢失，旧隧道也就再没有收敛依据。
		return fmt.Errorf("读本机安装清单失败,拒绝覆盖并保留删除依据:%w", err)
	}
	bindInstalledInventory(plan, inventory, manifestPath)
	if inventory.absent {
		fmt.Println("  首次安装:本机尚无 installed 清单")
	}
	for _, r := range plan.Remove {
		fmt.Printf("  - 不再声明,将清掉:%s\n", r)
	}
	if *dry {
		fmt.Printf("  (dry-run:%d 个文件,涉及 %s)\n", len(plan.Files), strings.Join(plan.Verify, " "))
		return nil
	}
	if err := continuation.mark(continuationConfiguring); err != nil {
		return fmt.Errorf("记录续跑进入配置事务:%w", err)
	}
	cmd := exec.Command("sh", "-s")
	lockFD, err := transactionLock.inheritTo(cmd)
	if err != nil {
		return fmt.Errorf("把部署锁传给安装 shell:%w", err)
	}
	cmd.Stdin = strings.NewReader(deploy.ScriptWithInheritedLock(plan, cur.Snapshot, lockFD))
	cmd.Stdout, cmd.Stderr = prefixWriter{"  "}, prefixWriter{"  "}
	if err := cmd.Run(); err != nil {
		if exitCode(err) == deploy.RollbackIncompleteExitCode {
			return fmt.Errorf("安装失败且回滚不完整，active 标记与材料已保留:%w", err)
		}
		return fmt.Errorf("安装失败:%w", err)
	}
	if err := continuation.mark(continuationCommitted); err != nil {
		// 配置已经完整安装并验证。即使阶段记录写失败，也必须让父进程按
		// unknown/configuring 保留新二进制，不能倒退成旧代码 + 新配置。
		return fmt.Errorf("配置已提交，但记录续跑提交阶段失败:%w", err)
	}

	// 安装脚本自己带验证(plan.Verify),跑到这里说明那一步过了。
	enterRec(rollout.Verifying)

	if err := os.MkdirAll(filepath.Dir(*statePath), 0o755); err != nil {
		return err
	}
	if err := writeStateAtomic(*statePath, []byte(cur.Snapshot+"\n"), 0o644); err != nil {
		return err
	}
	// **写完 applied 才算 Verified。** 装上了不算,记下来了才算 ——
	// 否则回退目标会指向一份 applied 里根本没有的快照。
	enterRec(rollout.Verified)
	return nil
}

// readPullCoordinates 的调用方必须已经持有 deploy.lock。单独拆成函数是为
// 了让并发回归测试钉住顺序：manual apply 失效 applied/rollout 后，pull
// 只能在拿到同一把锁之后读到新坐标，不能复用锁外缓存。
func readPullCoordinates(statePath, rolloutPath string) (string, *rollout.Record, error) {
	prev, err := os.ReadFile(statePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", nil, fmt.Errorf("持锁读取 applied:%w", err)
	}
	rec, err := rollout.Read(rolloutPath)
	if err != nil {
		return "", nil, fmt.Errorf("持锁读取 rollout:%w", err)
	}
	return strings.TrimSpace(string(prev)), rec, nil
}

// shouldTrackRollout 区分发布与普通 reconcile。
//
// 相同 applied 的健康终态不产生新记录；失败/半途退出的同目标重试仍是一
// 次有意义的恢复尝试。旧目标留下的失败要由当前快照 reconcile 收口。
func shouldTrackRollout(prev *rollout.Record, target, applied string) bool {
	if target != applied {
		return true
	}
	if prev == nil {
		return false
	}
	// 只有“这份当前快照已经成功过”能证明本轮只是 no-op。旧目标的失败/
	// 半途记录必须通过一次当前快照 reconcile 收口，否则 Status 会永久报坏。
	return prev.Snapshot != target || prev.Stage != rollout.Verified
}

func failRollout(rec, prev *rollout.Record, target string, err error, now time.Time) *rollout.Record {
	if err == nil {
		return rec
	}
	if rec == nil {
		rec = rollout.Begin(prev, target, "", now)
	}
	rec.Fail(err, now)
	return rec
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

// blobStall 是“多久没有新字节到”；另有按签名 size 算出的硬总时限。
//
// 原来二进制走的是跟 manifest 同一个客户端 —— 一个 60 秒的**总时长**上限。
// 12.3 MB 配 60 秒等于要求全程持续 205 KB/s,而本次实测二跳吞吐只有
// 244–273 KB/s,贴着线跑。edge-a 就是这么失败的:
//
//	错误:下载二进制:context deadline exceeded ... while reading body
//
// 而失败的后果不是"这次没升上",是**这台机器停在半路**:配置留给下一轮的
// 两段式意味着它既没换成新的,也不确定下一轮能不能换成。
//
// 慢不是故障,但每 44 秒滴一个字节也不能永久占住 loom-pull.service，
// 否则后续配置和 decommission 永远没有机会被读取。总时限按 32 KiB/s 的
// 保守下限估算，再加一个 stall 余量，并夹在 2–20 分钟之间。
const (
	blobStall        = 45 * time.Second
	blobMinimumRate  = int64(32 << 10)
	blobTotalMinimum = 2 * time.Minute
	blobTotalMaximum = 20 * time.Minute
)

func blobTotalTimeout(size int64) time.Duration {
	if size < 0 {
		size = 0
	}
	seconds := size / blobMinimumRate
	if size%blobMinimumRate != 0 {
		seconds++
	}
	maxSeconds := int64((blobTotalMaximum - blobStall) / time.Second)
	if seconds >= maxSeconds {
		return blobTotalMaximum
	}
	total := time.Duration(seconds)*time.Second + blobStall
	if total < blobTotalMinimum {
		return blobTotalMinimum
	}
	if total > blobTotalMaximum {
		return blobTotalMaximum
	}
	return total
}

// getBlob 取大块内容(二进制)。与 getBytes 的区别在于同时使用停顿时限和
// 按签名大小推导的较宽总时限。stall 由调用方给,是为了测试能把它调短。
func getBlob(c *http.Client, url string, max int64, stall time.Duration) ([]byte, error) {
	return getBlobWithLimits(c, url, max, stall, blobTotalTimeout(max))
}

func getBlobWithLimits(c *http.Client, url string, max int64, stall, total time.Duration) ([]byte, error) {
	if max <= 0 || stall <= 0 || total <= 0 {
		return nil, fmt.Errorf("非法 blob 下载限制:max=%d stall=%s total=%s", max, stall, total)
	}
	nc := *c       // 复用 Transport —— 里面有不读 HTTP_PROXY、自带 DNS 的设置
	nc.Timeout = 0 // 总时限由下面按签名 size 推导的 context 统一控制

	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := nc.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("下载在响应前超过按签名大小计算的总时限 %s", total)
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s → HTTP %d", url, resp.StatusCode)
	}

	var stalled atomic.Bool
	t := time.AfterFunc(stall, func() { stalled.Store(true); cancel() })
	defer t.Stop()

	b, err := io.ReadAll(&stallReader{r: io.LimitReader(resp.Body, max), t: t, d: stall})
	if err != nil && stalled.Load() {
		return nil, fmt.Errorf("下了 %.1f MB 之后卡住,%s 没有新字节", float64(len(b))/(1<<20), stall)
	}
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("下载超过按签名大小计算的总时限 %s(已收 %.1f MB)", total, float64(len(b))/(1<<20))
	}
	return b, err
}

// stallReader 每读到字节就把停顿计时器续上。读不到就不续 —— 计时器到点
// 取消掉整个请求。
type stallReader struct {
	r io.Reader
	t *time.Timer
	d time.Duration
}

func (s *stallReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.t.Reset(s.d)
	}
	return n, err
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

const deployLockFDEnv = "LOOM_DEPLOY_LOCK_FD"

// nodeDeployLock 是 apply 脚本和 pull 共用的 DeployLockPath。inherited 表示
// fd 来自续跑父进程：关闭自己的副本即可，不能 LOCK_UN（flock 绑定的是
// 共享 open file description，子进程 unlock 会把仍在 wait 的父进程也解锁）。
type nodeDeployLock struct {
	file      *os.File
	path      string
	inherited bool
}

// acquireNodeDeployLock 的 busy 不是错误：timer 与手工 pull/apply 撞车时，
// 已持锁的事务负责收敛，本轮什么都没碰，安静跳过即可。其他 flock 错误必须
// fail-closed，不能一律冒充“有人在跑”。
func acquireNodeDeployLock(path string) (lock *nodeDeployLock, busy bool, err error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, false, fmt.Errorf("部署锁路径必须是绝对路径:%q", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return &nodeDeployLock{file: f, path: path}, false, nil
}

// inheritNodeDeployLock 只接受与 path 指向同一 inode、且确实持有 flock 的
// fd。单凭环境变量不能绕过互斥；这是 continuation 继承通道的一部分。
func inheritNodeDeployLock(path string) (*nodeDeployLock, error) {
	raw := os.Getenv(deployLockFDEnv)
	fd, err := strconv.Atoi(raw)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("%s=%q 无效", deployLockFDEnv, raw)
	}
	f := os.NewFile(uintptr(fd), "loom-deploy-lock")
	if f == nil {
		return nil, fmt.Errorf("继承 fd %d 失败", fd)
	}
	bad := func(err error) (*nodeDeployLock, error) {
		_ = f.Close()
		return nil, err
	}
	inheritedInfo, err := f.Stat()
	if err != nil {
		return bad(err)
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		return bad(err)
	}
	if !inheritedInfo.Mode().IsRegular() || !os.SameFile(inheritedInfo, pathInfo) {
		return bad(fmt.Errorf("fd %d 不是 %s", fd, path))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return bad(fmt.Errorf("fd %d 没持有部署锁:%w", fd, err))
	}
	return &nodeDeployLock{file: f, path: path, inherited: true}, nil
}

// inheritTo 把同一 open file description 交给子进程，并返回子进程里对应
// 的 fd。ExtraFiles 从 3 起按顺序排列；环境变量供新版 continuation 采用，
// 安装 shell 则把返回值直接嵌进 ScriptWithInheritedLock。
func (l *nodeDeployLock) inheritTo(cmd *exec.Cmd) (int, error) {
	if l == nil || l.file == nil {
		return 0, fmt.Errorf("部署事务没有持锁")
	}
	if _, err := l.file.Stat(); err != nil {
		return 0, err
	}
	fd := 3 + len(cmd.ExtraFiles)
	cmd.ExtraFiles = append(cmd.ExtraFiles, l.file)
	base := cmd.Env
	if base == nil {
		base = os.Environ()
	}
	prefix := deployLockFDEnv + "="
	env := make([]string, 0, len(base)+1)
	for _, item := range base {
		if !strings.HasPrefix(item, prefix) {
			env = append(env, item)
		}
	}
	cmd.Env = append(env, prefix+strconv.Itoa(fd))
	return fd, nil
}

func (l *nodeDeployLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	// 不显式 LOCK_UN：continuation/shell 持有同一 open file description 的
	// 继承副本，父进程 unlock 会把它们也一起解锁。只 close 自己的 fd，
	// 内核会在最后一个继承副本关闭时自动释放 flock。
	return l.file.Close()
}

// decommission 执行一条经过认证的停机指令(§14.4)。
//
// 停服务、禁自启,**不销毁任何秘密**。销毁不可逆,而误签一次就全没了 ——
// 它要停,不要自毁。凭据的轮换是人的事,而且必须做:一台下线的服务器手上
// 那些 `cred/...` 是**跨节点共享**的,不轮换就等于留了一把配好的钥匙。
func decommission(node, statePath string) error {
	ctl := func(args ...string) (string, error) {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	// 配置文件只是 Loom 管理过哪些隧道的一份证据，不是唯一证据。文件可能
	// 已被人工删掉而 unit/内核接口仍活着；installed manifest 与 systemd
	// 的 loaded/enabled 集合都要参与发现，任何查询不确定都必须在写 marker、
	// 清 applied、关闭 pull.timer 之前失败。
	inventory, err := readApplyInventory(node, "", true, 0, render.ManifestPath)
	if err != nil {
		return fmt.Errorf("读取下线用安装清单:%w", err)
	}
	units, err := decommissionWithDiscovery(statePath, "/etc/wireguard", inventory.files, ctl)
	if err != nil {
		return fmt.Errorf("停机过程未完整收敛:%w", err)
	}
	fmt.Printf("  已停止并禁用:%s\n", strings.Join(units, " "))
	fmt.Printf("  **秘密未销毁**(不可逆的事不自动做)。这台机器上还有:\n")
	fmt.Printf("    /etc/loom/secrets/node.env   ← 里面的凭据是跨节点共享的,必须轮换\n")
	fmt.Printf("    /etc/wireguard/node.key      ← 对端已不再配它,实际已失效\n")
	fmt.Printf("    /etc/loom/tls/node.key       ← 应当从内部 CA 吊销\n")
	return nil
}

type systemctlFunc func(args ...string) (string, error)

// decommissionWithDiscovery 先完成只读发现，再进入状态切换。发现阶段失败时
// decommissionWith 根本不会被调用，因此不会写 DECOMMISSIONED、清 applied
// 或触碰 pull.timer。
func decommissionWithDiscovery(statePath, wireguardDir string, installed []string, ctl systemctlFunc) ([]string, error) {
	units, err := decommissionUnits(wireguardDir, installed, ctl)
	if err != nil {
		return nil, err
	}
	if err := decommissionWith(statePath, units, ctl); err != nil {
		return nil, err
	}
	return units, nil
}

// decommissionUnits 把 pull.timer 固定放最后。待停 WG 集合取三份证据的并集：
// 当前配置目录、上次安装 inventory、systemd 当前 loaded/enabled unit。只看
// 配置文件会漏掉“文件已经丢了、接口仍在”的暗连；systemd 查询失败则无法
// 证明集合完整，必须 fail-closed。
func decommissionUnits(wireguardDir string, installed []string, ctl systemctlFunc) ([]string, error) {
	units := []string{"loom-agent", "loom-report", "loom-publisher", "sing-box",
		"loom-wg-reresolve.service", "loom-wg-reresolve.timer"}
	tunnelSet := map[string]bool{}
	addIface := func(iface, source string) error {
		if !strings.HasPrefix(iface, "wg-") || !model.ValidNodeID(strings.TrimPrefix(iface, "wg-")) {
			return fmt.Errorf("%s 给出非 Loom WireGuard 接口 %q", source, iface)
		}
		tunnelSet["wg-quick@"+iface] = true
		return nil
	}
	addUnit := func(unit, source string) error {
		unit = strings.TrimSuffix(unit, ".service")
		if !strings.HasPrefix(unit, "wg-quick@") {
			return fmt.Errorf("%s 给出非 wg-quick unit %q", source, unit)
		}
		return addIface(strings.TrimPrefix(unit, "wg-quick@"), source)
	}

	ents, err := os.ReadDir(wireguardDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("枚举待停隧道:%w", err)
	}
	for _, e := range ents {
		if n := strings.TrimSuffix(e.Name(), ".conf"); n != e.Name() && strings.HasPrefix(n, "wg-") {
			if err := addIface(n, wireguardDir); err != nil {
				return nil, err
			}
		}
	}
	for _, abs := range installed {
		switch {
		case filepath.Dir(abs) == "/etc/wireguard" && strings.HasSuffix(filepath.Base(abs), ".conf") &&
			strings.HasPrefix(filepath.Base(abs), "wg-"):
			if err := addIface(strings.TrimSuffix(filepath.Base(abs), ".conf"), "installed manifest"); err != nil {
				return nil, err
			}
		case filepath.Dir(abs) == "/etc/systemd/system" &&
			strings.HasPrefix(filepath.Base(abs), "wg-quick@wg-") && strings.HasSuffix(abs, ".service"):
			if err := addUnit(filepath.Base(abs), "installed manifest"); err != nil {
				return nil, err
			}
		}
	}

	queries := [][]string{
		{"list-units", "--all", "--plain", "--no-legend", "--no-pager", "wg-quick@wg-*.service"},
		{"list-unit-files", "--no-legend", "--no-pager", "wg-quick@wg-*.service"},
	}
	for _, args := range queries {
		out, err := ctl(args...)
		if err != nil {
			return nil, fmt.Errorf("systemd %s 无法枚举 Loom WireGuard 单元:%v(%s)", args[0], err, out)
		}
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if err := addUnit(fields[0], "systemd "+args[0]); err != nil {
				return nil, err
			}
		}
	}

	tunnels := make([]string, 0, len(tunnelSet))
	for unit := range tunnelSet {
		tunnels = append(tunnels, unit)
	}
	sort.Strings(tunnels)
	units = append(units, tunnels...)
	return append(units, "loom-pull.timer"), nil
}

func decommissionWith(statePath string, units []string, ctl systemctlFunc) error {
	if len(units) == 0 || units[len(units)-1] != "loom-pull.timer" {
		return fmt.Errorf("停机序列必须把 loom-pull.timer 放最后")
	}
	var failed []error
	for _, unit := range units[:len(units)-1] {
		if err := convergeUnitOff(unit, ctl); err != nil {
			failed = append(failed, err)
		}
	}
	if len(failed) > 0 {
		return errors.Join(failed...)
	}

	// 在关闭最后的自修复入口前准备好状态切换；任何这里的文件错误都不会
	// 影响 pull.timer。若 timer 自己收敛失败，再恢复坐标并重新 enable。
	applied, readErr := os.ReadFile(statePath)
	appliedExists := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("备份 applied:%w", readErr)
	}
	marker := filepath.Join(filepath.Dir(statePath), "DECOMMISSIONED")
	markerBody := []byte("本节点已下线(decommission),服务已停并禁用自启。\n")
	if err := writeStateAtomic(marker, markerBody, 0o644); err != nil {
		return fmt.Errorf("写下线标记:%w", err)
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(marker)
		return fmt.Errorf("清 applied:%w", err)
	}

	timer := units[len(units)-1]
	if err := convergeUnitOff(timer, ctl); err != nil {
		markerRemoveErr := os.Remove(marker)
		if errors.Is(markerRemoveErr, os.ErrNotExist) {
			markerRemoveErr = nil
		}
		var restoreErr error
		if appliedExists {
			restoreErr = writeStateAtomic(statePath, applied, 0o644)
		}
		enableOut, enableErr := ctl("enable", "--now", timer)
		enabled, enabledErr := ctl("is-enabled", timer)
		active, activeErr := ctl("is-active", timer)
		if markerRemoveErr != nil || restoreErr != nil || enableErr != nil ||
			enabledErr != nil || enabled != "enabled" || activeErr != nil || active != "active" {
			return fmt.Errorf("%s 停用失败:%v；恢复 marker/applied/timer 也不完整:"+
				"marker=%v applied=%v enable=%v(%s) enabled=%q/%v active=%q/%v",
				timer, err, markerRemoveErr, restoreErr, enableErr, enableOut,
				enabled, enabledErr, active, activeErr)
		}
		return fmt.Errorf("%s 停用失败，已恢复 applied 并重新启用 timer:%w", timer, err)
	}
	return nil
}

func convergeUnitOff(unit string, ctl systemctlFunc) error {
	load, loadErr := ctl("show", "-p", "LoadState", "--value", unit)
	if loadErr != nil || (load != "loaded" && load != "not-found") {
		return fmt.Errorf("查询 %s LoadState=%q:%v", unit, load, loadErr)
	}

	// LoadState=not-found 只说明磁盘上的 unit 定义不在，不证明进程已经停、
	// enablement 已清。被删掉 unit 文件的 loaded 进程或 dangling wants symlink
	// 都可能继续留下暗连；active 与 enabled 必须各自查询、各自收敛。
	activeBefore, activeBeforeErr := ctl("is-active", unit)
	needsStop := false
	switch activeBefore {
	case "active", "activating", "deactivating", "reloading":
		needsStop = true
	case "inactive", "failed":
		// 已无运行进程；systemctl 对这些明确状态通常返回非零，文本仍是事实。
	case "unknown":
		return fmt.Errorf("%s LoadState=%s 但 active 状态 unknown:%v", unit, load, activeBeforeErr)
	default:
		return fmt.Errorf("无法确认 %s 原 active 状态=%q:%v", unit, activeBefore, activeBeforeErr)
	}
	if activeBefore == "active" && activeBeforeErr != nil {
		return fmt.Errorf("查询 %s active 状态=%q:%v", unit, activeBefore, activeBeforeErr)
	}
	if needsStop {
		if out, err := ctl("stop", unit); err != nil {
			return fmt.Errorf("停止 %s:%v(%s)", unit, err, out)
		}
		active, activeErr := ctl("is-active", unit)
		if active != "inactive" && active != "failed" {
			return fmt.Errorf("%s stop 后是 %q，不是 inactive/failed:%v", unit, active, activeErr)
		}
	}

	enabledBefore, enabledBeforeErr := ctl("is-enabled", unit)
	switch enabledBefore {
	case "enabled", "linked", "alias":
		if enabledBeforeErr != nil {
			return fmt.Errorf("查询 %s enabled 状态=%q:%v", unit, enabledBefore, enabledBeforeErr)
		}
		if out, err := ctl("disable", unit); err != nil {
			return fmt.Errorf("禁用 %s:%v(%s)", unit, err, out)
		}
	case "enabled-runtime", "linked-runtime":
		if enabledBeforeErr != nil {
			return fmt.Errorf("查询 %s enabled 状态=%q:%v", unit, enabledBefore, enabledBeforeErr)
		}
		if out, err := ctl("disable", "--runtime", unit); err != nil {
			return fmt.Errorf("运行时禁用 %s:%v(%s)", unit, err, out)
		}
	case "disabled", "static", "indirect", "generated", "transient", "masked", "masked-runtime", "not-found":
		// 已经不会自启，不做多余 mutation；下面仍统一复核。
	default:
		return fmt.Errorf("无法确认 %s 原 enabled 状态=%q:%v", unit, enabledBefore, enabledBeforeErr)
	}
	enabled, _ := ctl("is-enabled", unit)
	switch enabled {
	case "disabled", "static", "indirect", "generated", "transient", "masked", "masked-runtime", "not-found":
		return nil
	default:
		return fmt.Errorf("%s disable 后仍是 %q", unit, enabled)
	}
}

func writeStateAtomic(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".loom-state-*")
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
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	ok = true
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
