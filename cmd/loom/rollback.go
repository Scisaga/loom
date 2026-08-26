package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"loom/internal/netx"
	"loom/internal/publish"
	"loom/internal/snapshot"
)

// cmdRollback 把整份系统退回某个历史快照(§12.1、§15.4)。
//
// **它同时动源头和二进制,而这正是它存在的理由。** `loom pin` 只管二进制,
// 配置那一半原来只能回滚"上一次 apply"。两半分开回滚会得到 §15.4 明确要防
// 的那个组合:旧二进制配新配置,或者反过来。
//
// 做法上它刻意**不**引入"冻住分发点"这种粘性覆盖:源头一旦退回去,发布器
// 每 30 秒一轮的收敛机制自己就会把线上带回那个快照(D33、D39)。少一个
// 需要有人记得解除的状态,就少一个"我改了但没生效"的来源。
//
// 自证是这条命令的关键:源头与二进制取回本地之后**重算一遍快照 id**,
// 算出来必须还是 X。渲染是纯函数(§12),所以这条等式成立;不成立就说明
// 这个快照里还有别的东西没跟着回去,当场报出来而不是发一份"看起来回滚了"
// 的配置。
func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	ssotPath := fs.String("ssot", "", "要写回的 SSOT 路径(默认从 /etc/loom/control.json 读)")
	dir := fs.String("dir", publish.DefaultPinDir, "钉住状态放哪(与 loom pin 同一处)")
	history := fs.String("ssot-history", "deploy/ssot-history", "源头存档目录(中控本地;发布器写在这儿)")
	url := fs.String("url", "", "分发点地址(默认从 control.json 读)")
	pubPath := fs.String("pubkey", "/etc/loom/trust/platform.pub", "验签用的平台公钥")
	dns := fs.String("dns", "", "解析分发点用的 DNS(默认从 control.json 读)")
	reason := fs.String("reason", "", "为什么回滚(必填)")
	dryRun := fs.Bool("dry-run", false, "只取回来验一遍,不写任何东西")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}

	cURL, cDNS, cerr := controlDefaults()
	base := *url
	if base == "" {
		if cerr != nil {
			return cerr
		}
		base = cURL
	}
	if *dns == "" {
		*dns = cDNS
	}
	base = strings.TrimRight(base, "/")

	if *ssotPath == "" {
		p, err := controlSSOTPath()
		if err != nil {
			return err
		}
		*ssotPath = p
	}

	// 不带快照 id:报告现在处在什么状态。
	if len(rest) == 0 {
		return reportRollbackState(*dir, *ssotPath, base, *dns, *history)
	}
	if len(rest) != 1 {
		return fmt.Errorf("只能回滚到一个快照,收到 %d 个", len(rest))
	}
	id := rest[0]
	if !validSnapshotID(id) {
		return fmt.Errorf("快照 id %q 必须是 12 位小写十六进制", id)
	}
	if strings.TrimSpace(*reason) == "" && !*dryRun {
		return fmt.Errorf("要 -reason:回滚会覆盖当前 SSOT,几天后翻到它的人需要知道为什么")
	}

	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	c := netx.Client(*dns, 60*time.Second)

	// 先验签再信里面的任何内容 —— 分发点不需要被信任(D32),而我们接下来
	// 要拿它给出的字节覆盖本机的事实来源。
	manBytes, err := getBytes(c, base+"/"+id+"/"+manifestFile)
	if err != nil {
		return fmt.Errorf("取快照 %s:%w", short(id), err)
	}
	sig, err := getBytes(c, base+"/"+id+"/"+sigFile)
	if err != nil {
		return fmt.Errorf("取签名:%w", err)
	}
	man, err := verifyRequestedSnapshotManifest(id, manBytes, sig, ed25519.PublicKey(pub))
	if err != nil {
		return fmt.Errorf("快照 %s 不可信:%w", short(id), err)
	}
	fmt.Printf("快照 %s(%s,%s)\n", short(id), man.CreatedAt, man.Author)

	// --- 源头 -------------------------------------------------------------
	//
	// 从**中控本地存档**取,不从分发点下载:源头带着 `ssh_port` 这类不下发的
	// 管理平面字段,而分发点在设计上是当作已被攻陷来对待的(D32、D61)。
	//
	// 权威仍然是签了名的 manifest —— 它说了正确的哈希是多少。本地存档只是
	// 字节的来源,拿到之后照样核对。
	sum := man.SSOTSum()
	if sum == "" {
		return fmt.Errorf("快照 %s 的 manifest 里没有 ssot_hash,无法回滚源头", short(id))
	}
	ssotBytes, err := publish.ReadArchivedSSOT(*history, sum)
	if err != nil {
		// 两种情况给的建议不一样,合成一条会把人带偏。
		//
		// 不管哪种,都不退而求其次只回滚二进制:那正好是 §15.4 要防的
		// 半截回滚,而且它会**看起来成功**。
		why := "这份存档的内容与它的哈希对不上 —— 被改过了。"
		if errors.Is(err, os.ErrNotExist) {
			why = "存档里没有这一版:可能这个快照发布于存档启用之前,也可能存档被清理过。"
		}
		return fmt.Errorf("取不到快照 %s 的源头。\n"+
			"  %s\n"+
			"  位置:%s\n"+
			"  SSOT 没有别的版本历史(不在 git,中控界面是覆盖式保存),"+
			"所以只能从 `loom backup` 的备份里取回这一版。\n"+
			"  不会只回滚二进制 —— 那会得到「旧二进制 + 新配置」,正是 §15.4 要防的组合",
			short(id), why, publish.ArchivePath(*history, sum))
	}
	fmt.Printf("  源头   %s(%d 字节,本地存档)✅ 哈希相符\n", shortHash(man.SSOTHash), len(ssotBytes))

	// --- 二进制 -----------------------------------------------------------
	var want *snapshot.BinaryRef
	for i := range man.Binaries {
		if man.Binaries[i].OS == runtime.GOOS && man.Binaries[i].Arch == runtime.GOARCH {
			want = &man.Binaries[i]
		}
	}
	if want == nil {
		return fmt.Errorf("快照 %s 里没有 %s/%s 的二进制", short(id), runtime.GOOS, runtime.GOARCH)
	}
	binBody, err := getBlob(c, base+"/"+want.Path(), int64(want.Size)+1<<20, blobStall)
	if err != nil {
		return fmt.Errorf("下载二进制:%w", err)
	}
	if got := hexOf(binBody); got != want.SHA256 {
		return fmt.Errorf("二进制哈希对不上(签名说 %s,实际 %s)", short(want.SHA256), short(got))
	}
	// 真跑一遍。回滚到一个跑不起来的二进制,等于把退路也堵死(同 D60)。
	stage, cleanup, err := stageSelfcheckBinary(*dir, "rollback", binBody)
	if err != nil {
		return err
	}
	defer cleanup()
	if out, err := exec.Command(stage, "selfcheck").CombinedOutput(); err != nil {
		return fmt.Errorf("这个二进制没通过自检,不回滚:%w\n%s", err, strings.TrimSpace(string(out)))
	}
	fmt.Printf("  二进制 %s(%.1f MB)✅ 哈希相符,自检通过\n",
		short(want.SHA256), float64(want.Size)/(1<<20))

	// --- 自证 -------------------------------------------------------------
	//
	// 拿刚取回来的两样东西在本地重算一遍。渲染是纯函数,所以算出来必须还是
	// X;不是的话,说明这个快照里有东西不由这两样决定,而回滚会留下一个
	// **看起来成功、实际没回去**的系统。
	rebuilt, err := publish.SnapshotID(ssotBytes, map[string][]byte{
		want.OS + "/" + want.Arch: binBody,
	})
	if err != nil {
		return fmt.Errorf("用取回的源头重算快照失败:%w", err)
	}
	if rebuilt != id {
		return fmt.Errorf("自证不通过:用取回的源头与二进制重算得到 %s,而不是 %s。\n"+
			"  回滚会得到一份和目标快照不同的配置,已放弃。\n"+
			"  可能的原因:这个二进制的渲染逻辑与当前不同,或 manifest 里有本机算不出的字段",
			short(rebuilt), short(id))
	}
	fmt.Printf("  ✅ 自证通过:重算得到的仍是 %s\n", short(id))

	if *dryRun {
		fmt.Printf("\n-dry-run:什么都没写。\n")
		fmt.Printf("   真的执行会:覆盖 %s、把二进制钉到 %s\n", *ssotPath, short(id))
		return nil
	}

	p := &publish.Pin{
		Snapshot: id, SHA256: want.SHA256,
		PinnedAt: time.Now().Format(time.RFC3339),
		By:       os.Getenv("SUDO_USER") + os.Getenv("USER"),
		Reason:   "回滚:" + *reason,
	}
	prevPath, prevSize, sourceChanged, err := commitRollbackState(
		*ssotPath, *dir, p, binBody, ssotBytes, writeFileAtomicDurable)
	if err != nil {
		return err
	}
	fmt.Printf("\n  当前源头已存到 %s(%d 字节)\n", prevPath, prevSize)
	fmt.Printf("  二进制已钉到 %s\n", short(id))
	if sourceChanged {
		fmt.Printf("  源头已退回 %s\n", *ssotPath)
	} else {
		fmt.Printf("  源头本来就是这一版,不改动\n")
	}

	fmt.Printf("\n✅ 已回滚到 %s。发布器下一轮(约 30 秒)会自己收敛过去,不用手工发布。\n", short(id))
	fmt.Printf("   节点每 45 秒检查、最多 15 秒抖动；二进制升级会在同一轮 continuation 完成,正常目标 90 秒内。\n")
	fmt.Printf("\n   往前走的时候两件事都要做,只做一件会留下半截状态:\n")
	fmt.Printf("     1. 改 SSOT(%s;回滚前那一版存在 %s)\n", *ssotPath, prevPath)
	fmt.Printf("     2. loom pin -clear -dir %s\n", *dir)
	return nil
}

type atomicFileWriter func(string, []byte, os.FileMode) error

// commitRollbackState 把 rollback 的两个授权输入放在同一把
// publish.lock 下提交。顺序必须是 pin → SSOT：中间失败时，
// publisher 会因 pin/snapshot 不匹配而 fail-closed；反过来则可能把
// 目标源头与当前新二进制真正发出去。
func commitRollbackState(ssotPath, pinDir string, pin *publish.Pin, binBody, targetSSOT []byte, writeAtomic atomicFileWriter) (prevPath string, prevSize int, sourceChanged bool, retErr error) {
	err := withPublishTransactionLock(func() error {
		prev, err := os.ReadFile(ssotPath)
		if err != nil {
			return fmt.Errorf("读当前 SSOT:%w", err)
		}
		if err := os.MkdirAll(pinDir, 0o755); err != nil {
			return err
		}
		prevPath = filepath.Join(pinDir, "ssot.prev.yaml")
		if err := writeAtomic(prevPath, prev, 0o644); err != nil {
			return fmt.Errorf("存当前 SSOT:%w", err)
		}
		prevSize = len(prev)

		// 先安装粘性安全门。即使随后 SSOT 写失败，发布器
		// 也只会报“钉住快照与当前源头不匹配”，不会混发。
		if err := publish.WritePin(pinDir, pin, binBody); err != nil {
			return fmt.Errorf("安装回滚 pin:%w", err)
		}
		if hexOf(prev) == hexOf(targetSSOT) {
			return nil
		}
		sourceChanged = true
		if err := writeAtomic(ssotPath, targetSSOT, 0o644); err != nil {
			return fmt.Errorf("目标二进制已安全钉住，但 SSOT 原子替换失败；publisher 会保持阻断:%w", err)
		}
		return nil
	})
	if err != nil {
		return prevPath, prevSize, sourceChanged, err
	}
	return prevPath, prevSize, sourceChanged, nil
}

// reportRollbackState 说清楚现在处在不处在回滚状态。
//
// 不带参数运行时的输出比命令本身更常被人看到 —— 回滚是个粘性状态,
// 而看不见的粘性状态就是陷阱(D58、D60 的同一条道理)。
func reportRollbackState(dir, ssotPath, base, dns, history string) error {
	p, _, err := publish.ReadPin(dir)
	if err != nil {
		return err
	}
	served := ""
	if resp, err := getBytes(netx.Client(dns, 15*time.Second), base+"/current.json"); err == nil {
		var cur struct {
			Snapshot string `json:"snapshot"`
		}
		if json.Unmarshal(resp, &cur) == nil {
			served = cur.Snapshot
		}
	}
	if served != "" {
		fmt.Printf("分发点当前提供   %s\n", short(served))
	} else {
		fmt.Printf("分发点当前提供   (问不到)\n")
	}

	// 存档里有几版,决定了"能退回多远"。空存档时这条尤其要说 ——
	// 那意味着回滚现在根本用不了,而不说的话要到需要回滚时才发现。
	n, aerr := countArchived(history)
	switch {
	case aerr != nil:
		fmt.Printf("源头存档         读不到 %s:%v\n", history, aerr)
	case n == 0:
		fmt.Printf("源头存档         ⚠️ %s 里一版都没有 —— 现在回滚不了\n", history)
	default:
		fmt.Printf("源头存档         %d 版(%s)\n", n, history)
	}

	if p == nil {
		fmt.Printf("没有回滚,也没有钉住 —— 发的是本机源头与本机二进制\n")
		return nil
	}
	fmt.Printf("\n⚠️ 钉在快照 %s\n", short(p.Snapshot))
	fmt.Printf("   理由    %s\n", p.Reason)
	fmt.Printf("   钉于    %s  %s\n", p.PinnedAt, p.By)

	// 钉住的快照与源头现在算出来的对不对得上,是这里唯一真正有信息量的一行:
	// 对不上就意味着**旧二进制配着新配置**在发,正是 §15.4 要防的组合。
	body, rerr := os.ReadFile(ssotPath)
	if rerr != nil {
		fmt.Printf("   源头    读不到 %s:%v\n", ssotPath, rerr)
		return nil
	}
	_, binPath, _ := publish.ReadPin(dir)
	bin, berr := os.ReadFile(binPath)
	if berr != nil {
		return nil
	}
	cur, cerr := publish.SnapshotID(body, map[string][]byte{runtime.GOOS + "/" + runtime.GOARCH: bin})
	switch {
	case cerr != nil:
		fmt.Printf("   源头    算不出快照 id:%v\n", cerr)
	case cur == p.Snapshot:
		fmt.Printf("   源头    ✅ 与钉住的快照一致(%s)\n", short(cur))
	default:
		fmt.Printf("\n   ⚠️ 源头已经不是 %s 那一版了(现在算出来是 %s)。\n", short(p.Snapshot), short(cur))
		fmt.Printf("      发出去的是「%s 的二进制 + 当前源头的配置」—— §15.4 要防的正是这个组合。\n", short(p.Snapshot))
		fmt.Printf("      要么把源头也退回去(loom rollback %s),要么解除钉住(loom pin -clear)。\n", short(p.Snapshot))
	}
	return nil
}

// controlSSOTPath 从中控配置里读事实来源在哪。回滚要覆盖它,写错地方
// 等于什么都没做而且不报错。
func controlSSOTPath() (string, error) {
	b, err := os.ReadFile("/etc/loom/control.json")
	if err != nil {
		return "", fmt.Errorf("读不到 /etc/loom/control.json,请用 -ssot 指定源头路径:%w", err)
	}
	var c struct {
		SSOTPath string `json:"ssot_path"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return "", err
	}
	if c.SSOTPath == "" {
		return "", fmt.Errorf("control.json 里没有 ssot_path,请用 -ssot 指定")
	}
	return c.SSOTPath, nil
}

// shortHash 去掉算法前缀再截断。带着 "sha256:" 一起截会只剩五位十六进制,
// 那不足以让人把两个哈希区分开 —— 而这行输出的用途正是区分。
func shortHash(h string) string {
	return short(strings.TrimPrefix(h, "sha256:"))
}

// countArchived 数存档里有几版源头。
func countArchived(dir string) (int, error) {
	if dir == "" {
		return 0, nil
	}
	m, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return 0, err
	}
	return len(m), nil
}

func hexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
