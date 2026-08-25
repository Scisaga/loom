package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"loom/internal/publish"
	"loom/internal/version"
)

// cmdRelease 把一份二进制**显式**批准为可以发到全网的那一份。
//
// 在此之前发布器每轮重新读 `-binary`,sha 一变就发 —— 于是任何一次
// `go build` 都武装了一次全网升级。调试期间编译四次就是四轮 12.5 MB × 5。
//
// 三道检查全在**人按下回车的这一刻**做完,而不是留给发布器在半夜静默失败:
//
//  1. 追溯得回 git 吗(D75)—— 脏构建或认不出 commit 的一律拒绝
//  2. 这台机器上跑得起来吗、读得懂现有配置吗(selfcheck,§15.4)
//  3. 理由填了吗 —— 几天后翻到这条记录的人需要知道为什么
func cmdRelease(args []string) error {
	fs := flag.NewFlagSet("release", flag.ExitOnError)
	binPath := fs.String("binary", stagedBinary, "要放行的二进制(默认是构建产物,不是正在跑的那份)")
	dir := fs.String("dir", "deploy/released", "放行记录与副本存放目录")
	reason := fs.String("reason", "", "为什么发这一版(必填)")
	by := fs.String("by", "", "谁批的")
	show := fs.Bool("show", false, "只看当前放行的是哪个")
	clear := fs.Bool("clear", false, "停止分发二进制(配置照发)")
	force := fs.Bool("allow-dirty", false, "放行追溯不回 git 的二进制")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	if *show {
		return showRelease(*dir)
	}
	if *clear {
		if err := publish.ClearRelease(*dir); err != nil {
			return err
		}
		fmt.Println("✓ 已停止分发二进制。配置照发,节点保持现有版本。")
		fmt.Println("  本地副本没删 —— 它们是回滚缓存,删了就得回网络取。")
		return nil
	}
	if *reason == "" {
		return fmt.Errorf("需要 -reason 说明为什么发这一版")
	}

	// 0. 别放行那个**会被退回去**的文件。
	//
	// 中控同时也是一个被管理的节点:它自己的 pull 每 10 分钟把
	// /usr/local/bin/loom 收敛到**已发布快照里的那份**。所以手工装完
	// 再 release 是有竞态的,窗口就是一个 pull 周期 —— 实测输过一次:
	// 慢了 2 分钟,pull 先把二进制退回旧版,release 于是记下了旧版。
	//
	// 放行**构建产物**没有这个问题:那个路径不归 pull 管。
	if *binPath == managedBinary {
		fmt.Printf("! %s 由本机 pull 管着,随时会被退回已发布的版本。\n", managedBinary)
		fmt.Printf("  刚手工装上去的东西可能在 release 之前就没了(踩过一次)。\n")
		fmt.Printf("  建议:go build -o %s ./cmd/loom 然后直接放行构建产物。\n\n", stagedBinary)
	}

	// 1. 追溯得回 git 吗。
	vc, err := version.OfFile(*binPath)
	if err != nil {
		return fmt.Errorf("读不出 %s 的构建信息:%w —— 它是 Go 二进制吗", *binPath, err)
	}
	if !vc.Traceable() && !*force {
		why := "认不出 commit"
		if vc.Dirty {
			why = "构建自脏工作区(" + version.Short(vc.Commit) + "+dirty)"
		}
		return fmt.Errorf("%s %s,追溯不回 git —— 提交后重新编译,或明知故犯时加 -allow-dirty", *binPath, why)
	}

	// 2. 这台机器上跑得起来、读得懂现有配置吗。
	//
	// 这一步是 §15.4 的冒烟测试。配对失败的方向不对称:新版通常读得懂
	// 旧配置,旧版读不懂新配置 —— 而发布器就是这么崩过两次的。
	out, err := exec.Command(*binPath, "selfcheck", "-q").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s 的 selfcheck 没过,不放行:%v\n%s", *binPath, err, out)
	}

	r := publish.Release{
		Commit: vc.Commit, Dirty: vc.Dirty,
		ReleasedAt: time.Now().UTC().Format(time.RFC3339),
		By:         *by, Reason: *reason,
	}
	if err := publish.WriteRelease(*dir, *binPath, r); err != nil {
		return err
	}

	cur, _, err := publish.ReadRelease(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("✓ 已放行 %s(commit %s)\n", version.Short(cur.SHA256), version.Short(cur.Commit))
	if cur.Dirty {
		fmt.Printf("  ⚠️ 这是脏构建 —— 出了问题没法用 git 复现\n")
	}
	fmt.Printf("  理由:%s\n", cur.Reason)
	fmt.Printf("\n发布器会在下一轮(最多 30 秒)带上它。节点按各自的 pull 周期取 ——\n")
	fmt.Printf("**包括中控自己**,所以不用手工装到 %s。\n", managedBinary)
	fmt.Printf("反悔:`loom release -clear` 停发,或 `loom pin <快照 id>` 退回历史版本。\n")
	return nil
}

func showRelease(dir string) error {
	r, bin, err := publish.ReadRelease(dir)
	if err != nil {
		return err
	}
	if r == nil {
		fmt.Println("还没有放行过任何二进制 —— 发布器只发配置,节点保持现有版本。")
		fmt.Println("放行:loom release -reason <理由>")
		return nil
	}
	fmt.Printf("当前放行 %s\n", version.Short(r.SHA256))
	fmt.Printf("  commit    %s%s\n", orUnknown(r.Commit), map[bool]string{true: " ⚠️ +dirty"}[r.Dirty])
	fmt.Printf("  大小      %.1f MB\n", float64(r.Size)/(1<<20))
	fmt.Printf("  放行于    %s%s\n", r.ReleasedAt, byline(r.By))
	fmt.Printf("  理由      %s\n", r.Reason)
	fmt.Printf("  副本      %s\n", bin)

	// 本机二进制和放行的不一致 —— **正是"我重新编译了但没 release"那一刻**。
	// 说出来,否则人会以为改动已经在路上了。
	if live, err := os.ReadFile("/usr/local/bin/loom"); err == nil {
		if s := sha256Hex(live); s != r.SHA256 {
			fmt.Printf("\n  ⓘ /usr/local/bin/loom 现在是 %s,和放行的不是同一份。\n", version.Short(s))
			fmt.Printf("     重新编译不会自动发出去 —— 这是有意的。要发就 `loom release`。\n")
		}
	}
	return nil
}

func byline(by string) string {
	if by == "" {
		return ""
	}
	return "(" + by + ")"
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

const (
	// stagedBinary 是构建产物的约定位置。**不归 pull 管**,所以放在这里
	// 的东西不会被收敛掉。
	stagedBinary = "deploy/staging/loom"
	// managedBinary 是节点上跑着的那份。pull 会把它收敛到已发布快照里
	// 的版本 —— 手工往这儿装的东西活不过一个 pull 周期。
	managedBinary = "/usr/local/bin/loom"
)
