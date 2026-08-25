package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"loom/internal/publish"
)

// publisher 是中控上的发布器(§14.2.2、D35、D36)。
//
// 它是"我为什么还要自己部署"的答案:盯着 SSOT,变了就校验、渲染、签名、
// 推到分发点;节点那半边本来就在定时自取。**改完文件,不用敲任何命令。**
//
// 签名私钥只有它用得到,不上任何服务器。它挂了不影响系统运行 —— 只影响
// 改变系统。
func cmdPublisher(args []string) error {
	fs := flag.NewFlagSet("publisher", flag.ExitOnError)
	ssot := fs.String("ssot", "deploy/ssot.yaml", "盯着哪个 SSOT")
	keyPath := fs.String("key", "", "平台签名私钥(必需)")
	target := fs.String("target", "", "分发目标:/绝对路径 或 ssh://主机/绝对路径(必需)")
	verify := fs.String("verify-url", "", "推完后从这个地址确认节点取得到(强烈建议)")
	sshConf := fs.String("ssh-config", "", "ssh 配置文件(target 是 ssh:// 时用)")
	dns := fs.String("dns", "", "解析 verify-url 用的 DNS(不依赖机器全局设置)")
	author := fs.String("author", "", "记进 manifest 的作者")
	binary := fs.String("binary", "", "把这个 Agent 二进制一起发(与配置绑定回滚,§15.4)")
	pinDir := fs.String("pin-dir", "deploy/pinned", "钉住状态目录(loom pin 写在这儿)")
	health := fs.String("health", publish.HealthPath,
		"发布器写自己状态的地方 —— 让 loom status 看得出\"进程活着但发不出去\"")
	allowDirty := fs.Bool("allow-dirty", false,
		"放行追溯不回 git 的二进制(认不出 commit,或构建自脏工作区)")
	archive := fs.String("ssot-history", "deploy/ssot-history", "源头存档目录(中控本地,不进分发树;loom rollback 从这里取)")
	interval := fs.Duration("interval", 30*time.Second, "多久看一次")
	once := fs.Bool("once", false, "只跑一轮就退出")

	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *keyPath == "" || *target == "" {
		return fmt.Errorf("需要 -key 和 -target")
	}
	privBytes, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	tgt, err := publish.ParseTarget(*target, *sshConf)
	if err != nil {
		return err
	}

	fmt.Printf("Loom 发布器 · %s → %s\n", *ssot, tgt)
	if *verify == "" {
		// 推成功不等于取得到。不验证就跑,等于把一类静默故障留在系统里。
		fmt.Fprintln(os.Stderr, "! 没有 -verify-url:推送成功不代表节点取得到(nginx 路径写错时推送侧完全正常)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *binary == "" {
		// 不带二进制不是错误,但值得说一声 —— 那意味着改了 Go 代码之后
		// 仍然要手工分发,而 §15.4 的绑定回滚也就不成立。
		fmt.Fprintln(os.Stderr, "! 没有 -binary:只发配置。改了代码仍要手工分发到每台机器")
	}

	return publish.Run(ctx, publish.Options{
		SSOTPath: *ssot, Key: ed25519.PrivateKey(privBytes), Target: tgt,
		Author: *author, VerifyURL: *verify, DNS: *dns, BinaryPath: *binary,
		ArchiveDir:       *archive,
		PinDir:           *pinDir,
		HealthPath:       *health,
		AllowUntraceable: *allowDirty,
		Interval:         *interval, Once: *once, Log: os.Stdout,
	})
}
