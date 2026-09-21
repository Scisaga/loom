package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"loom/internal/localconfig"
	"loom/internal/publish"
)

// publisher 是中控上的发布器(§14.2.2、D35、D36)。
//
// 它消费本机 control admin socket 提供的 certified Projection/head，渲染、
// 签名并推到分发点。旧 SSOT 文件不是运行输入。
//
// 签名私钥只有它用得到,不上任何服务器。它挂了不影响系统运行 —— 只影响
// 改变系统。
func cmdPublisher(args []string) error {
	fs := flag.NewFlagSet("publisher", flag.ExitOnError)
	envPath := fs.String("env", "", "六项本机部署配置；设置后从中读取签名 key、target 和 SSH config")
	controlSocket := fs.String("control-socket", "/run/loom-control/admin.sock", "本机 control 管理 Unix socket")
	keyPath := fs.String("key", "", "平台签名私钥(必需)")
	var targetSpecs, verifyURLs repeatedFlag
	fs.Var(&targetSpecs, "target", "分发目标，可重复:/绝对路径 或 ssh://主机/绝对路径(至少一个)")
	fs.Var(&verifyURLs, "verify-url", "推完后从这个地址确认节点取得到，可重复(强烈建议)")
	sshConf := fs.String("ssh-config", "", "ssh 配置文件(target 是 ssh:// 时用)")
	dns := fs.String("dns", "", "解析 verify-url 用的 DNS(不依赖机器全局设置)")
	author := fs.String("author", "", "记进 manifest 的作者")
	binary := fs.String("binary", "", "本机二进制路径(只用于提示未 release 的新构建；实际发布读 release-dir)")
	pinDir := fs.String("pin-dir", publish.DefaultPinDir, "钉住状态目录(loom pin 写在这儿)")
	health := fs.String("health", publish.HealthPath,
		"发布器写自己状态的地方 —— 让 loom status 看得出\"进程活着但发不出去\"")
	observation := fs.String("observation", publish.HealthPath+".signed",
		"平台密钥签名的 publisher observation")
	allowDirty := fs.Bool("allow-dirty", false,
		"放行追溯不回 git 的二进制(认不出 commit,或构建自脏工作区)")
	releaseDir := fs.String("release-dir", publish.DefaultReleaseDir,
		"放行记录目录 —— 只发 loom release 批准过的二进制;留空则回到\"本机二进制一变就发\"")
	archive := fs.String("ssot-history", "deploy/ssot-history", "认证发布输入与 release authority 的本机存档目录")
	interval := fs.Duration("interval", 30*time.Second, "多久看一次")
	once := fs.Bool("once", false, "只跑一轮就退出")

	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *envPath != "" {
		if *keyPath != "" || len(targetSpecs) != 0 || *sshConf != "" {
			return fmt.Errorf("-env 不能与 -key、-target 或 -ssh-config 混用")
		}
		config, err := localconfig.Load(*envPath)
		if err != nil {
			return fmt.Errorf("读取本机部署配置:%w", err)
		}
		*keyPath = config.SigningKey
		*sshConf = config.SSHConfig
		targetSpecs = append(targetSpecs, config.PublishOutputs...)
	}
	if *archive == "" {
		return fmt.Errorf("publisher 不允许关闭 -ssot-history：没有认证输入存档就无法审计 release")
	}
	if *keyPath == "" || len(targetSpecs) == 0 || *controlSocket == "" {
		return fmt.Errorf("需要 -control-socket、-key 和至少一个 -target")
	}
	privBytes, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	targets := make([]publish.Target, 0, len(targetSpecs))
	for _, spec := range targetSpecs {
		target, err := publish.ParseTarget(spec, *sshConf)
		if err != nil {
			return err
		}
		targets = append(targets, target)
	}
	tgt, err := publish.NewMirrorSet(targets...)
	if err != nil {
		return err
	}

	fmt.Printf("Loom 发布器 · certified control %s → %s\n", *controlSocket, tgt)
	if len(verifyURLs) == 0 {
		fmt.Fprintln(os.Stderr, "ⓘ 未设置本机补充 -verify-url；使用 certified NetworkIntent 的 distribution URLs")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *releaseDir == "" && *binary == "" {
		// 只有显式关闭 release 机制的兼容模式才靠 -binary 选发布内容。
		fmt.Fprintln(os.Stderr, "! 没有 -binary:只发配置。改了代码仍要手工分发到每台机器")
	}

	return publish.Run(ctx, publish.Options{
		AuthorityInput: certifiedPublisherInputReader(*controlSocket), AuthorityInputName: *controlSocket,
		Key: ed25519.PrivateKey(privBytes), Target: tgt,
		Author: *author, VerifyURLs: verifyURLs, DNS: *dns, BinaryPath: *binary,
		ArchiveDir:       *archive,
		PinDir:           *pinDir,
		HealthPath:       *health,
		ObservationPath:  *observation,
		LockPath:         publishTransactionLockPath,
		AllowUntraceable: *allowDirty,
		ReleaseDir:       *releaseDir,
		Interval:         *interval, Once: *once, Log: os.Stdout,
	})
}

func certifiedPublisherInputReader(socket string) func(context.Context) ([]byte, error) {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return func(ctx context.Context) ([]byte, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet,
			"http://loom.local/api/control/publisher-input", nil)
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
		if err != nil {
			return nil, err
		}
		if len(body) > 8<<20 {
			return nil, fmt.Errorf("certified publisher input exceeds size limit")
		}
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("control publisher input: %s", response.Status)
		}
		return body, nil
	}
}
