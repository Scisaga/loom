package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"loom/internal/publish"
)

// 手工入口与 daemon 必须指向同一把锁。变量只为包内测试
// 放到临时目录；生产命令没有可覆盖该路径的 flag。
var publishTransactionLockPath = publish.LockPath

func withPublishTransactionLock(fn func() error) error {
	unlock, err := publish.AcquireLock(publishTransactionLockPath)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// publish 手动发一次。日常由发布器守护进程自动做(`loom publisher`),
// 这个命令留给首次发布、排障、以及不想跑守护进程的场合。
//
// 两者共用 internal/publish —— 分成两份实现,迟早会在"校验不过要不要发"
// 这类问题上分叉。

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	var outSpecs, verifyURLs repeatedFlag
	fs.Var(&outSpecs, "o", "分发目标，可重复:/绝对路径 或 ssh://主机/绝对路径(至少一个)")
	keyPath := fs.String("key", "", "平台签名私钥(必需)")
	fs.Var(&verifyURLs, "verify-url", "推完后从这个地址确认节点取得到，可重复")
	dns := fs.String("dns", "", "解析 verify-url 用的 DNS(不依赖机器全局设置)")
	sshConf := fs.String("ssh-config", "", "ssh 配置文件")
	author := fs.String("author", "", "记进 manifest 的作者")
	binary := fs.String("binary", "", "已禁用；二进制必须先 loom release，再由 publisher 发布")
	pinDir := fs.String("pin-dir", publish.DefaultPinDir, "钉住状态目录(必须与 publisher 一致)")
	releaseDir := fs.String("release-dir", publish.DefaultReleaseDir, "放行状态目录(必须与 publisher 一致)")
	allowDirty := fs.Bool("allow-dirty", false, "允许发布追溯不回 git 的已 release 二进制(高风险)")
	archive := fs.String("ssot-history", "deploy/ssot-history", "源头存档目录(中控本地,不进分发树;loom rollback 从这里取)")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || len(outSpecs) == 0 || *keyPath == "" {
		return fmt.Errorf("用法:loom publish <ssot.yaml> -o <目标> [-o <镜像>] -key <私钥>")
	}
	if *binary != "" {
		return fmt.Errorf("loom publish -binary 已禁用：它会绕过 reason、buildinfo 与 selfcheck 安全门；请先 `loom release -binary %s -reason <理由>`，再重跑本命令或等 publisher", *binary)
	}
	if *releaseDir == "" {
		return fmt.Errorf("手工 publish 不允许关闭 release 安全门；请使用与 publisher 一致的 -release-dir")
	}
	if *archive == "" {
		return fmt.Errorf("手工 publish 不允许关闭 -ssot-history：没有源头存档的快照无法回滚")
	}
	privBytes, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	// -o 给相对路径时当本地目录用,省得每次都写绝对路径。
	targets := make([]publish.Target, 0, len(outSpecs))
	for _, raw := range outSpecs {
		spec := raw
		if !strings.HasPrefix(spec, "ssh://") && !strings.HasPrefix(spec, "/") {
			abs, err := filepath.Abs(spec)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(abs, 0o755); err != nil {
				return err
			}
			spec = abs
		}
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

	// 手工命令不再维护第二套 Build/Push/Verify 实现。Once 仍走守护发布器
	// 的完整收敛路径：运行产物等价判定、整树自愈、节点视角验签、存档和
	// 每事务 publish.lock 都完全一致。PinDir/ReleaseDir 也与 daemon
	// 同源：已放行或已钉住的二进制仍进 manifest，手工发配置不能
	// 偷偷把 §15.4 的版本绑定清空。
	return publish.Run(context.Background(), publish.Options{
		SSOTPath: rest[0], Key: ed25519.PrivateKey(privBytes), Target: tgt,
		Author: *author, VerifyURLs: verifyURLs, DNS: *dns,
		ArchiveDir: *archive, PinDir: *pinDir, ReleaseDir: *releaseDir,
		AllowUntraceable: *allowDirty, LockPath: publishTransactionLockPath,
		Once: true, Log: os.Stdout,
	})
}
