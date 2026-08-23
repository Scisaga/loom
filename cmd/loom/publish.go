package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/publish"
)

// publish 手动发一次。日常由发布器守护进程自动做(`loom publisher`),
// 这个命令留给首次发布、排障、以及不想跑守护进程的场合。
//
// 两者共用 internal/publish —— 分成两份实现,迟早会在"校验不过要不要发"
// 这类问题上分叉。

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	out := fs.String("o", "", "分发目标:/绝对路径 或 ssh://主机/绝对路径(必需)")
	keyPath := fs.String("key", "", "平台签名私钥(必需)")
	verify := fs.String("verify-url", "", "推完后从这个地址确认节点取得到")
	dns := fs.String("dns", "", "解析 verify-url 用的 DNS(不依赖机器全局设置)")
	sshConf := fs.String("ssh-config", "", "ssh 配置文件")
	author := fs.String("author", "", "记进 manifest 的作者")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || *out == "" || *keyPath == "" {
		return fmt.Errorf("用法:loom publish <ssot.yaml> -o <目标> -key <私钥>")
	}
	body, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	privBytes, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	// -o 给相对路径时当本地目录用,省得每次都写绝对路径。
	spec := *out
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
	tgt, err := publish.ParseTarget(spec, *sshConf)
	if err != nil {
		return err
	}

	t, err := publish.Build(body, ed25519.PrivateKey(privBytes), publish.Meta{
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Author: *author,
	})
	if err != nil {
		return err
	}
	if err := tgt.Push(t); err != nil {
		return err
	}
	fmt.Printf("✓ 快照 %s\n  %d 个节点:%v\n  → %s\n",
		t.Snapshot, len(t.Owners()), t.Owners(), tgt)
	fmt.Printf("\n树里全是占位符,没有任何凭据;manifest 已签名。\n")
	fmt.Printf("分发点不需要被信任 —— 改一个字节,节点验签就过不了。\n")

	if *verify != "" {
		if err := publish.VerifyServed(*verify, t.Snapshot, *dns, 20*time.Second); err != nil {
			return fmt.Errorf("推完了,但从节点视角取不到:%w", err)
		}
		fmt.Printf("✅ 节点视角已确认(%s)\n", *verify)
	}
	return nil
}
