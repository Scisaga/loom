package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"loom/internal/clientdist"
)

func cmdClientInstall(args []string) error {
	fs := flag.NewFlagSet("client install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var options clientdist.InstallOptions
	fs.StringVar(&options.PackageRoot, "package-root", "", "已通过带外公钥验证并解包的目录")
	fs.StringVar(&options.PublicKey, "pubkey", "", "带外信任公钥；已有安装默认使用保留的信任输入")
	fs.StringVar(&options.State, "state", defaultDeviceState, "唯一设备身份/LKG 路径")
	fs.StringVar(&options.ResourceInputs, "resource-inputs", "", "受保护的本机资源材料引用")
	fs.StringVar(&options.Capture, "capture", "", "激活须显式选择 mixed 或隔离 tun")
	fs.StringVar(&options.InviteFile, "invite-file", "", "owner-only 邀请文件")
	fs.BoolVar(&options.InviteStdin, "invite-stdin", false, "从标准输入消费邀请")
	fs.BoolVar(&options.Upgrade, "upgrade", false, "保留现有身份和认证状态的前向升级")
	fs.BoolVar(&options.NoEnroll, "no-enroll", false, "只缓存验签制品，不推进 current 或启动服务")
	fs.BoolVar(&options.Inspect, "inspect", false, "只读核对本机制品、安装条件和公开设备身份，不改变目标")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client install does not accept positional arguments")
	}
	options.Input, options.Log = os.Stdin, os.Stdout
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return clientdist.Install(ctx, options)
}
