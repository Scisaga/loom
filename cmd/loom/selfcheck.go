package main

import (
	"flag"
	"fmt"

	"loom/internal/publish"
	"loom/internal/version"
)

const signedCurrentCapability = publish.SignedCurrentCapability

// selfcheck 是二进制自我验证:**这个二进制在这台机器上能不能用**。
//
// 它是升级前的冒烟测试(§15.4)。检查三件事:
//
//  1. 它能在这台机器上跑起来(架构对、没损坏、动态库齐)
//  2. 它报告自己的构建信息与要求的安全能力。
//
// Linux DeviceView 与真实 sing-box 的配对检查由 `loom client preflight`
// 完成；selfcheck 不再读取旧 Agent/report 配置形成兼容入口。
func cmdSelfcheck(args []string) error {
	fs := flag.NewFlagSet("selfcheck", flag.ExitOnError)
	quiet := fs.Bool("q", false, "只用退出码说话")
	require := fs.String("require", "", "要求二进制具备指定安全能力")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if err := requireSelfcheckCapability(*require); err != nil {
		return err
	}

	say := func(f string, a ...any) {
		if !*quiet {
			fmt.Printf(f+"\n", a...)
		}
	}
	vc := version.Self()
	say("%s", vc.Line())
	// 认不出 commit、或者构建自脏工作区,都要在升级前的这一步就说出来 ——
	// 装上去之后再想追溯"这台跑的是哪一版"就晚了。
	for _, w := range vc.Warnings() {
		say("  ⚠️ %s", w)
	}

	if *require != "" {
		say("  ✅ capability %s", *require)
	}
	return nil
}

func requireSelfcheckCapability(name string) error {
	switch name {
	case "", signedCurrentCapability:
		return nil
	default:
		return fmt.Errorf("这个二进制不具备要求的 capability %q", name)
	}
}
