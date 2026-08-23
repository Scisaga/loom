package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"loom/internal/agent"
	"loom/internal/report"
)

// selfcheck 是二进制自我验证:**这个二进制在这台机器上能不能用**。
//
// 它是升级前的冒烟测试(§15.4)。检查三件事:
//
//  1. 它能在这台机器上跑起来(架构对、没损坏、动态库齐)
//  2. 它读得懂**这台机器现有的**配置
//  3. 报出自己的构建信息
//
// 第 2 条是关键。§15.4 要求配置与二进制绑定,而配对失败的方向是不对称的:
// 新版通常读得懂旧配置,旧版读不懂新配置 —— 今天发布器就是这么崩的
// (旧二进制遇到新增的 services 字段,直接拒绝发布)。所以升级顺序是
// **先装二进制,再装配置**,而这个检查确认前半步是安全的。
func cmdSelfcheck(args []string) error {
	fs := flag.NewFlagSet("selfcheck", flag.ExitOnError)
	quiet := fs.Bool("q", false, "只用退出码说话")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	say := func(f string, a ...any) {
		if !*quiet {
			fmt.Printf(f+"\n", a...)
		}
	}
	say("loom %s · %s/%s · %s", buildTag, runtime.GOOS, runtime.GOARCH, runtime.Version())

	checked := 0
	for _, c := range []struct {
		path string
		load func([]byte) error
	}{
		{report.ControlPath, func(b []byte) error { return nil }}, // 存在即可,内容由 LoadControl 管
		{"/etc/loom/report/config.json", func(b []byte) error { _, err := report.Load(b); return err }},
		{"/etc/loom/agent/config.json", func(b []byte) error { _, err := agent.Load(b); return err }},
	} {
		b, err := os.ReadFile(c.path)
		if os.IsNotExist(err) {
			continue // 不是每台机器都有每种配置
		}
		if err != nil {
			return fmt.Errorf("读 %s:%w", c.path, err)
		}
		if err := c.load(b); err != nil {
			return fmt.Errorf("这个二进制读不懂 %s:%w", c.path, err)
		}
		checked++
		say("  ✅ %s", c.path)
	}
	say("读懂了 %d 份现有配置", checked)
	return nil
}
