package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"loom/internal/agent"
)

// agent 是跑在接入节点上的调参回路(§5.5):按 tuning_period 探测每条候选、
// 按 objective 排序、带阻尼地切 selector。
//
// 它读的是渲染出来的 agent/config.json,**不是 SSOT** —— 节点上不该有全网
// 拓扑和别人的凭据。
func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	cfgPath := fs.String("c", "/etc/loom/agent/config.json", "Agent 配置(loom render 的产物)")
	mPath := fs.String("m", "/var/lib/loom/measurements.jsonl", "度量文件")
	once := fs.Bool("once", false, "每条声明只跑一轮就退出")
	dry := fs.Bool("dry-run", false, "照常探测和判断,但不真的切 selector")
	timeout := fs.Duration("timeout", 8*time.Second, "单次探测超时")
	retention := fs.Duration("retention", 24*time.Hour, "度量文件保留时长,启动时压实")

	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	cfg, err := agent.Load(b)
	if err != nil {
		return err
	}

	fmt.Printf("Loom Agent · 节点 %s · %d 条声明\n", cfg.Node, len(cfg.Declarations))
	for i := range cfg.Declarations {
		d := &cfg.Declarations[i]
		fmt.Printf("  %-14s %-9s 每 %-5s  %2d 条候选 × %d 个目标\n",
			d.ID, d.Objective, d.TuningPeriod, len(d.Candidates), len(d.Targets))
	}
	if *dry {
		fmt.Println("  (dry-run:只探测和判断,不切)")
	}

	// SIGTERM 来自 systemd stop/restart,SIGINT 来自终端 Ctrl-C。两者都该让
	// 当前这轮跑完再退出,而不是把度量写了一半。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return agent.Run(ctx, cfg, agent.Options{
		MeasurementPath: *mPath,
		ProbeTimeout:    *timeout,
		Retention:       *retention,
		Once:            *once,
		DryRun:          *dry,
		Log:             os.Stdout,
	})
}
