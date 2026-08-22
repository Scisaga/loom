package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"loom/internal/report"
)

// report 是节点上的上报者:回答"隧道还活着吗"和"配置还是渲染出来的那份吗"。
//
// 它**不做任何决定**。选路的决策者只有一个,在接入节点上(D11)。
//
// 两种用法:一次性打印(人排障、或者被别的东西调用),或者常驻监听隧道内
// 地址等人来拉。
func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	cfgPath := fs.String("c", "/etc/loom/report/config.json", "上报者配置(loom render 的产物)")
	serve := fs.Bool("serve", false, "常驻监听,提供 GET /status")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	cfg, err := report.Load(b)
	if err != nil {
		return err
	}

	if *serve {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		fmt.Printf("Loom 上报者 · 节点 %s\n", cfg.Node)
		return report.Serve(ctx, cfg, func() time.Time { return time.Now() }, os.Stdout)
	}

	st := report.Collect(cfg, time.Now())
	// 一次性模式下现场量一轮 —— 没有后台循环替它攒数据。
	if own, learned, err := report.Once(cfg, time.Now); err != nil {
		st.Errors = append(st.Errors, "观测:"+err.Error())
	} else {
		st.Observation, st.Learned = own, learned
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(st); err != nil {
		return err
	}
	// 自检有发现时退出码非零 —— 这样它能直接放进 cron 或别的检查里,
	// 而不需要谁去解析 JSON。
	if !st.OK() {
		return errSelfCheck
	}
	return nil
}

// errSelfCheck 让 main 用非零退出码结束,但不再重复打印 —— 细节已经在
// JSON 里了。
var errSelfCheck = &quietError{}

type quietError struct{}

func (*quietError) Error() string { return "自检发现问题(详见上面的 JSON)" }
