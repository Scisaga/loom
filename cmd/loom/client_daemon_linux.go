//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"loom/internal/clientv2"
	"loom/internal/deploy"
	"loom/internal/version"
)

// 宿主 unit 随软件保留；Device tombstone 只撤下该身份的 runtime，宿主读到
// terminal 后正常退出，不在自身安装事务中 systemctl stop 自己。
func startLinuxClientDaemon(stateDirectory string, timeout time.Duration) error {
	if !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory || strings.ContainsAny(stateDirectory, "\x00\n\r") {
		return errors.New("[Linux daemon] 状态目录无效")
	}
	unit := `[Unit]
Description=Loom v2 private device configuration and reporting
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/loom client serve-v2 -state-dir ` + strconv.Quote(strings.ReplaceAll(stateDirectory, "%", "%%")) + `
Restart=on-failure
RestartSec=5s
UMask=0077

[Install]
WantedBy=multi-user.target
`
	const path = "/etc/systemd/system/loom-client-v2.service"
	plan := &deploy.Plan{Node: "local-device", Files: map[string]string{path: unit}, Triggers: map[string][]string{path: {"loom-client-v2"}}, Verify: []string{"loom-client-v2"}}
	return runScript(plan.Node, deploy.Script(plan, "client-v2-host-"+time.Now().UTC().Format("20060102T150405.000000000Z")), "", true, timeout)
}

func cmdClientServeV2(args []string) error {
	fs := flag.NewFlagSet("client serve-v2", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/loom/client-v2", "已安装 v2 身份、配置与报告日志目录")
	interval := fs.Duration("interval", time.Minute, "正常配置同步和报告周期")
	timeout := fs.Duration("timeout", 30*time.Second, "每次请求与安装超时")
	once := fs.Bool("once", false, "只执行一次正常同步、安装和报告")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || os.Geteuid() != 0 {
		return errors.New("client serve-v2 必须由目标 Linux 节点 root 运行")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := clientv2.RunLinuxDeviceDaemon(ctx, clientv2.LinuxDeviceDaemonOptions{StateDirectory: *dir, Interval: *interval, Timeout: *timeout,
		Version: version.Base().Line(), Once: *once, Log: os.Stderr,
		Apply: func(ctx context.Context, plan *deploy.Plan) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return runScript(plan.Node, deploy.Script(plan, "client-v2-"+time.Now().UTC().Format("20060102T150405.000000000Z")), "", true, *timeout)
		},
		Healthy: func(ctx context.Context, units []string) bool {
			if len(units) == 0 {
				return false
			}
			args := append([]string{"show", "--property=ActiveState", "--value"}, units...)
			output, err := exec.CommandContext(ctx, "systemctl", args...).Output()
			states := strings.Fields(string(output))
			if err != nil || len(states) != len(units) {
				return false
			}
			for _, state := range states {
				if state != "active" {
					return false
				}
			}
			return true
		}})
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
