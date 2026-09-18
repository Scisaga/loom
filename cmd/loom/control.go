package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"

	"loom/internal/control"
	"loom/internal/localconfig"
)

const minimalStateName = "state.json"

func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] != "check" && args[0] != "migrate" {
		return errors.New("用法: loom config <check|migrate> [-env .env]")
	}
	action := args[0]
	fs := flag.NewFlagSet("config "+action, flag.ContinueOnError)
	path := fs.String("env", ".env", "六项部署输入")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("config %s 不接受位置参数", action)
	}
	if action == "migrate" {
		if err := localconfig.Migrate(*path); err != nil {
			return err
		}
		fmt.Println("deployment config migrated to the canonical six-key representation")
		return nil
	}
	config, err := localconfig.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("deployment config valid: hosts=%d outputs=%d local=%t provider_secret=present\n",
		len(config.DeployHosts), len(config.PublishOutputs), config.LocalNode != "")
	return nil
}

func cmdControl(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: loom control <import|serve|inspect>")
	}
	switch args[0] {
	case "import":
		return cmdControlImport(args[1:])
	case "serve":
		return cmdControlServe(args[1:])
	case "inspect":
		return cmdControlInspect(args[1:])
	default:
		return fmt.Errorf("未知 control 子命令 %q", args[0])
	}
}

func cmdControlImport(args []string) error {
	fs := flag.NewFlagSet("control import", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/loom-minimal", "最小控制状态目录")
	sourceDir := fs.String("source-dir", "/var/lib/loom-control", "受保护旧控制状态目录")
	floor := fs.String("release-floor", "/var/lib/loom/release-floor.json", "release anti-rollback floor")
	observation := fs.String("observation", "", "可选的认证 Web 观测快照")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control import 不接受位置参数")
	}
	state, err := control.Import(control.ImportInput{
		ConfigPath: filepath.Join(*sourceDir, "config.json"), CertifiedPath: filepath.Join(*sourceDir, "control-state.json"),
		OperationsPath: filepath.Join(*sourceDir, "operations.json"), BrowserTLSPath: filepath.Join(*sourceDir, "browser-tls.json"),
		ReleaseFloorPath: *floor, ObservationPath: *observation,
	})
	if err != nil {
		return err
	}
	path := filepath.Join(*stateDir, minimalStateName)
	if existing, loadErr := control.LoadState(path); loadErr == nil {
		if !reflect.DeepEqual(existing, state) {
			return errors.New("已存在的最小状态与导入结果不同；拒绝覆盖")
		}
		fmt.Printf("minimal control state already matches: head=%s revision=%d\n", state.Head.Hash, state.Head.Revision)
		return nil
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return fmt.Errorf("读取已有最小状态: %w", loadErr)
	}
	if err := control.SaveState(path, state); err != nil {
		return err
	}
	fmt.Printf("minimal control state imported: head=%s revision=%d\n", state.Head.Hash, state.Head.Revision)
	return nil
}

func cmdControlServe(args []string) error {
	fs := flag.NewFlagSet("control serve", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/loom-minimal", "最小控制状态目录")
	releaseRoot := fs.String("release-root", "/var/lib/loom/client-dist/releases", "客户端 release 根目录")
	releaseKey := fs.String("release-key", "/etc/loom/trust/platform.pub", "catalog 验签公钥")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control serve 不接受位置参数")
	}
	state, err := control.LoadState(filepath.Join(*stateDir, minimalStateName))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return (&control.Server{State: state, ReleaseRoot: *releaseRoot, ReleaseKey: *releaseKey}).Serve(ctx)
}

func cmdControlInspect(args []string) error {
	fs := flag.NewFlagSet("control inspect", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/loom-minimal", "最小控制状态目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control inspect 不接受位置参数")
	}
	state, err := control.LoadState(filepath.Join(*stateDir, minimalStateName))
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Head          control.CertifiedHead `json:"certified_head"`
		Floor         uint64                `json:"release_floor_generation"`
		V2Latch       bool                  `json:"v2_latch"`
		Devices       int                   `json:"devices"`
		Services      int                   `json:"services"`
		AdminBindings int                   `json:"admin_bindings"`
	}{state.Head, state.Recovery.ReleaseFloor.Generation, state.Recovery.V2Latch,
		len(state.Projection.Devices), len(state.Projection.Services), len(state.AdminCertDER)})
}
