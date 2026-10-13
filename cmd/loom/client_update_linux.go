package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"loom/internal/clientdist"
)

func cmdClientUpdate(args []string) error {
	fs := flag.NewFlagSet("client update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var options clientdist.UpdateOptions
	fs.StringVar(&options.State, "state", defaultDeviceState, "唯一受保护的设备配置")
	fs.StringVar(&options.ResourceInputs, "resource-inputs", "", "原本机资源输入")
	fs.StringVar(&options.Capture, "capture", "", "显式 mixed 或隔离 tun")
	fs.StringVar(&options.UpdateUnitMigration, "update-unit-migration", "", "本次操作者显式提供的旧更新入口证明；日常检查不需要")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client update accepts no positional arguments")
	}
	options.Log = os.Stdout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return clientdist.Update(ctx, options)
}
