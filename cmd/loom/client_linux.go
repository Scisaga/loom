package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"loom/internal/clientmodel"
	"loom/internal/deviceclient"
	"loom/internal/linuxclient"
)

const (
	defaultLinuxLocalState = "/var/lib/loom-device/runtime.json"
	defaultLinuxStatus     = "/run/loom-client/status.json"
	defaultLinuxConfig     = "/run/loom-client/config.json"
	defaultLinuxSingBox    = "/usr/local/lib/loom-client/current/sing-box"
)

func cmdClientRun(args []string) error {
	fs := flag.NewFlagSet("client run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	local := fs.String("runtime-state", defaultLinuxLocalState, "preference and bounded observation state")
	status := fs.String("status", defaultLinuxStatus, "deletable selector readback")
	config := fs.String("runtime-config", defaultLinuxConfig, "ephemeral config projected from the LKG")
	singBox := fs.String("sing-box", defaultLinuxSingBox, "exact packaged sing-box executable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client run does not accept positional arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	return linuxclient.Run(ctx, linuxclient.Options{DeviceState: *state, LocalState: *local, Status: *status,
		Config: *config, SingBox: *singBox, Log: os.Stderr})
}

func cmdClientPreflight(args []string) error {
	fs := flag.NewFlagSet("client preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	singBox := fs.String("sing-box", defaultLinuxSingBox, "exact packaged sing-box executable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client preflight does not accept positional arguments")
	}
	if err := linuxclient.Preflight(*state, *singBox); err != nil {
		return err
	}
	fmt.Println("Linux certified LKG and sing-box preflight passed")
	return nil
}

func cmdClientRoute(args []string) error {
	fs := flag.NewFlagSet("client route", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	local := fs.String("runtime-state", defaultLinuxLocalState, "preference and bounded observation state")
	unit := fs.String("unit", "loom-client.service", "formal Linux client service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	preference := clientmodel.Preference{Schema: 1}
	switch {
	case len(rest) == 1 && rest[0] == "direct":
		preference.Mode = clientmodel.ModeDirect
	case len(rest) == 1 && rest[0] == "auto":
		preference.Mode = clientmodel.ModeAuto
	case len(rest) == 2 && rest[0] == "exit":
		preference.Mode, preference.Exit = clientmodel.ModeFixed, rest[1]
	default:
		return errors.New("用法: loom client route <direct|auto|exit ID>")
	}
	store, err := deviceclient.Load(*state)
	if err != nil {
		return err
	}
	lkg := store.LKG()
	if lkg == nil || lkg.View.Platform != "linux" || lkg.View.Runtime == nil {
		return errors.New("Linux device has no certified runtime profile")
	}
	if preference.Mode == clientmodel.ModeFixed {
		found := false
		for _, route := range lkg.View.Routes {
			found = found || route.FinalExit == preference.Exit
		}
		if !found {
			return errors.New("requested final exit is not authorized by the certified LKG")
		}
	}
	generation, err := linuxclient.NetworkGeneration()
	if err != nil {
		return err
	}
	if err := linuxclient.SetPreference(*local, generation, preference); err != nil {
		return err
	}
	if output, err := exec.Command("systemctl", "reload", *unit).CombinedOutput(); err != nil {
		return fmt.Errorf("preference saved but service reload failed: %w: %s", err, string(output))
	}
	fmt.Printf("Linux route preference saved and service reloaded: %s", preference.Mode)
	if preference.Exit != "" {
		fmt.Printf(" %s", preference.Exit)
	}
	fmt.Println()
	return nil
}

func cmdClientStatus(args []string) error {
	fs := flag.NewFlagSet("client status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("status", defaultLinuxStatus, "deletable selector readback")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client status does not accept positional arguments")
	}
	status, err := linuxclient.ReadStatus(*path)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}
