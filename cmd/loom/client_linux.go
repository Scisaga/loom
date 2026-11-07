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
	"strings"
	"syscall"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
	"loom/internal/linuxclient"
)

const (
	defaultLinuxLocalState = "/var/lib/loom-device/runtime.json"
	defaultLinuxStatus     = "/run/loom-client/status.json"
	defaultLinuxConfig     = "/run/loom-client/config.json"
	defaultLinuxSingBox    = "/usr/local/lib/loom-client/current/sing-box"
)

func cmdClientCapture(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	switch args[0] {
	case "_tun-worker":
		if len(args) != 3 && (len(args) != 4 || args[3] != "check") {
			return errors.New("invalid isolated data-plane invocation")
		}
		return linuxclient.ExecTUNWorker(args[1], args[2], len(args) == 4)
	case "_tun-workload":
		return linuxclient.RunTUNWorkload(ctx, args[1:])
	case "exec":
		fs := flag.NewFlagSet("client exec", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		config := fs.String("runtime-config", defaultLinuxConfig, "runtime configuration identifying the active isolated capture")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return linuxclient.ExecuteCapture(ctx, *config, fs.Args())
	default:
		return errors.New("invalid capture command")
	}
}

func cmdClientRun(args []string) error {
	fs := flag.NewFlagSet("client run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	local := fs.String("runtime-state", defaultLinuxLocalState, "preference and bounded observation state")
	status := fs.String("status", defaultLinuxStatus, "deletable selector readback")
	config := fs.String("runtime-config", defaultLinuxConfig, "ephemeral config projected from the LKG")
	singBox := fs.String("sing-box", defaultLinuxSingBox, "exact packaged sing-box executable")
	capture := fs.String("capture", "mixed", "tun (supervised isolated applications) or mixed (explicit loopback proxy)")
	resources := fs.String("resource-inputs", "", "protected local server listener/TLS input file")
	wgKey := fs.String("wireguard-private-key", "/etc/wireguard/node.key", "protected WireGuard private key file")
	traceProbes := fs.Bool("trace-probes", false, "emit safe Debug correlation for transport echo diagnostics")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client run does not accept positional arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	return linuxclient.Run(ctx, linuxclient.Options{DeviceState: *state, LocalState: *local, Status: *status,
		Config: *config, SingBox: *singBox, Capture: *capture, ResourceInputs: *resources, WireGuardPrivateKey: *wgKey, Reload: reload, TraceProbes: *traceProbes, Log: os.Stderr})
}

func cmdClientPreflight(args []string) error {
	fs := flag.NewFlagSet("client preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	singBox := fs.String("sing-box", defaultLinuxSingBox, "exact packaged sing-box executable")
	capture := fs.String("capture", "mixed", "tun (supervised isolated applications) or mixed (explicit loopback proxy)")
	resources := fs.String("resource-inputs", "", "protected local server listener/TLS input file")
	wgKey := fs.String("wireguard-private-key", "/etc/wireguard/node.key", "protected WireGuard private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client preflight does not accept positional arguments")
	}
	if err := linuxclient.PreflightResources(*state, *singBox, *capture, *resources, *wgKey); err != nil {
		return err
	}
	fmt.Println("Linux certified LKG and sing-box preflight passed")
	return nil
}

func cmdClientCleanup(args []string) error {
	fs := flag.NewFlagSet("client cleanup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("runtime-config", defaultLinuxConfig, "runtime configuration whose owned network objects must be cleaned")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client cleanup does not accept positional arguments")
	}
	return linuxclient.CleanupWireGuard(linuxclient.Options{Config: *config})
}

func cmdClientPolicy(args []string) error {
	fs := flag.NewFlagSet("client policy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	unit := fs.String("unit", "loom-client.service", "formal Linux client service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 || rest[0] != "list" {
		if len(rest) != 2 || rest[0] != "select" {
			return errors.New("用法: loom client policy [flags] <list|select PolicyID>")
		}
	}
	store, err := deviceclient.Load(*state)
	if err != nil {
		return err
	}
	lkg := store.LKG()
	if lkg == nil || lkg.View.Platform != "linux" {
		return errors.New("Linux device has no certified view")
	}
	if rest[0] == "list" {
		services, policies := clientmodel.PolicyOptions(lkg.View)
		return json.NewEncoder(os.Stdout).Encode(struct {
			Services []control.Service       `json:"services"`
			Policies []control.NetworkPolicy `json:"policies"`
			PolicyID string                  `json:"policy_id,omitempty"`
		}{services, policies, store.Preference().PolicyID})
	}
	preference, err := clientmodel.ChoosePolicy(store.Preference(), lkg.View, rest[1])
	if err != nil {
		return err
	}
	if err := store.SetPreference(preference); err != nil {
		return err
	}
	if output, err := exec.Command("systemctl", "reload", *unit).CombinedOutput(); err != nil {
		return fmt.Errorf("policy choice saved but service reload failed: %w: %s", err, string(output))
	}
	fmt.Println("Policy choice saved; verify actual application with client status")
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
	if err := encoder.Encode(status); err != nil {
		return err
	}
	if status.Runtime != "running" {
		if status.Runtime == "unknown" {
			return errors.New("certified configuration is saved; Linux client runtime readback is unknown")
		}
		return errors.New("certified configuration is saved; Linux client runtime is not running")
	}
	return nil
}

func cmdClientMigratePolicySelection(args []string) error {
	fs := flag.NewFlagSet("client migrate-policy-selection", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", defaultDeviceState, "existing identity")
	local := fs.String("runtime-state", defaultLinuxLocalState, "existing protected runtime preferences")
	view := fs.String("view", "", "new certified configuration")
	evidence := fs.String("evidence", "", "protected original identity evidence")
	unit := fs.String("unit", "loom-client.service", "formal service that must remain stopped")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *view == "" || *evidence == "" {
		return errors.New("migrate-policy-selection requires -view and -evidence")
	}
	active, err := exec.Command("systemctl", "show", *unit, "-p", "ActiveState", "--value").Output()
	if err != nil {
		return err
	}
	if value := strings.TrimSpace(string(active)); value != "inactive" && value != "failed" {
		return errors.New("stop the formal client service before policy migration")
	}
	body, err := readBoundedRegular(*view, 5<<20, true)
	if err != nil {
		return err
	}
	defer clear(body)
	var envelope control.DeviceViewEnvelope
	if err := control.DecodeCanonical(body, &envelope, control.ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return err
	}
	original, legacy, err := linuxclient.PolicyMigrationInput(*local, *evidence+".runtime")
	if err != nil {
		return err
	}
	defer clear(original)
	defer clear(legacy)
	preference, err := deviceclient.PreviewPolicySelectionFile(*state, *evidence, envelope, legacy, nil)
	if err != nil {
		return err
	}
	generation, err := linuxclient.NetworkGeneration()
	if err != nil {
		return err
	}
	next, err := linuxclient.PreparePolicyMigration(original, preference, generation, envelope.ViewDigest)
	if err != nil {
		return err
	}
	if err := linuxclient.CommitPolicyMigration(*local, *evidence+".runtime", original, next); err != nil {
		return err
	}
	if _, err := deviceclient.MigratePolicySelectionFile(*state, *evidence, envelope, legacy, nil); err != nil {
		return err
	}
	fmt.Println("policy configuration advanced; original identity and settings preserved; service remains stopped pending activation readback")
	return nil
}
