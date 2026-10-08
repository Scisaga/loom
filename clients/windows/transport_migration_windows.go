//go:build windows

package main

import (
	"errors"
	"flag"
	"io"
	"os"

	"loom/internal/clientsecret"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func migrateWindowsTransport(args []string, edition clientEdition) error {
	fs := flag.NewFlagSet("migrate-transport", flag.ContinueOnError)
	state := fs.String("state", "", "existing protected identity file")
	view := fs.String("view", "", "certified replacement file")
	evidence := fs.String("evidence", "", "protected historical evidence file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *state == "" || *view == "" || *evidence == "" {
		return errors.New("migrate-transport requires -state, -view and -evidence")
	}
	ui, err := acquireWindowsClientUILock()
	if err != nil {
		return err
	}
	defer ui.close()
	data, err := acquireWindowsDataPlaneLock()
	if err != nil {
		return err
	}
	defer data.close()
	file, err := os.Open(*view)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return errors.New("replacement requires a bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err != nil {
		return err
	}
	defer clear(body)
	var envelope control.DeviceViewEnvelope
	if err := control.DecodeCanonical(body, &envelope, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return err
	}
	if envelope.View.Platform != "windows" {
		return errors.New("replacement belongs to another platform")
	}
	var protector clientsecret.Protector = clientsecret.UserProtector{}
	if edition == editionInstalled {
		protector = clientsecret.MachineProtector{}
	}
	return deviceclient.MigrateTransportFile(*state, *evidence, envelope, protector)
}
