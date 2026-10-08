package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"loom/internal/control"
)

func cmdControlExportDeviceView(args []string) error {
	fs := flag.NewFlagSet("control export-device-view", flag.ContinueOnError)
	socket := fs.String("admin-socket", "/var/lib/loom-control/admin.sock", "owner-only local control socket")
	device := fs.String("device", "", "existing device ID")
	output := fs.String("out", "", "new owner-only delivery file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || control.ValidateID(*device) != nil || !filepath.IsAbs(*output) || filepath.Clean(*output) != *output {
		return errors.New("export-device-view requires -device and an absolute -out file")
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("administrative redirect is forbidden") }}
	response, err := client.Get("http://loom.local/api/control/devices/" + *device + "/view")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("device configuration export rejected: %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil {
		return err
	}
	defer clear(body)
	var envelope control.DeviceViewEnvelope
	if err = control.DecodeCanonical(body, &envelope, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return err
	}
	if err = envelope.Validate(); err != nil {
		return err
	}
	if envelope.View.DeviceID != *device {
		return errors.New("exported View belongs to another device")
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	readback, err := readBoundedRegular(*output, 8<<20, true)
	defer clear(readback)
	if err != nil {
		return err
	}
	if string(readback) != string(body) {
		return errors.New("delivery file readback differs")
	}
	fmt.Println("certified device configuration saved to protected delivery file")
	return nil
}
