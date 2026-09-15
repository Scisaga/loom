package main

import (
	"context"
	"path/filepath"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

var controlDeviceReportSchemas = wire.DeviceReportSchemaRegistry{"health": 1}

func verifyControlDeviceReportPayload(kind string, schema int64, payload []byte) error {
	_, err := wire.DecodeDeviceHealthPayload(kind, schema, payload)
	return err
}

func (runtime *controlRuntime) openDeviceReportSink() (*controlplane.DeviceReportStore, controlplane.DeviceReportCommitter, error) {
	store, err := controlplane.OpenDeviceReportStore(filepath.Join(runtime.dir, "device-reports.json"), controlDeviceReportSchemas)
	if err != nil {
		return nil, nil, err
	}
	commit := func(ctx context.Context, report controlplane.VerifiedDeviceReportV2) error {
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		application, err := runtime.certifiedApplicationLocked()
		if err != nil {
			return err
		}
		var profiles []string
		for _, service := range application.Services {
			if service.Role == "device_report" {
				profiles = service.AuthorizedSubjectProfiles
			}
		}
		reader := func(_ context.Context, hash string) (controlplane.DeviceIdentityAuthorityV1, error) {
			return runtime.readDeviceIdentityLocked(hash)
		}
		if err := controlplane.RevalidateDeviceReportAuthority(ctx, report, profiles, reader, runtime.now().UTC()); err != nil {
			return err
		}
		return store.Commit(ctx, report)
	}
	return store, commit, nil
}
