//go:build linux

package clientv2

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"time"

	"loom/internal/observation"
	"loom/internal/wire"
)

var linuxDeviceReportSchemas = wire.DeviceReportSchemaRegistry{"health": 1, "node-health": 1}

func linuxNodeHealthPayload(directory, version string, healthy bool, now time.Time) (string, []byte, error) {
	body, err := readPrivateRegularFile(filepath.Join(directory, "node-observation.json"), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		payload, err := wire.MarshalCanonical(wire.DeviceHealthPayloadV1{Healthy: healthy, Version: version})
		return "health", payload, err
	}
	if err != nil {
		return "", nil, err
	}
	var own observation.Observation
	canonical, err := wire.DecodeStrict(body, 1<<20, &own)
	if err != nil || !bytes.Equal(body, canonical) {
		return "", nil, errors.New("[Linux 报告] 本机观测不是规范对象")
	}
	store, err := Open(filepath.Join(directory, "state.json"))
	if err != nil {
		return "", nil, err
	}
	view := store.Envelope()
	if view == nil || view.Payload.Active == nil || view.Payload.DeviceID != own.Node || !containsString(view.Payload.Active.Responsibilities.Values, "forward") {
		return "", nil, errors.New("[Linux 报告] 观测不属于当前 forward 设备")
	}
	ca, err := linuxObservationCA(store.Installation())
	if err != nil {
		return "", nil, err
	}
	if _, err := observation.VerifyObservationAtLeast(&own, ca, now, 10*time.Minute, 5); err != nil {
		return "", nil, err
	}
	if err := observation.VerifyAttachments(&own, ca, now, 10*time.Minute); err != nil {
		return "", nil, err
	}
	payload, err := wire.MarshalCanonical(wire.DeviceNodeHealthPayloadV1{Healthy: healthy, Version: version, Observation: own})
	return "node-health", payload, err
}
