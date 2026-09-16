//go:build linux

package clientv2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"loom/internal/wire"
)

const LinuxAgentObservationFile = "agent-observations.json"

type linuxAgentObservationsV1 struct {
	Schema       int               `json:"schema"`
	ClusterID    string            `json:"cluster_id"`
	DeviceID     string            `json:"device_id"`
	Observations []json.RawMessage `json:"observations"`
}

func persistLinuxAgentObservations(statePath string, raw []json.RawMessage) error {
	store, err := Open(statePath)
	if err != nil {
		return err
	}
	view := store.Envelope()
	if view == nil || view.Payload.Active == nil {
		return errors.New("[Linux 观测] 缺当前活动身份")
	}
	if raw == nil {
		raw = []json.RawMessage{}
	}
	return persistProtectedCanonical(filepath.Join(filepath.Dir(statePath), LinuxAgentObservationFile), linuxAgentObservationsV1{
		Schema: 1, ClusterID: view.Payload.ClusterID, DeviceID: view.Payload.DeviceID, Observations: raw})
}

// 文件只是 daemon 与 Agent 的本机交接。返回的观测仍是未信任原文，调用方
// 必须使用同一 installation 解封的服务器 CA 验签，并保留原生成时间。
func LinuxAgentObservationInput(statePath string, deviceID string) ([]json.RawMessage, []byte, error) {
	store, err := Open(statePath)
	if err != nil {
		return nil, nil, err
	}
	view, installation := store.Envelope(), store.Installation()
	if view == nil || view.Payload.Active == nil || installation == nil || view.Payload.DeviceID != deviceID {
		return nil, nil, errors.New("[Linux 观测] Agent 与当前 installation 身份不一致")
	}
	ca, err := linuxObservationCA(installation)
	if err != nil {
		return nil, nil, err
	}
	path := filepath.Join(filepath.Dir(statePath), LinuxAgentObservationFile)
	body, err := readPrivateRegularFile(path, wire.MaximumDeviceReportReceiptBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ca, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var input linuxAgentObservationsV1
	canonical, err := wire.DecodeStrict(body, wire.MaximumDeviceReportReceiptBytes, &input)
	if err != nil || !bytes.Equal(body, canonical) || input.Schema != 1 || input.ClusterID != view.Payload.ClusterID || input.DeviceID != deviceID || input.Observations == nil || len(input.Observations) > 256 {
		return nil, nil, errors.New("[Linux 观测] 本机观测交接文件无效或属于另一设备")
	}
	return input.Observations, ca, nil
}

func linuxObservationCA(installation *DeviceInstallationV1) ([]byte, error) {
	if installation == nil {
		return nil, errors.New("[Linux 观测] 缺 installation")
	}
	var ca []byte
	for _, credential := range installation.Credentials {
		if credential.SecretID != wire.DeviceObservationCASecretIDV1 || credential.Purpose != "device_credential" {
			continue
		}
		if ca != nil {
			return nil, errors.New("[Linux 观测] 服务器 CA 重复")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(credential.SecretBytes)
		if err != nil || wire.HashRaw("loom-linux-installed-secret-v1", decoded) != credential.SecretDigest || wire.ValidateRuntimeCABundle(string(decoded)) != nil {
			return nil, errors.New("[Linux 观测] 服务器 CA 材料无效")
		}
		ca = decoded
	}
	if ca == nil {
		return nil, errors.New("[Linux 观测] 当前 installation 缺认证服务器 CA")
	}
	return ca, nil
}
