package wire

import (
	"bytes"
	"errors"
	"strings"
	"unicode"
)

type DeviceHealthPayloadV1 struct {
	Healthy bool   `json:"healthy"`
	Version string `json:"version"`
}

// 缺失 healthy 不能通过 bool 零值伪装成一份有效的失败报告。
func DecodeDeviceHealthPayload(kind string, schema int64, raw []byte) (DeviceHealthPayloadV1, error) {
	var result DeviceHealthPayloadV1
	var payload struct {
		Healthy *bool  `json:"healthy"`
		Version string `json:"version"`
	}
	canonical, err := DecodeStrict(raw, 2048, &payload)
	if err != nil || !bytes.Equal(raw, canonical) || kind != "health" || schema != 1 || payload.Healthy == nil ||
		payload.Version == "" || len(payload.Version) > 256 || strings.TrimSpace(payload.Version) != payload.Version ||
		strings.IndexFunc(payload.Version, unicode.IsControl) >= 0 {
		return result, errors.New("[设备健康] 报告的版本、健康状态或 schema 无效")
	}
	return DeviceHealthPayloadV1{Healthy: *payload.Healthy, Version: payload.Version}, nil
}
