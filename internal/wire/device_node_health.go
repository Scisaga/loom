package wire

import (
	"bytes"
	"encoding/json"
	"errors"

	"loom/internal/observation"
)

// Node health 保留原节点签名观测；v2 报告只换传输和身份绑定，不改变测量协议。
type DeviceNodeHealthPayloadV1 struct {
	Healthy     bool                    `json:"healthy"`
	Version     string                  `json:"version"`
	Observation observation.Observation `json:"observation"`
}

func DecodeDeviceNodeHealthPayload(kind string, schema int64, raw []byte) (DeviceNodeHealthPayloadV1, error) {
	var input struct {
		Healthy     *bool                    `json:"healthy"`
		Version     string                   `json:"version"`
		Observation *observation.Observation `json:"observation"`
	}
	var result DeviceNodeHealthPayloadV1
	canonical, err := DecodeStrict(raw, 1<<20, &input)
	if err != nil || !bytes.Equal(canonical, raw) || kind != "node-health" || schema != 1 || input.Healthy == nil || input.Observation == nil {
		return result, errors.New("[节点报告] schema、健康状态或原始观测无效")
	}
	health, err := json.Marshal(DeviceHealthPayloadV1{Healthy: *input.Healthy, Version: input.Version})
	if err != nil {
		return result, err
	}
	health, err = CanonicalizeStrict(health)
	if err != nil {
		return result, err
	}
	if _, err := DecodeDeviceHealthPayload("health", 1, health); err != nil {
		return result, err
	}
	if !validIdentifier(input.Observation.Node, 128) || input.Observation.Attest == nil {
		return result, errors.New("[节点报告] 缺本节点身份和原签名")
	}
	if _, err := ParseTimeZ(input.Observation.TS); err != nil {
		return result, err
	}
	return DeviceNodeHealthPayloadV1{Healthy: *input.Healthy, Version: input.Version, Observation: *input.Observation}, nil
}
