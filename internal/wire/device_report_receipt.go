package wire

import (
	"bytes"
	"encoding/json"
	"errors"
)

const DeviceReportReceiptMediaTypeV1 = "application/vnd.loom.device-report-receipt.v1+json"
const MaximumDeviceReportReceiptBytes = (1 << 20) + (16 << 10)

// receipt 只确认这次已持久化的报告；观测保留原始来源和签名，客户端仍须按
// 当前授权和原测量时间验签，不能把 HTTPS 回执当作服务器测量证明。
type DeviceReportReceiptV1 struct {
	Schema             int               `json:"schema"`
	ClusterID          string            `json:"cluster_id"`
	DeviceID           string            `json:"device_id"`
	ReportID           string            `json:"report_id"`
	ReportSequence     int64             `json:"report_sequence"`
	ReportEnvelopeHash string            `json:"report_envelope_hash"`
	Observations       []json.RawMessage `json:"observations"`
}

func DeviceReportEnvelopeHash(envelope *DeviceReportEnvelopeV2) (string, error) {
	if envelope == nil || envelope.Schema != 2 {
		return "", errors.New("[设备回执] 缺已签报告")
	}
	return HashObject("loom-device-report-envelope-v2", envelope)
}

func NewDeviceReportReceipt(body DeviceReportBodyV2, envelopeHash string, observations []json.RawMessage) (DeviceReportReceiptV1, error) {
	receipt := DeviceReportReceiptV1{Schema: 1, ClusterID: body.ClusterID, DeviceID: body.DeviceID, ReportID: body.ReportID,
		ReportSequence: body.ReportSequence, ReportEnvelopeHash: envelopeHash, Observations: observations}
	if receipt.Observations == nil {
		receipt.Observations = []json.RawMessage{}
	}
	return receipt, validateDeviceReportReceipt(receipt)
}

func DecodeDeviceReportReceipt(raw []byte, envelope *DeviceReportEnvelopeV2) (DeviceReportReceiptV1, error) {
	var receipt DeviceReportReceiptV1
	canonical, err := DecodeStrict(raw, MaximumDeviceReportReceiptBytes, &receipt)
	if err != nil || !bytes.Equal(canonical, raw) {
		return receipt, errors.New("[设备回执] 不是规范回执")
	}
	if err := validateDeviceReportReceipt(receipt); err != nil {
		return receipt, err
	}
	hash, err := DeviceReportEnvelopeHash(envelope)
	if err != nil || receipt.ReportEnvelopeHash != hash || receipt.ClusterID != envelope.Body.ClusterID ||
		receipt.DeviceID != envelope.Body.DeviceID || receipt.ReportID != envelope.Body.ReportID || receipt.ReportSequence != envelope.Body.ReportSequence {
		return receipt, errors.New("[设备回执] 未绑定本次 exact signed report")
	}
	return receipt, nil
}

func validateDeviceReportReceipt(receipt DeviceReportReceiptV1) error {
	if receipt.Schema != 1 || !validIdentifier(receipt.ClusterID, 128) || !validIdentifier(receipt.DeviceID, 128) ||
		!validIdentifier(receipt.ReportID, 128) || receipt.ReportSequence < 1 || receipt.Observations == nil || len(receipt.Observations) > 256 {
		return errors.New("[设备回执] 身份、序号或观测数量无效")
	}
	if _, err := ParseHash(receipt.ReportEnvelopeHash); err != nil {
		return err
	}
	total := 0
	for _, observation := range receipt.Observations {
		total += len(observation)
		if total > 1<<20 {
			return errors.New("[设备回执] 观测超过大小边界")
		}
		var object map[string]json.RawMessage
		if _, err := DecodeStrict(observation, 1<<20, &object); err != nil || len(object) == 0 {
			return errors.New("[设备回执] 观测不是 JSON 对象")
		}
	}
	return nil
}
