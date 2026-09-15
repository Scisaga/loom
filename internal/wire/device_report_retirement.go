package wire

import (
	"crypto/ecdsa"
	"errors"
	"time"
)

// RetiredDeviceReportV1 保留无法继续发送的原签名；它不表示服务端接受。
type RetiredDeviceReportV1 struct {
	Envelope  DeviceReportEnvelopeV2 `json:"envelope"`
	Floors    ClientFloorsV2         `json:"floors"`
	RetiredAt string                 `json:"retired_at"`
	Reason    string                 `json:"reason"`
}

// RetireObsoleteDeviceReport 只接收正常 Device state reader 已完整验证并持久化的
// floors，不能用于认证来自 HTTP 的裸 floors。序号已被占用，退休后也不能复用。
func RetireObsoleteDeviceReport(envelope *DeviceReportEnvelopeV2, verifiedFloors ClientFloorsV2,
	identity *ecdsa.PublicKey, deviceID, identityHash string, now time.Time,
	schemas DeviceReportSchemaRegistry) (*RetiredDeviceReportV1, error) {
	if envelope == nil || now.IsZero() || validateClientFloors(verifiedFloors) != nil {
		return nil, errors.New("[device_report] 退休上下文无效")
	}
	generated, err := ParseTimeZ(envelope.Body.GeneratedAt)
	if err != nil || VerifyDeviceReport(envelope, identity, deviceID, identityHash, generated, 0, 0, schemas) != nil {
		return nil, errors.New("[device_report] 待退休报告签名无效")
	}
	previous := envelope.Body.AcceptedFloors
	if previous.ClusterID != verifiedFloors.ClusterID || previous.BootstrapTransitionHash != verifiedFloors.BootstrapTransitionHash ||
		previous.AcceptedRecoveryEpoch > verifiedFloors.AcceptedRecoveryEpoch || previous.DeviceGeneration > verifiedFloors.DeviceGeneration {
		return nil, errors.New("[device_report] 当前认证状态不能覆盖 pending")
	}
	if previous.AcceptedRecoveryEpoch == verifiedFloors.AcceptedRecoveryEpoch {
		if previous.RecoveryStatementHash != verifiedFloors.RecoveryStatementHash || previous.RecoveryPolicyHash != verifiedFloors.RecoveryPolicyHash ||
			previous.AcceptedControlEpoch > verifiedFloors.AcceptedControlEpoch {
			return nil, errors.New("[device_report] pending 与当前 authority 分叉")
		}
		if previous.AcceptedControlEpoch == verifiedFloors.AcceptedControlEpoch {
			if _, err := AdvanceFloors(previous, verifiedFloors); err != nil {
				return nil, err
			}
		}
	}
	if previous.DeviceGeneration == verifiedFloors.DeviceGeneration &&
		(previous.DeviceLeafHash != verifiedFloors.DeviceLeafHash || previous.DeviceViewHash != verifiedFloors.DeviceViewHash) {
		return nil, errors.New("[device_report] 相同 Device generation 不得退休分叉报告")
	}
	reason := ""
	if !EqualCanonical(previous, verifiedFloors) {
		reason = "superseded_floors"
	} else if generated.Before(now.UTC().Add(-24*time.Hour - 5*time.Minute)) {
		reason = "expired"
	}
	if reason == "" {
		return nil, nil
	}
	return &RetiredDeviceReportV1{Envelope: *envelope, Floors: verifiedFloors,
		RetiredAt: now.UTC().Truncate(time.Second).Format(time.RFC3339), Reason: reason}, nil
}

// RetiredDeviceReportSequence 同时校验 journal 中的退休记录，成功序号另行保留。
func RetiredDeviceReportSequence(retired *RetiredDeviceReportV1, deviceID string) (int64, error) {
	if retired == nil {
		return 0, nil
	}
	if retired.Envelope.Schema != 2 || retired.Envelope.Body.DeviceID != deviceID || retired.Envelope.Body.ReportSequence < 1 ||
		(retired.Reason != "expired" && retired.Reason != "superseded_floors") || validateClientFloors(retired.Floors) != nil {
		return 0, errors.New("[device_report] journal 退休记录无效")
	}
	if _, err := ParseTimeZ(retired.RetiredAt); err != nil {
		return 0, err
	}
	return retired.Envelope.Body.ReportSequence, nil
}
