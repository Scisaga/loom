package wire

import (
	"bytes"
	"errors"
)

const DeviceConfigDeliveryMediaTypeV1 = "application/vnd.loom.device-config-delivery.v1+json"

// DeviceConfigUpdateV1 是 private device_config 保留窗口中的一个完整 Device
// certified-head 坐标。ControlSet 变化的那一步必须携 Joint→Final bundle；普通
// Head 只携同集合签出的 view。客户端由自己当前 exact head 定位后重放后缀（D112、D131）。
type DeviceConfigUpdateV1 struct {
	Schema               int                           `json:"schema"`
	Envelope             DeviceViewEnvelopeV2          `json:"envelope"`
	ControlSet           ControlSetV1                  `json:"control_set"`
	PreviousControlSet   *ControlSetV1                 `json:"previous_control_set,omitempty"`
	ControlSetTransition *ControlSetTransitionBundleV1 `json:"control_set_transition,omitempty"`
}

type DeviceConfigDeliveryV1 struct {
	Schema          int                      `json:"schema"`
	ClusterID       string                   `json:"cluster_id"`
	DeviceID        string                   `json:"device_id"`
	Updates         []DeviceConfigUpdateV1   `json:"updates"`
	SecretEnvelopes []SealedSecretEnvelopeV1 `json:"secret_envelopes,omitempty"`
}

// VerifiedDeviceConfigDeliveryV1 的字段不导出，调用方不能跳过完整 lineage 验证
// 自行把网络输入包装成可信状态（D105、D112）。
type VerifiedDeviceConfigDeliveryV1 struct {
	floors             ClientFloorsV2
	envelope           DeviceViewEnvelopeV2
	controlSet         ControlSetV1
	previousControlSet *ControlSetV1
}

func (verified VerifiedDeviceConfigDeliveryV1) Floors() ClientFloorsV2 {
	return verified.floors
}

func (verified VerifiedDeviceConfigDeliveryV1) Envelope() DeviceViewEnvelopeV2 {
	return cloneDeviceConfigValue(verified.envelope)
}

func (verified VerifiedDeviceConfigDeliveryV1) ControlSet() ControlSetV1 {
	return cloneDeviceConfigValue(verified.controlSet)
}

func (verified VerifiedDeviceConfigDeliveryV1) PreviousControlSet() *ControlSetV1 {
	if verified.previousControlSet == nil {
		return nil
	}
	value := cloneDeviceConfigValue(*verified.previousControlSet)
	return &value
}

// ValidateDeviceConfigDelivery 验证服务端保留的完整更新窗口。首项是窗口锚点，
// 后续每个 certified Head 都必须能从前一项连续推进；不得只拼一张新集合自签 view（D112）。
func ValidateDeviceConfigDelivery(delivery *DeviceConfigDeliveryV1) error {
	if delivery == nil || delivery.Schema != 1 || !validIdentifier(delivery.ClusterID, 128) ||
		!validIdentifier(delivery.DeviceID, 128) || len(delivery.Updates) == 0 || len(delivery.Updates) > 4096 {
		return errors.New("[D131 device_config] delivery header/update window 无效")
	}
	first := &delivery.Updates[0]
	if first.ControlSetTransition != nil {
		return errors.New("[D112 device_config] delivery 首项必须是已认证窗口锚点")
	}
	floors, err := verifyDeviceConfigUpdate(first, delivery.ClusterID, delivery.DeviceID)
	if err != nil {
		return err
	}
	set := first.ControlSet
	previous := first.PreviousControlSet
	envelope := first.Envelope
	for index := 1; index < len(delivery.Updates); index++ {
		update := &delivery.Updates[index]
		candidate, err := verifyDeviceConfigUpdate(update, delivery.ClusterID, delivery.DeviceID)
		if err != nil {
			return err
		}
		floors, set, previous, envelope, err = advanceDeviceConfigUpdate(
			floors, set, previous, envelope, update, candidate,
		)
		if err != nil {
			return err
		}
	}
	return validateDeviceConfigDeliverySecrets(delivery)
}

func validateDeviceConfigDeliverySecrets(delivery *DeviceConfigDeliveryV1) error {
	if len(delivery.SecretEnvelopes) == 0 {
		return nil
	}
	last := &delivery.Updates[len(delivery.Updates)-1].Envelope
	if last.Payload.State != "active" || len(last.SecretArtifactRefs) != len(delivery.SecretEnvelopes) {
		return errors.New("[D124 device_config] sealed envelopes 未 exact 覆盖 final refs")
	}
	for index := range delivery.SecretEnvelopes {
		var ref SecretArtifactRefV2
		canonical, err := DecodeStrict(last.SecretArtifactRefs[index], 4<<20, &ref)
		if err != nil || !bytes.Equal(canonical, last.SecretArtifactRefs[index]) ||
			ref.ClusterID != delivery.ClusterID || ref.Owner.Kind != "device" ||
			ref.Owner.Device == nil || ref.Owner.Device.DeviceID != delivery.DeviceID ||
			VerifySealedSecretBinding(&ref, &delivery.SecretEnvelopes[index]) != nil {
			return errors.New("[D124 device_config] sealed envelope 未绑定 final exact Device ref")
		}
	}
	return nil
}

// VerifyDeviceConfigDeliveryFromProtected 要求 delivery 窗口中存在 protected exact
// head/floors，然后只重放其后缀。窗口截断越过离线 LKG 时失败关闭并保留原状态（D106、D131）。
func VerifyDeviceConfigDeliveryFromProtected(delivery *DeviceConfigDeliveryV1,
	currentEnvelope *DeviceViewEnvelopeV2, currentFloors ClientFloorsV2,
	currentSet *ControlSetV1, currentPreviousSet *ControlSetV1,
	expectedDeviceID, expectedIdentitySPKIHash string,
) (VerifiedDeviceConfigDeliveryV1, error) {
	if err := ValidateDeviceConfigDelivery(delivery); err != nil {
		return VerifiedDeviceConfigDeliveryV1{}, err
	}
	if currentEnvelope == nil || currentSet == nil || expectedDeviceID == "" || expectedIdentitySPKIHash == "" ||
		delivery.DeviceID != expectedDeviceID {
		return VerifiedDeviceConfigDeliveryV1{}, errors.New("[D131 device_config] protected anchor/identity 不完整")
	}
	verifiedCurrent, err := VerifyDeviceViewEnvelopeWithPrevious(currentEnvelope, currentSet, currentPreviousSet)
	if err != nil || !EqualCanonical(verifiedCurrent, currentFloors) ||
		currentEnvelope.Payload.DeviceID != expectedDeviceID ||
		currentEnvelope.Payload.State == "active" &&
			currentEnvelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return VerifiedDeviceConfigDeliveryV1{}, errors.New("[D131 device_config] protected anchor 无法重放")
	}
	anchor := -1
	for index := range delivery.Updates {
		candidate, err := VerifyDeviceViewEnvelopeWithPrevious(&delivery.Updates[index].Envelope,
			&delivery.Updates[index].ControlSet, delivery.Updates[index].PreviousControlSet)
		if err == nil && EqualCanonical(candidate, currentFloors) &&
			delivery.Updates[index].Envelope.SignedCurrent.Head.HeadHash == currentEnvelope.SignedCurrent.Head.HeadHash {
			anchor = index
			break
		}
	}
	if anchor < 0 {
		return VerifiedDeviceConfigDeliveryV1{}, errors.New("[D131 device_config] delivery window 不含 protected exact Head")
	}
	floors := currentFloors
	set := cloneDeviceConfigValue(*currentSet)
	var previous *ControlSetV1
	if currentPreviousSet != nil {
		value := cloneDeviceConfigValue(*currentPreviousSet)
		previous = &value
	}
	envelope := cloneDeviceConfigValue(*currentEnvelope)
	for index := anchor + 1; index < len(delivery.Updates); index++ {
		update := &delivery.Updates[index]
		candidate, err := verifyDeviceConfigUpdate(update, delivery.ClusterID, delivery.DeviceID)
		if err != nil {
			return VerifiedDeviceConfigDeliveryV1{}, err
		}
		if update.Envelope.Payload.State == "active" &&
			update.Envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
			return VerifiedDeviceConfigDeliveryV1{}, errors.New("[D105 device_config] update view identity 被替换")
		}
		floors, set, previous, envelope, err = advanceDeviceConfigUpdate(
			floors, set, previous, envelope, update, candidate,
		)
		if err != nil {
			return VerifiedDeviceConfigDeliveryV1{}, err
		}
	}
	last := &delivery.Updates[len(delivery.Updates)-1]
	if last.Envelope.Payload.State == "active" &&
		last.Envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return VerifiedDeviceConfigDeliveryV1{}, errors.New("[D105 device_config] final view identity 被替换")
	}
	return VerifiedDeviceConfigDeliveryV1{
		floors: floors, envelope: cloneDeviceConfigValue(last.Envelope),
		controlSet: set, previousControlSet: previous,
	}, nil
}

func verifyDeviceConfigUpdate(update *DeviceConfigUpdateV1, clusterID, deviceID string) (ClientFloorsV2, error) {
	if update == nil || update.Schema != 1 || update.Envelope.Payload.ClusterID != clusterID ||
		update.Envelope.Payload.DeviceID != deviceID {
		return ClientFloorsV2{}, errors.New("[D131 device_config] update cluster/Device/schema 无效")
	}
	return VerifyDeviceViewEnvelopeWithPrevious(&update.Envelope, &update.ControlSet, update.PreviousControlSet)
}

func advanceDeviceConfigUpdate(currentFloors ClientFloorsV2, currentSet ControlSetV1,
	currentPreviousSet *ControlSetV1, currentEnvelope DeviceViewEnvelopeV2, update *DeviceConfigUpdateV1,
	candidate ClientFloorsV2,
) (ClientFloorsV2, ControlSetV1, *ControlSetV1, DeviceViewEnvelopeV2, error) {
	if err := VerifyDeviceViewSuccessor(&currentEnvelope, &update.Envelope); err != nil {
		return currentFloors, currentSet, currentPreviousSet, currentEnvelope, err
	}
	if update.ControlSetTransition == nil {
		next, err := AdvanceFloors(currentFloors, candidate)
		if err != nil || !EqualCanonical(currentSet, update.ControlSet) {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope,
				errors.New("[D112 device_config] 普通 update 改变了 ControlSet authority")
		}
		var previous *ControlSetV1
		if update.PreviousControlSet != nil {
			if currentPreviousSet == nil || !EqualCanonical(*currentPreviousSet, *update.PreviousControlSet) {
				return currentFloors, currentSet, currentPreviousSet, currentEnvelope,
					errors.New("[D112 device_config] 普通 update 的 previous ControlSet 分叉")
			}
			value := cloneDeviceConfigValue(*update.PreviousControlSet)
			previous = &value
		}
		return next, cloneDeviceConfigValue(update.ControlSet), previous,
			cloneDeviceConfigValue(update.Envelope), nil
	}
	if !EqualCanonical(update.ControlSetTransition.OldControlSet, currentSet) ||
		!EqualCanonical(update.ControlSetTransition.NewControlSet, update.ControlSet) ||
		update.PreviousControlSet == nil || !EqualCanonical(*update.PreviousControlSet, currentSet) {
		return currentFloors, currentSet, currentPreviousSet, currentEnvelope,
			errors.New("[D112 device_config] ControlSet transition old/new/previous binding 无效")
	}
	transition, err := VerifyControlSetTransitionBundle(update.ControlSetTransition, &currentEnvelope.SignedCurrent.Head)
	if err != nil {
		return currentFloors, currentSet, currentPreviousSet, currentEnvelope, err
	}
	next, err := AdvanceFloorsWithControl(currentFloors, candidate, transition)
	if err != nil {
		return currentFloors, currentSet, currentPreviousSet, currentEnvelope, err
	}
	previous := cloneDeviceConfigValue(currentSet)
	return next, cloneDeviceConfigValue(update.ControlSet), &previous,
		cloneDeviceConfigValue(update.Envelope), nil
}

func cloneDeviceConfigValue[T any](value T) T {
	body, _ := MarshalCanonical(value)
	var cloned T
	_, _ = DecodeStrict(body, 64<<20, &cloned)
	return cloned
}
