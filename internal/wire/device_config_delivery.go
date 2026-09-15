package wire

import (
	"bytes"
	"errors"
)

const DeviceConfigDeliveryMediaTypeV1 = "application/vnd.loom.device-config-delivery.v1+json"

// DeviceConfigUpdateV1 是 private device_config 保留窗口中的一个完整 Device
// certified-head 坐标。authority 变化的那一步必须携对应的唯一 transition bundle；
// 普通 Head 只携同 authority 签出的 view。recovery policy preimage 可随任一坐标
// 交付，但必须命中该 Head 已承诺的 hash。
type DeviceConfigUpdateV1 struct {
	Schema                      int                               `json:"schema"`
	Envelope                    DeviceViewEnvelopeV2              `json:"envelope"`
	ControlSet                  ControlSetV1                      `json:"control_set"`
	PreviousControlSet          *ControlSetV1                     `json:"previous_control_set,omitempty"`
	RecoveryPolicy              *RecoveryPolicyV1                 `json:"recovery_policy,omitempty"`
	ControlSetTransition        *ControlSetTransitionBundleV1     `json:"control_set_transition,omitempty"`
	EmergencyRecoveryTransition *EmergencyRecoveryBundleV1        `json:"emergency_recovery_transition,omitempty"`
	RecoveryPolicyTransition    *RecoveryPolicyActivationBundleV1 `json:"recovery_policy_transition,omitempty"`
}

type DeviceConfigDeliveryV1 struct {
	Schema          int                      `json:"schema"`
	ClusterID       string                   `json:"cluster_id"`
	DeviceID        string                   `json:"device_id"`
	Updates         []DeviceConfigUpdateV1   `json:"updates"`
	SecretEnvelopes []SealedSecretEnvelopeV1 `json:"secret_envelopes,omitempty"`
}

// VerifiedDeviceConfigDeliveryV1 的字段不导出，调用方不能跳过完整 lineage 验证
// 自行把网络输入包装成可信状态。
type VerifiedDeviceConfigDeliveryV1 struct {
	floors             ClientFloorsV2
	envelope           DeviceViewEnvelopeV2
	controlSet         ControlSetV1
	previousControlSet *ControlSetV1
	recoveryPolicy     *RecoveryPolicyV1
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

func (verified VerifiedDeviceConfigDeliveryV1) RecoveryPolicy() *RecoveryPolicyV1 {
	if verified.recoveryPolicy == nil {
		return nil
	}
	value := cloneDeviceConfigValue(*verified.recoveryPolicy)
	return &value
}

// ValidateDeviceConfigDelivery 验证服务端保留的完整更新窗口。首项是窗口锚点，
// 后续每个 certified Head 都必须能从前一项连续推进；不得只拼一张新集合自签 view。
func ValidateDeviceConfigDelivery(delivery *DeviceConfigDeliveryV1) error {
	if delivery == nil || delivery.Schema != 1 || !validIdentifier(delivery.ClusterID, 128) ||
		!validIdentifier(delivery.DeviceID, 128) || len(delivery.Updates) == 0 || len(delivery.Updates) > 4096 {
		return errors.New("[device_config] delivery header/update window 无效")
	}
	first := &delivery.Updates[0]
	if deviceConfigTransitionCount(first) != 0 {
		return errors.New("[device_config] delivery 首项必须是已认证窗口锚点")
	}
	floors, err := verifyDeviceConfigUpdate(first, delivery.ClusterID, delivery.DeviceID)
	if err != nil {
		return err
	}
	set := first.ControlSet
	previous := first.PreviousControlSet
	envelope := first.Envelope
	policy, err := verifiedDeviceConfigRecoveryPolicy(first.RecoveryPolicy, floors.RecoveryPolicyHash)
	if err != nil {
		return err
	}
	for index := 1; index < len(delivery.Updates); index++ {
		update := &delivery.Updates[index]
		candidate, err := verifyDeviceConfigUpdate(update, delivery.ClusterID, delivery.DeviceID)
		if err != nil {
			return err
		}
		floors, set, previous, envelope, policy, err = advanceDeviceConfigUpdate(
			floors, set, previous, envelope, update, policy, candidate,
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
		return errors.New("[device_config] sealed envelopes 未 exact 覆盖 final refs")
	}
	for index := range delivery.SecretEnvelopes {
		var ref SecretArtifactRefV2
		canonical, err := DecodeStrict(last.SecretArtifactRefs[index], 4<<20, &ref)
		if err != nil || !bytes.Equal(canonical, last.SecretArtifactRefs[index]) ||
			ref.ClusterID != delivery.ClusterID || ref.Owner.Kind != "device" ||
			ref.Owner.Device == nil || ref.Owner.Device.DeviceID != delivery.DeviceID ||
			VerifySealedSecretBinding(&ref, &delivery.SecretEnvelopes[index]) != nil {
			return errors.New("[device_config] sealed envelope 未绑定 final exact Device ref")
		}
	}
	return nil
}

// VerifyDeviceConfigDeliveryFromProtected 要求 delivery 窗口中存在 protected exact
// head/floors，然后只重放其后缀。窗口截断越过离线 LKG 时失败关闭并保留原状态。
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
		return VerifiedDeviceConfigDeliveryV1{}, errors.New("[device_config] protected anchor/identity 不完整")
	}
	verifiedCurrent, err := VerifyDeviceViewEnvelopeWithPrevious(currentEnvelope, currentSet, currentPreviousSet)
	if err == nil && currentEnvelope.SignedCurrent.Head.Body.Payload.HeadKind != "bootstrap" {
		verifiedCurrent.BootstrapTransitionHash = currentFloors.BootstrapTransitionHash
	}
	if err != nil || !EqualCanonical(verifiedCurrent, currentFloors) ||
		currentEnvelope.Payload.DeviceID != expectedDeviceID ||
		currentEnvelope.Payload.State == "active" &&
			currentEnvelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return VerifiedDeviceConfigDeliveryV1{}, errors.New("[device_config] protected anchor 无法重放")
	}
	anchor := -1
	for index := range delivery.Updates {
		candidate, err := VerifyDeviceViewEnvelopeWithPrevious(&delivery.Updates[index].Envelope,
			&delivery.Updates[index].ControlSet, delivery.Updates[index].PreviousControlSet)
		if err == nil && delivery.Updates[index].Envelope.SignedCurrent.Head.Body.Payload.HeadKind != "bootstrap" {
			candidate.BootstrapTransitionHash = currentFloors.BootstrapTransitionHash
		}
		if err == nil && EqualCanonical(candidate, currentFloors) &&
			delivery.Updates[index].Envelope.SignedCurrent.Head.HeadHash == currentEnvelope.SignedCurrent.Head.HeadHash {
			anchor = index
			break
		}
	}
	if anchor < 0 {
		return VerifiedDeviceConfigDeliveryV1{}, errors.New("[device_config] delivery window 不含 protected exact Head")
	}
	floors := currentFloors
	set := cloneDeviceConfigValue(*currentSet)
	var previous *ControlSetV1
	if currentPreviousSet != nil {
		value := cloneDeviceConfigValue(*currentPreviousSet)
		previous = &value
	}
	envelope := cloneDeviceConfigValue(*currentEnvelope)
	var policy *RecoveryPolicyV1
	for index := anchor; index >= 0; index-- {
		anchorPolicy := delivery.Updates[index].RecoveryPolicy
		if anchorPolicy != nil {
			policy, err = verifiedDeviceConfigRecoveryPolicy(anchorPolicy, currentFloors.RecoveryPolicyHash)
			if err != nil {
				return VerifiedDeviceConfigDeliveryV1{}, err
			}
			break
		}
	}
	for index := anchor + 1; index < len(delivery.Updates); index++ {
		update := &delivery.Updates[index]
		candidate, err := verifyDeviceConfigUpdate(update, delivery.ClusterID, delivery.DeviceID)
		if err != nil {
			return VerifiedDeviceConfigDeliveryV1{}, err
		}
		if update.Envelope.Payload.State == "active" &&
			update.Envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
			return VerifiedDeviceConfigDeliveryV1{}, errors.New("[device_config] update view identity 被替换")
		}
		floors, set, previous, envelope, policy, err = advanceDeviceConfigUpdate(
			floors, set, previous, envelope, update, policy, candidate,
		)
		if err != nil {
			return VerifiedDeviceConfigDeliveryV1{}, err
		}
	}
	last := &delivery.Updates[len(delivery.Updates)-1]
	if last.Envelope.Payload.State == "active" &&
		last.Envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return VerifiedDeviceConfigDeliveryV1{}, errors.New("[device_config] final view identity 被替换")
	}
	return VerifiedDeviceConfigDeliveryV1{
		floors: floors, envelope: cloneDeviceConfigValue(last.Envelope),
		controlSet: set, previousControlSet: previous, recoveryPolicy: policy,
	}, nil
}

func verifyDeviceConfigUpdate(update *DeviceConfigUpdateV1, clusterID, deviceID string) (ClientFloorsV2, error) {
	if update == nil || update.Schema != 1 || update.Envelope.Payload.ClusterID != clusterID ||
		update.Envelope.Payload.DeviceID != deviceID || deviceConfigTransitionCount(update) > 1 {
		return ClientFloorsV2{}, errors.New("[device_config] update cluster/Device/schema 无效")
	}
	floors, err := VerifyDeviceViewEnvelopeWithPrevious(&update.Envelope, &update.ControlSet, update.PreviousControlSet)
	if err != nil {
		return ClientFloorsV2{}, err
	}
	if update.RecoveryPolicy != nil {
		if _, err := verifiedDeviceConfigRecoveryPolicy(update.RecoveryPolicy, floors.RecoveryPolicyHash); err != nil {
			return ClientFloorsV2{}, err
		}
	}
	return floors, nil
}

func advanceDeviceConfigUpdate(currentFloors ClientFloorsV2, currentSet ControlSetV1,
	currentPreviousSet *ControlSetV1, currentEnvelope DeviceViewEnvelopeV2, update *DeviceConfigUpdateV1,
	currentPolicy *RecoveryPolicyV1, candidate ClientFloorsV2,
) (ClientFloorsV2, ControlSetV1, *ControlSetV1, DeviceViewEnvelopeV2, *RecoveryPolicyV1, error) {
	if err := VerifyDeviceViewSuccessor(&currentEnvelope, &update.Envelope); err != nil {
		return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
	}
	switch {
	case update.EmergencyRecoveryTransition != nil:
		bundle := update.EmergencyRecoveryTransition
		if currentPolicy == nil || update.RecoveryPolicy == nil || update.PreviousControlSet != nil ||
			!EqualCanonical(bundle.NewControlSet, update.ControlSet) ||
			!EqualCanonical(bundle.NewRecoveryPolicy, *update.RecoveryPolicy) {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy,
				errors.New("[device_config] emergency recovery new authority binding 无效")
		}
		transition, err := VerifyEmergencyRecoveryBundle(bundle, currentPolicy,
			&currentEnvelope.SignedCurrent.Head)
		if err != nil {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
		}
		next, err := AdvanceFloorsWithRecovery(currentFloors, candidate, transition)
		if err != nil {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
		}
		policy := cloneDeviceConfigValue(*update.RecoveryPolicy)
		return next, cloneDeviceConfigValue(update.ControlSet), nil,
			cloneDeviceConfigValue(update.Envelope), &policy, nil

	case update.RecoveryPolicyTransition != nil:
		bundle := update.RecoveryPolicyTransition
		if currentPolicy == nil || update.RecoveryPolicy == nil ||
			!EqualCanonical(currentSet, update.ControlSet) ||
			!EqualCanonical(bundle.NewRecoveryPolicy, *update.RecoveryPolicy) ||
			!equalOptionalDeviceConfigControlSet(currentPreviousSet, update.PreviousControlSet) {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy,
				errors.New("[device_config] recovery policy transition authority binding 无效")
		}
		transition, err := VerifyRecoveryPolicyActivationBundle(bundle, currentPolicy,
			&currentSet, &currentEnvelope.SignedCurrent.Head)
		if err != nil {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
		}
		next, err := AdvanceFloorsWithRecoveryPolicy(currentFloors, candidate, transition)
		if err != nil {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
		}
		policy := cloneDeviceConfigValue(*update.RecoveryPolicy)
		return next, cloneDeviceConfigValue(update.ControlSet), cloneOptionalDeviceConfigControlSet(update.PreviousControlSet),
			cloneDeviceConfigValue(update.Envelope), &policy, nil

	case update.ControlSetTransition == nil:
		if ValidateHeadEntry(&update.Envelope.SignedCurrent.Head,
			&currentEnvelope.SignedCurrent.Head) != nil ||
			update.Envelope.SignedCurrent.Head.Body.Payload.HeadKind != "ordinary" {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy,
				errors.New("[device_config] 普通 update Head lineage 不连续")
		}
		next, err := AdvanceFloors(currentFloors, candidate)
		if err != nil || !EqualCanonical(currentSet, update.ControlSet) {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy,
				errors.New("[device_config] 普通 update 改变了 ControlSet authority")
		}
		if !equalOptionalDeviceConfigControlSet(currentPreviousSet, update.PreviousControlSet) {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy,
				errors.New("[device_config] 普通 update 的 previous ControlSet 分叉")
		}
		policy, err := carryDeviceConfigRecoveryPolicy(currentPolicy, update.RecoveryPolicy, candidate.RecoveryPolicyHash)
		if err != nil {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
		}
		return next, cloneDeviceConfigValue(update.ControlSet), cloneOptionalDeviceConfigControlSet(update.PreviousControlSet),
			cloneDeviceConfigValue(update.Envelope), policy, nil

	default:
		if !EqualCanonical(update.ControlSetTransition.OldControlSet, currentSet) ||
			!EqualCanonical(update.ControlSetTransition.NewControlSet, update.ControlSet) ||
			update.PreviousControlSet == nil || !EqualCanonical(*update.PreviousControlSet, currentSet) {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy,
				errors.New("[device_config] ControlSet transition old/new/previous binding 无效")
		}
		transition, err := VerifyControlSetTransitionBundle(update.ControlSetTransition, &currentEnvelope.SignedCurrent.Head)
		if err != nil {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
		}
		next, err := AdvanceFloorsWithControl(currentFloors, candidate, transition)
		if err != nil {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
		}
		policy, err := carryDeviceConfigRecoveryPolicy(currentPolicy, update.RecoveryPolicy, candidate.RecoveryPolicyHash)
		if err != nil {
			return currentFloors, currentSet, currentPreviousSet, currentEnvelope, currentPolicy, err
		}
		previous := cloneDeviceConfigValue(currentSet)
		return next, cloneDeviceConfigValue(update.ControlSet), &previous,
			cloneDeviceConfigValue(update.Envelope), policy, nil
	}
}

func deviceConfigTransitionCount(update *DeviceConfigUpdateV1) int {
	if update == nil {
		return 0
	}
	count := 0
	for _, present := range []bool{update.ControlSetTransition != nil,
		update.EmergencyRecoveryTransition != nil, update.RecoveryPolicyTransition != nil} {
		if present {
			count++
		}
	}
	return count
}

func verifiedDeviceConfigRecoveryPolicy(policy *RecoveryPolicyV1, expectedHash string) (*RecoveryPolicyV1, error) {
	if policy == nil {
		return nil, nil
	}
	hash, err := RecoveryPolicyHash(policy)
	if err != nil || hash != expectedHash {
		return nil, errors.New("[device_config] recovery policy preimage 未绑定 certified Head")
	}
	value := cloneDeviceConfigValue(*policy)
	return &value, nil
}

func carryDeviceConfigRecoveryPolicy(current, candidate *RecoveryPolicyV1,
	expectedHash string,
) (*RecoveryPolicyV1, error) {
	if candidate == nil {
		return current, nil
	}
	verified, err := verifiedDeviceConfigRecoveryPolicy(candidate, expectedHash)
	if err != nil {
		return current, err
	}
	if current != nil && !EqualCanonical(*current, *verified) {
		return current, errors.New("[device_config] 非 recovery update 改写了 recovery policy")
	}
	return verified, nil
}

func equalOptionalDeviceConfigControlSet(left, right *ControlSetV1) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return EqualCanonical(*left, *right)
}

func cloneOptionalDeviceConfigControlSet(value *ControlSetV1) *ControlSetV1 {
	if value == nil {
		return nil
	}
	copy := cloneDeviceConfigValue(*value)
	return &copy
}

func cloneDeviceConfigValue[T any](value T) T {
	body, _ := MarshalCanonical(value)
	var cloned T
	_, _ = DecodeStrict(body, 64<<20, &cloned)
	return cloned
}
