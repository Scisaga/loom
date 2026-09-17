package main

import (
	"context"
	"encoding/json"
	"errors"

	"loom/internal/controlplane"
	"loom/internal/crdt"
	"loom/internal/wire"
)

const (
	controlOperationMaterialName = "operation-materials.json"
	controlOperationMaterialKind = "control_operation_material_v1"
)

// controlOperationMaterialV1 只包含 follower 重算 Head 所需的不可变输入。
// journal 的 result/phases 是各副本的本地执行进度，不能进入 add-only anti-entropy；
// Invite token 明文继续只存在独立 root-only secret artifact 中。
type controlOperationMaterialV1 struct {
	Schema                 int                              `json:"schema"`
	Payload                json.RawMessage                  `json:"payload,omitempty"`
	Operation              wire.ControlOperationV1          `json:"operation"`
	Leaf                   wire.ControlOperationLeafV1      `json:"leaf"`
	Candidate              wire.HeadEntryV2                 `json:"candidate"`
	AdminRotation          *controlAdminRotationV1          `json:"admin_rotation,omitempty"`
	Activation             *controlRuntimeActivationV1      `json:"activation,omitempty"`
	Enrollment             *controlEnrollmentOperationV1    `json:"enrollment,omitempty"`
	Invite                 *controlInviteStateV1            `json:"invite,omitempty"`
	DevicePublication      *controlDevicePublicationV1      `json:"device_publication,omitempty"`
	BootstrapAdvertisement *controlBootstrapAdvertisementV1 `json:"bootstrap_advertisement,omitempty"`
	AdditionalLeaves       []wire.ControlOperationLeafV1    `json:"additional_leaves,omitempty"`
}

func controlOperationMaterial(record controlOperationRecordV1) controlOperationMaterialV1 {
	return controlOperationMaterialV1{
		Schema: record.Schema, Payload: append(json.RawMessage(nil), record.Payload...),
		Operation: controlClone(record.Operation), Leaf: controlClone(record.Leaf),
		Candidate: controlClone(record.Candidate), AdminRotation: controlClonePointer(record.AdminRotation),
		Activation: controlClonePointer(record.Activation), Enrollment: controlClonePointer(record.Enrollment),
		Invite: controlClonePointer(record.Invite), DevicePublication: controlClonePointer(record.DevicePublication),
		BootstrapAdvertisement: controlClonePointer(record.BootstrapAdvertisement),
		AdditionalLeaves:       controlClone(record.AdditionalLeaves),
	}
}

func controlOperationMaterialRecord(material controlOperationMaterialV1) controlOperationRecordV1 {
	return controlOperationRecordV1{
		Schema: material.Schema, Payload: append(json.RawMessage(nil), material.Payload...),
		Operation: controlClone(material.Operation), Leaf: controlClone(material.Leaf),
		Candidate: controlClone(material.Candidate), AdminRotation: controlClonePointer(material.AdminRotation),
		Activation: controlClonePointer(material.Activation), Enrollment: controlClonePointer(material.Enrollment),
		Invite: controlClonePointer(material.Invite), DevicePublication: controlClonePointer(material.DevicePublication),
		BootstrapAdvertisement: controlClonePointer(material.BootstrapAdvertisement),
		AdditionalLeaves:       controlClone(material.AdditionalLeaves),
		Phases:                 []controlplane.Phase{controlplane.PhasePending},
	}
}

func controlClonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := controlClone(*value)
	return &cloned
}

func newControlOperationMaterialObject(record controlOperationRecordV1) (crdt.Object, error) {
	material := controlOperationMaterial(record)
	if err := validateControlOperationMaterial(&material); err != nil {
		return crdt.Object{}, err
	}
	payload, err := wire.MarshalCanonical(material)
	if err != nil {
		return crdt.Object{}, err
	}
	return crdt.NewObject(material.Candidate.EntryHash, controlOperationMaterialKind, payload)
}

func decodeControlOperationMaterialObject(object crdt.Object) (controlOperationMaterialV1, error) {
	var material controlOperationMaterialV1
	if object.Kind != controlOperationMaterialKind || object.ID == "" {
		return material, errors.New("[operation material] CRDT object kind/id 无效")
	}
	rebuiltObject, err := crdt.NewObject(object.ID, object.Kind, object.Payload)
	if err != nil || rebuiltObject.ObjectID != object.ObjectID {
		return material, errors.New("[operation material] CRDT object hash 无效")
	}
	canonical, err := wire.DecodeStrict(object.Payload, 64<<20, &material)
	if err != nil || string(canonical) != string(object.Payload) {
		return material, errors.New("[operation material] payload 不是 exact canonical wire")
	}
	if err := validateControlOperationMaterial(&material); err != nil {
		return material, err
	}
	if object.ID != material.Candidate.EntryHash {
		return material, errors.New("[operation material] logical ID 未绑定 candidate entry")
	}
	return material, nil
}

func validateControlOperationMaterial(material *controlOperationMaterialV1) error {
	if material == nil || material.Schema != 1 || material.Candidate.Body.Payload.HeadKind == "bootstrap" ||
		material.Candidate.Body.Payload.RaftIndex < 2 || material.Leaf.Schema != 1 ||
		material.Leaf.OperationID == "" {
		return errors.New("[operation material] schema/candidate/leaf 无效")
	}
	if _, err := wire.ParseHash(material.Leaf.ObjectID); err != nil {
		return err
	}
	rebuilt, err := wire.NewHeadEntry(material.Candidate.Body)
	if err != nil || !wire.EqualCanonical(rebuilt, material.Candidate) {
		return errors.New("[operation material] candidate Head hash/binding 无效")
	}
	seen := map[string]struct{}{material.Leaf.OperationID: {}}
	for index := range material.AdditionalLeaves {
		leaf := &material.AdditionalLeaves[index]
		if leaf.Schema != 1 || leaf.OperationID == "" {
			return errors.New("[operation material] additional leaf 无效")
		}
		if _, err := wire.ParseHash(leaf.ObjectID); err != nil {
			return err
		}
		if _, exists := seen[leaf.OperationID]; exists {
			return errors.New("[operation material] operation leaf ID 重复")
		}
		seen[leaf.OperationID] = struct{}{}
	}
	special := 0
	for _, present := range []bool{material.AdminRotation != nil, material.Activation != nil,
		material.Enrollment != nil} {
		if present {
			special++
		}
	}
	if special > 1 {
		return errors.New("[operation material] reducer preimage union 冲突")
	}
	if special == 0 && material.Operation.Body.OperationID == "" {
		return errors.New("[operation material] 管理 operation 缺签名 envelope")
	}
	return nil
}

func (runtime *controlRuntime) verifyControlOperationMaterialObject(_ context.Context,
	object crdt.Object) error {
	_, err := decodeControlOperationMaterialObject(object)
	return err
}

func (runtime *controlRuntime) persistOperationMaterialsLocked() error {
	if runtime.operationMaterials == nil {
		return errors.New("[operation material] store 未初始化")
	}
	for index := range runtime.journal.Records {
		object, err := newControlOperationMaterialObject(runtime.journal.Records[index])
		if err != nil {
			return err
		}
		if err := runtime.operationMaterials.Add(object); err != nil {
			return err
		}
	}
	return nil
}
