package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

// controlRaftLog 返回验证器当前可见的 exact 日志。verificationLog 只在处理
// 尚未 fsync 的 AppendEntries 时由隔离的 verifier runtime 设置。
func (runtime *controlRuntime) controlRaftLog() []controlplane.RaftLogRecordV1 {
	if runtime.verificationLog != nil {
		return controlClone(runtime.verificationLog)
	}
	if runtime.storage == nil {
		return nil
	}
	return runtime.storage.SnapshotRaft().Log
}

func (runtime *controlRuntime) verifyRaftHeadCandidate(ctx context.Context, head wire.HeadEntryV2,
	appendPrefix []controlplane.RaftLogRecordV1) error {
	return runtime.verifyHeadFromOperationMaterials(ctx, head, appendPrefix)
}

func (runtime *controlRuntime) verifyHeadFromOperationMaterials(ctx context.Context,
	head wire.HeadEntryV2, appendPrefix []controlplane.RaftLogRecordV1) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	verificationLog, err := runtime.controlVerificationLog(appendPrefix)
	if err != nil {
		return err
	}
	if head.Body.Payload.HeadKind == "bootstrap" {
		if head.Body.Payload.RaftIndex != 1 {
			return errors.New("bootstrap Head index 无效")
		}
		return wire.ValidateHeadEntry(&head, nil)
	}
	journal, err := runtime.operationJournalForHead(head, verificationLog)
	if err != nil {
		return err
	}
	verifier := &controlRuntime{dir: runtime.dir, config: controlClone(runtime.config),
		journal: journal, controlTLS: runtime.controlTLS, storage: runtime.storage,
		verificationLog: verificationLog, now: runtime.now}
	firstUnapplied := 0
	if runtime.storage != nil {
		lastApplied := runtime.storage.SnapshotRaft().LastApplied
		for firstUnapplied < len(verifier.journal.Records) &&
			verifier.journal.Records[firstUnapplied].Candidate.Body.Payload.RaftIndex <= lastApplied {
			firstUnapplied++
		}
	}
	for index := firstUnapplied; index < len(verifier.journal.Records); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifier.verifyOperationRecord(index); err != nil {
			return fmt.Errorf("[operation material] record[%d] 重算失败: %w", index, err)
		}
	}
	object, err := newControlOperationMaterialObject(
		verifier.journal.Records[len(verifier.journal.Records)-1])
	if err != nil {
		return err
	}
	runtime.verifiedMaterials.Store(head.EntryHash, object.ObjectID)
	return nil
}

func (runtime *controlRuntime) operationMaterialAlreadyVerified(head wire.HeadEntryV2) bool {
	if runtime.operationMaterials == nil || head.Body.Payload.HeadKind == "bootstrap" {
		return false
	}
	remembered, ok := runtime.verifiedMaterials.Load(head.EntryHash)
	if !ok {
		return false
	}
	objectID, ok := remembered.(string)
	if !ok || objectID == "" {
		return false
	}
	for _, object := range runtime.operationMaterials.Snapshot() {
		if object.ID != head.EntryHash || object.ObjectID != objectID {
			continue
		}
		material, err := decodeControlOperationMaterialObject(object)
		return err == nil && wire.EqualCanonical(material.Candidate, head)
	}
	return false
}

func (runtime *controlRuntime) controlVerificationLog(
	appendPrefix []controlplane.RaftLogRecordV1) ([]controlplane.RaftLogRecordV1, error) {
	current := runtime.controlRaftLog()
	if len(appendPrefix) == 0 {
		return current, nil
	}
	first := appendPrefix[0].Index
	if first < 1 || first > int64(len(current))+1 {
		return nil, errors.New("[operation material] AppendEntries prefix 起点与本机日志不连续")
	}
	combined := append([]controlplane.RaftLogRecordV1(nil), current[:first-1]...)
	for index := range appendPrefix {
		record := appendPrefix[index]
		if record.Index != int64(len(combined))+1 {
			return nil, errors.New("[operation material] AppendEntries prefix index 不连续")
		}
		combined = append(combined, controlClone(record))
	}
	return combined, nil
}

func (runtime *controlRuntime) operationJournalForHead(head wire.HeadEntryV2,
	verificationLog []controlplane.RaftLogRecordV1) (controlOperationJournalV1, error) {
	journal := controlOperationJournalV1{Schema: 1, Records: []controlOperationRecordV1{}}
	if runtime.operationMaterials == nil {
		return journal, errors.New("[operation material] store 未初始化")
	}
	materials := make(map[string]controlOperationMaterialV1)
	for _, object := range runtime.operationMaterials.Snapshot() {
		material, err := decodeControlOperationMaterialObject(object)
		if err != nil {
			return journal, err
		}
		materials[material.Candidate.EntryHash] = material
	}
	found := false
	for _, raftRecord := range verificationLog {
		if raftRecord.Index > head.Body.Payload.RaftIndex {
			break
		}
		if raftRecord.Kind != controlplane.RaftRecordHead || raftRecord.Head == nil {
			continue
		}
		candidate := *raftRecord.Head
		if raftRecord.Index == head.Body.Payload.RaftIndex {
			if raftRecord.EntryHash != head.EntryHash || !wire.EqualCanonical(candidate, head) {
				return journal, errors.New("[operation material] candidate 不属于 exact Raft prefix")
			}
			found = true
		}
		if candidate.Body.Payload.HeadKind == "bootstrap" {
			continue
		}
		expectedHeadKind := "ordinary"
		if material, ok := materials[candidate.EntryHash]; ok && material.Activation != nil {
			expectedHeadKind = "legacy_runtime_activation"
		}
		if candidate.Body.Payload.HeadKind != expectedHeadKind {
			return journal, errors.New("[operation material] Head kind 与 reducer preimage union 不一致")
		}
		material, ok := materials[candidate.EntryHash]
		if !ok || !wire.EqualCanonical(material.Candidate, candidate) {
			return journal, errors.New("[operation material] Raft Head 缺 exact durable reducer preimage")
		}
		record := controlOperationMaterialRecord(material)
		if candidate.EntryHash != head.EntryHash {
			record.Result = &controlCertifiedOperationResultV1{Schema: 1, Status: "certified", Head: candidate}
			record.Phases = []controlplane.Phase{controlplane.PhaseApplied}
		}
		journal.Records = append(journal.Records, record)
	}
	if !found || len(journal.Records) == 0 ||
		journal.Records[len(journal.Records)-1].Candidate.EntryHash != head.EntryHash {
		return journal, errors.New("[operation material] target Head 不在可验证日志或缺 preimage")
	}
	return journal, nil
}

func (runtime *controlRuntime) verifyOperationRecord(index int) error {
	if index < 0 || index >= len(runtime.journal.Records) {
		return errors.New("[operation material] journal index 无效")
	}
	record := &runtime.journal.Records[index]
	leaves := runtime.operationLeaves(index + 1)
	root, err := wire.ControlOperationRoot(leaves)
	if err != nil || root != record.Candidate.Body.Payload.OperationRoot {
		return errors.New("operation journal 与 committed Head root 不匹配")
	}
	if record.AdminRotation != nil {
		return runtime.verifyAdminRotationRecord(index)
	}
	if record.Activation != nil {
		return runtime.verifyActivationRecord(index)
	}
	if record.Enrollment != nil {
		return runtime.verifyEnrollmentRecord(index)
	}
	return runtime.verifyAdminOperationRecord(index)
}
