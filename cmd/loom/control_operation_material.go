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
	controlOperationMaterialName          = "operation-materials.json"
	controlOperationMaterialKind          = "control_operation_material_v1"
	controlHeadCertificationMaterialKind  = "control_head_certification_material_v1"
	controlHeadCertificationLogicalSuffix = ".certification"
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

// controlHeadCertificationMaterialV1 保存已由 committed ControlSet 形成的 exact
// QC。它与 reducer preimage 分成两个 add-only 对象，避免在认证后改写原 CRDT
// 对象；learner 可据此按 Raft 顺序逐条恢复历史 certified Head。
type controlHeadCertificationMaterialV1 struct {
	Schema     int                            `json:"schema"`
	Head       wire.HeadEntryV2               `json:"head"`
	ControlSet wire.ControlSetV1              `json:"control_set"`
	QC         wire.StableHeadReplicationQCV1 `json:"qc"`
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

func newControlHeadCertificationMaterialObject(head wire.HeadEntryV2, set wire.ControlSetV1,
	qc wire.StableHeadReplicationQCV1) (crdt.Object, error) {
	material := controlHeadCertificationMaterialV1{Schema: 1, Head: controlClone(head),
		ControlSet: controlClone(set), QC: controlClone(qc)}
	if err := validateControlHeadCertificationMaterial(&material); err != nil {
		return crdt.Object{}, err
	}
	logicalID, err := controlHeadCertificationLogicalID(&material)
	if err != nil {
		return crdt.Object{}, err
	}
	payload, err := wire.MarshalCanonical(material)
	if err != nil {
		return crdt.Object{}, err
	}
	return crdt.NewObject(logicalID,
		controlHeadCertificationMaterialKind, payload)
}

func decodeControlHeadCertificationMaterialObject(object crdt.Object) (controlHeadCertificationMaterialV1, error) {
	var material controlHeadCertificationMaterialV1
	if object.Kind != controlHeadCertificationMaterialKind || object.ID == "" {
		return material, errors.New("[Head certification material] CRDT object kind/id 无效")
	}
	rebuiltObject, err := crdt.NewObject(object.ID, object.Kind, object.Payload)
	if err != nil || rebuiltObject.ObjectID != object.ObjectID {
		return material, errors.New("[Head certification material] CRDT object hash 无效")
	}
	canonical, err := wire.DecodeStrict(object.Payload, 16<<20, &material)
	if err != nil || string(canonical) != string(object.Payload) {
		return material, errors.New("[Head certification material] payload 不是 exact canonical wire")
	}
	if err := validateControlHeadCertificationMaterial(&material); err != nil {
		return material, err
	}
	logicalID, err := controlHeadCertificationLogicalID(&material)
	if err != nil || object.ID != logicalID {
		return material, errors.New("[Head certification material] logical ID 未绑定 Head")
	}
	return material, nil
}

// 同一 Head 在 leader 换届时可能形成不同但都有效的 quorum signer 子集。logical
// ID 必须同时绑定 QC hash，才能让 add-only union 保存这些证明而不是制造伪冲突。
func controlHeadCertificationLogicalID(material *controlHeadCertificationMaterialV1) (string, error) {
	if material == nil {
		return "", errors.New("[Head certification material] material 不能为空")
	}
	qcHash, err := wire.QCStableHash(&material.QC)
	if err != nil {
		return "", err
	}
	return material.Head.EntryHash + controlHeadCertificationLogicalSuffix + "." + qcHash, nil
}

func validateControlHeadCertificationMaterial(material *controlHeadCertificationMaterialV1) error {
	if material == nil || material.Schema != 1 {
		return errors.New("[Head certification material] schema 无效")
	}
	if err := wire.ValidateHeadEntry(&material.Head, nil); err != nil {
		return err
	}
	setHash, err := wire.ControlSetHash(&material.ControlSet)
	if err != nil || setHash != material.Head.Body.Payload.ControlSetHash {
		return errors.New("[Head certification material] ControlSet 未绑定 Head")
	}
	return wire.VerifyStableHeadQC(&material.Head, &material.ControlSet, &material.QC)
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

func (runtime *controlRuntime) verifyControlReplicationMaterialObject(_ context.Context,
	object crdt.Object) error {
	switch object.Kind {
	case controlOperationMaterialKind:
		_, err := decodeControlOperationMaterialObject(object)
		return err
	case controlHeadCertificationMaterialKind:
		_, err := decodeControlHeadCertificationMaterialObject(object)
		return err
	default:
		return errors.New("[control replication material] 未知 CRDT object kind")
	}
}

func (runtime *controlRuntime) persistHeadCertificationMaterialLocked(head wire.HeadEntryV2,
	qc wire.StableHeadReplicationQCV1) error {
	if runtime.operationMaterials == nil {
		return errors.New("[Head certification material] store 未初始化")
	}
	object, err := newControlHeadCertificationMaterialObject(head, runtime.config.ControlSet, qc)
	if err != nil {
		return err
	}
	return runtime.operationMaterials.Add(object)
}

// installFollowerProjectionLocked 在 controlplane 已完成 commit/QC 安装之后重建本
// 副本的 durable journal 与业务投影。每个历史 Head 都必须同时具备 exact reducer
// preimage 和 exact certification；缺一项就失败关闭，不能用当前 QC 推导历史结果。
func (runtime *controlRuntime) installFollowerProjectionLocked(
	request controlplane.HeadCertificationRequestV1) error {
	if runtime.storage == nil || runtime.store == nil || runtime.operationMaterials == nil {
		return errors.New("[control follower] storage/store/replication material 未初始化")
	}
	raft := runtime.storage.SnapshotRaft()
	if request.RaftIndex < 1 || request.RaftIndex > raft.LastApplied ||
		request.RaftIndex > int64(len(raft.Log)) {
		return errors.New("[control follower] certification 尚未 apply 到本机 Raft prefix")
	}
	target := raft.Log[request.RaftIndex-1]
	if target.Kind != controlplane.RaftRecordHead || target.Head == nil ||
		target.EntryHash != request.EntryHash {
		return errors.New("[control follower] certification target 不是 exact Head record")
	}
	if err := runtime.persistHeadCertificationMaterialLocked(*target.Head, request.QC); err != nil {
		return err
	}
	return runtime.rebuildCertifiedJournalLocked(request.RaftIndex)
}

func (runtime *controlRuntime) rebuildCertifiedJournalLocked(through int64) error {
	raft := runtime.storage.SnapshotRaft()
	state := runtime.store.Snapshot()
	if through < 1 || through > raft.LastApplied || through > raft.CommitIndex ||
		state.CertifiedHead == nil || state.CertifiedQC == nil ||
		state.CertifiedHead.Body.Payload.RaftIndex != through {
		return errors.New("[control follower] certified journal 恢复坐标无效")
	}
	needsApply := state.Active != nil
	if needsApply && (state.Active.Entry.EntryHash != state.CertifiedHead.EntryHash ||
		(state.Active.Phase != controlplane.PhaseCertified &&
			state.Active.Phase != controlplane.PhaseReconciled)) {
		return errors.New("[control follower] certified active state 与恢复 Head 不一致")
	}
	operationMaterials := make(map[string]controlOperationMaterialV1)
	certifications := make(map[string][]controlHeadCertificationMaterialV1)
	for _, object := range runtime.operationMaterials.Snapshot() {
		switch object.Kind {
		case controlOperationMaterialKind:
			material, err := decodeControlOperationMaterialObject(object)
			if err != nil {
				return err
			}
			operationMaterials[material.Candidate.EntryHash] = material
		case controlHeadCertificationMaterialKind:
			material, err := decodeControlHeadCertificationMaterialObject(object)
			if err != nil {
				return err
			}
			certifications[material.Head.EntryHash] = append(
				certifications[material.Head.EntryHash], material)
		default:
			return errors.New("[control follower] replication material 含未知 kind")
		}
	}

	original := runtime.journal
	rebuilt := controlOperationJournalV1{Schema: 1, Records: []controlOperationRecordV1{}}
	runtime.journal = rebuilt
	restore := true
	defer func() {
		if restore {
			runtime.journal = original
		}
	}()
	for _, raftRecord := range raft.Log[:through] {
		if raftRecord.Kind == controlplane.RaftRecordNoOp {
			continue
		}
		if raftRecord.Kind != controlplane.RaftRecordHead || raftRecord.Head == nil {
			return errors.New("[control follower] stable certified prefix 含 membership record")
		}
		if raftRecord.Head.Body.Payload.HeadKind == "bootstrap" {
			continue
		}
		material, materialOK := operationMaterials[raftRecord.EntryHash]
		certification, certificationOK := selectControlHeadCertification(
			certifications[raftRecord.EntryHash], *raftRecord.Head, through,
			state.CertifiedQC, original, len(runtime.journal.Records))
		if !materialOK || !certificationOK ||
			!wire.EqualCanonical(material.Candidate, *raftRecord.Head) ||
			!wire.EqualCanonical(certification.Head, *raftRecord.Head) {
			return errors.New("[control follower] committed Head 缺 exact preimage/certification")
		}
		record := controlOperationMaterialRecord(material)
		runtime.journal.Records = append(runtime.journal.Records, record)
		index := len(runtime.journal.Records) - 1
		if err := runtime.verifyOperationRecord(index); err != nil {
			return fmt.Errorf("[control follower] record[%d] 独立重算失败: %w", index, err)
		}
		result, err := runtime.certifiedOperationResultLocked(index, record.Candidate,
			&certification.QC)
		if err != nil {
			return err
		}
		runtime.journal.Records[index].Result = result
		phases := []controlplane.Phase{
			controlplane.PhasePending, controlplane.PhaseCommittedNotCertified,
			controlplane.PhaseCertified,
		}
		if raftRecord.Index < through || !needsApply {
			phases = append(phases, controlplane.PhaseReconciled, controlplane.PhaseApplied)
		}
		runtime.journal.Records[index].Phases = phases
	}
	if len(original.Records) > len(runtime.journal.Records) {
		for _, pending := range original.Records[len(runtime.journal.Records):] {
			if pending.Result != nil || pending.Candidate.Body.Payload.RaftIndex <= through {
				return errors.New("[control follower] 本地 journal 与 certified prefix 冲突")
			}
			runtime.journal.Records = append(runtime.journal.Records, controlClone(pending))
		}
	}
	if err := runtime.persistJournalLocked(); err != nil {
		return err
	}
	restore = false
	if err := runtime.reconcileEnrollmentPrefixLocked(); err != nil {
		return err
	}
	if needsApply {
		entryHash := state.CertifiedHead.EntryHash
		if err := runtime.store.MarkReconciled(entryHash, nil); err != nil {
			return err
		}
		if err := runtime.recordOperationPhaseLocked(entryHash, controlplane.PhaseReconciled); err != nil {
			return err
		}
		if err := runtime.store.MarkApplied(entryHash); err != nil {
			return err
		}
		if err := runtime.recordOperationPhaseLocked(entryHash, controlplane.PhaseApplied); err != nil {
			return err
		}
	}
	if err := runtime.projectAdminRotations(); err != nil {
		return err
	}
	return runtime.recoverAppliedProgressLocked()
}

func selectControlHeadCertification(candidates []controlHeadCertificationMaterialV1,
	head wire.HeadEntryV2, through int64, currentQC *wire.StableHeadReplicationQCV1,
	original controlOperationJournalV1, journalIndex int) (controlHeadCertificationMaterialV1, bool) {
	if len(candidates) == 0 {
		return controlHeadCertificationMaterialV1{}, false
	}
	// 当前恢复点必须使用 control Store 已耐久安装的 exact QC。
	if head.Body.Payload.RaftIndex == through && currentQC != nil {
		for _, candidate := range candidates {
			if wire.EqualCanonical(candidate.QC, *currentQC) {
				return candidate, true
			}
		}
		return controlHeadCertificationMaterialV1{}, false
	}
	// 历史 journal 已存在时保持它原先回读的 exact QC；新 learner 没有历史
	// result 时使用按 CRDT logical ID 排序后遇到的第一份有效证明。
	if journalIndex < len(original.Records) && original.Records[journalIndex].Result != nil {
		var originalQC wire.StableHeadReplicationQCV1
		if _, err := wire.DecodeStrict(original.Records[journalIndex].Result.ConfigQC,
			4<<20, &originalQC); err == nil {
			for _, candidate := range candidates {
				if wire.EqualCanonical(candidate.QC, originalQC) {
					return candidate, true
				}
			}
		}
	}
	return candidates[0], true
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
		if object.Kind != controlOperationMaterialKind {
			continue
		}
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
