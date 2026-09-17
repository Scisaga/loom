package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

const controlProvisionalResultsName = "enrollment-first-results.json"

type controlEnrollmentOperationV1 struct {
	Mutation    enrollmentv2.EnrollmentHeadMutationV1 `json:"mutation"`
	LineageFrom wire.HeadEntryV2                      `json:"lineage_from"`
}

func enrollmentMutationInviteID(mutation enrollmentv2.EnrollmentHeadMutationV1) string {
	if mutation.Preimage == nil {
		return ""
	}
	switch mutation.Preimage.Kind {
	case "reservation":
		if mutation.Preimage.Reservation != nil {
			return mutation.Preimage.Reservation.Operation.InviteID
		}
	case "provisional":
		if mutation.Preimage.Provisional != nil {
			return mutation.Preimage.Provisional.Record.InviteID
		}
	case "completion":
		if mutation.Preimage.Completion != nil {
			return mutation.Preimage.Completion.Record.InviteID
		}
	case "expiry":
		if mutation.Preimage.Expiry != nil {
			return mutation.Preimage.Expiry.Record.InviteID
		}
	}
	return ""
}

func (application *controlApplicationV1) reduceEnrollment(mutation enrollmentv2.EnrollmentHeadMutationV1,
	coordinate enrollmentv2.EnrollmentCommitCoordinateV1, set wire.ControlSetV1) (*controlApplicationV1, error) {
	if application == nil {
		return nil, errors.New("[D130 daemon] 私有入网尚未激活")
	}
	id := enrollmentMutationInviteID(mutation)
	inviteIndex := sort.Search(len(application.Invites), func(i int) bool { return application.Invites[i].Record.InviteID >= id })
	if id == "" || inviteIndex == len(application.Invites) || application.Invites[inviteIndex].Record.InviteID != id {
		return nil, errors.New("[D130 daemon] 缺当前 certified Invite")
	}
	invite := application.Invites[inviteIndex]
	if invite.Status == "revoked" || invite.Status == "consumed" {
		return nil, errors.New("[D130 daemon] Invite 已撤销或消费")
	}
	index := sort.Search(len(application.Transactions), func(i int) bool { return application.Transactions[i].InviteID >= id })
	var previous *enrollmentv2.TransactionStateV2
	if index < len(application.Transactions) && application.Transactions[index].InviteID == id {
		copy := application.Transactions[index]
		previous = &copy
	}
	if r := mutation.Preimage.Reservation; r != nil {
		if invite.Status != "available" || !wire.EqualCanonical(r.Material.Record, invite.Record) ||
			!wire.EqualCanonical(r.Material.Opening, invite.Opening) || !wire.EqualCanonical(r.Material.Commitment, invite.Commitment) ||
			!wire.EqualCanonical(r.Material.Policy, application.InvitePolicy) ||
			!wire.EqualCanonical(r.Material.EnrollmentServiceRef, application.EnrollmentService) ||
			!wire.EqualCanonical(r.Material.ControlSet, set) {
			return nil, errors.New("[D130 daemon] reservation 替换了当前邀请或 authority")
		}
	}
	next, err := enrollmentv2.ReduceEnrollmentMutation(mutation, previous, coordinate)
	if err != nil {
		return nil, err
	}
	candidate := controlClone(*application)
	if r := mutation.Preimage.Provisional; r != nil {
		if len(r.Prepared.RuntimePlan) != 0 {
			plan, err := decodeEnrollmentRuntimePlan(r.Prepared.RuntimePlan)
			if err != nil {
				return nil, err
			}
			if len(application.EnrollmentPlans) != 0 || plan.Parent.Head.HeadHash != coordinate.ParentHeadHash || plan.PreparedAt != coordinate.CommittedLogicalTime {
				return nil, errors.New("[首次配置] 存在未完成计划或签发 base 不一致")
			}
			if err := wire.VerifyConfigQCAuthority(plan.Parent.Head.HeadHash, plan.Parent.QC, &plan.Parent.Head, &set, nil); err != nil {
				return nil, err
			}
			if _, err := application.applyEnrollmentRuntimePlan(plan, r.Record, r.Prepared.Result.InitialDeviceView, coordinate.CommittedLogicalTime); err != nil {
				return nil, err
			}
			candidate.EnrollmentPlans = append(candidate.EnrollmentPlans, plan)
		}
		var found bool
		for _, profile := range application.CARegistry.DeviceProfiles {
			if wire.EqualCanonical(profile, r.Prepared.Profile) && profile.Status == "active" {
				found = true
			}
		}
		if !found {
			return nil, errors.New("[D102 daemon] provisional CA 不在当前 active registry")
		}
		root, err := wire.EnrollmentIssuanceRegistryRoot(application.IssuanceRegistry)
		if err != nil || root != r.Prepared.Operation.PreviousIssuanceRegistryRoot {
			return nil, errors.New("[D130 daemon] provisional issuance registry CAS 冲突")
		}
		candidate.IssuanceRegistry = append(candidate.IssuanceRegistry, r.Prepared.Operation.IssuanceRegistryLeaf)
		sort.Slice(candidate.IssuanceRegistry, func(i, j int) bool {
			return candidate.IssuanceRegistry[i].ClaimOperationHash < candidate.IssuanceRegistry[j].ClaimOperationHash
		})
		root, err = wire.EnrollmentIssuanceRegistryRoot(candidate.IssuanceRegistry)
		if err != nil || root != r.Prepared.Operation.ResultingIssuanceRegistryRoot {
			return nil, errors.New("[D130 daemon] provisional issuance registry 重算不一致")
		}
	}
	if r := mutation.Preimage.Completion; r != nil {
		view := mutation.InitialDeviceView
		if view == nil || view.Active == nil || len(view.Active.ConfigArtifactRefs) == 0 {
			return nil, errors.New("[D130 daemon] completion 缺可交付的实际配置制品")
		}
		for _, device := range application.Devices {
			if device.View.DeviceID == view.DeviceID {
				return nil, errors.New("[D130 daemon] completion 不能覆盖已有 Device")
			}
		}
		appliedPlan := false
		for i, plan := range application.EnrollmentPlans {
			if plan.InviteID != id {
				continue
			}
			applied, err := application.applyEnrollmentRuntimePlan(plan, r.Record, *view, coordinate.CommittedLogicalTime)
			if err != nil {
				return nil, err
			}
			candidate = *applied
			candidate.EnrollmentPlans = append(candidate.EnrollmentPlans[:i], candidate.EnrollmentPlans[i+1:]...)
			appliedPlan = true
			break
		}
		if !appliedPlan {
			candidate.Devices = append(candidate.Devices, controlDeviceStateV1{View: *view, PreviousViewHash: wire.EmptyHashV1,
				SecretArtifactRefs: append([]wire.SecretArtifactRefV2{}, r.Record.ResultArtifact.SecretArtifactRefs...), EnrollmentInviteID: id})
		}
		sort.Slice(candidate.Devices, func(i, j int) bool { return candidate.Devices[i].View.DeviceID < candidate.Devices[j].View.DeviceID })
		candidate.Invites[inviteIndex].Status = "consumed"
	} else if mutation.Preimage.Expiry != nil {
		candidate.Invites[inviteIndex].Status = "revoked"
		plans := candidate.EnrollmentPlans[:0]
		for _, plan := range candidate.EnrollmentPlans {
			if plan.InviteID != id {
				plans = append(plans, plan)
			}
		}
		candidate.EnrollmentPlans = plans
	} else {
		candidate.Invites[inviteIndex].Status = "reserved"
	}
	if previous == nil {
		candidate.Transactions = append(candidate.Transactions, next)
		sort.Slice(candidate.Transactions, func(i, j int) bool { return candidate.Transactions[i].InviteID < candidate.Transactions[j].InviteID })
	} else {
		candidate.Transactions[index] = next
	}
	if _, err := candidate.roots(); err != nil {
		return nil, err
	}
	return &candidate, nil
}

func controlEnrollmentCoordinate(head wire.HeadEntryV2) enrollmentv2.EnrollmentCommitCoordinateV1 {
	p := head.Body.Payload
	return enrollmentv2.EnrollmentCommitCoordinateV1{Schema: 1, ClusterID: p.ClusterID, RecoveryEpoch: p.RecoveryEpoch,
		RaftTerm: p.RaftTerm, RaftIndex: p.RaftIndex, PreviousLogEntryHash: p.PreviousLogEntryHash,
		ParentHeadHash: p.ParentHeadHash, CommittedLogicalTime: p.CommittedLogicalTime}
}

// applicationBefore 从迁移 preimage 和已认证 operation 重算私有状态。它不读取
// 一份可独立修改的“当前 application.json”，磁盘唯一 authority 仍是原 Head/QC 日志。
func (runtime *controlRuntime) applicationBefore(limit int) (*controlApplicationV1, error) {
	if limit < 0 || limit > len(runtime.journal.Records) {
		return nil, errors.New("[D104 daemon] application 重放范围无效")
	}
	setHash, err := wire.ControlSetHash(&runtime.config.ControlSet)
	if err != nil {
		return nil, err
	}
	cache := &runtime.applicationCache
	if cache.controlSetHash != setHash {
		*cache = controlApplicationCache{controlSetHash: setHash}
	}
	keys := make([]string, limit)
	common := 0
	for i := 0; i < limit; i++ {
		keys[i], err = controlApplicationRecordKey(runtime.journal.Records[i])
		if err != nil {
			return nil, err
		}
		if i < len(cache.recordKeys) && i < len(cache.history) && cache.recordKeys[i] == keys[i] && common == i {
			common++
		}
	}
	if common == limit {
		if limit == 0 || cache.history[limit-1] == nil {
			return nil, nil
		}
		copy := controlClone(*cache.history[limit-1])
		return &copy, nil
	}
	history := append([]*controlApplicationV1(nil), cache.history[:common]...)
	var application *controlApplicationV1
	if common > 0 && history[common-1] != nil {
		copy := controlClone(*history[common-1])
		application = &copy
	}
	for i := common; i < limit; i++ {
		application, err = runtime.reduceApplicationRecord(i, application)
		if err != nil {
			return nil, err
		}
		if application == nil {
			history = append(history, nil)
		} else {
			copy := controlClone(*application)
			history = append(history, &copy)
		}
	}
	cache.key = ""
	cache.controlSetHash = setHash
	cache.recordKeys = keys
	cache.history = history
	if limit == 0 || application == nil {
		return nil, nil
	}
	copy := controlClone(*application)
	return &copy, nil
}

// phase/result 会在同一 preimage 上依次耐久推进，不影响 application 投影；把它们
// 排除在记录 key 外，避免一次提交的五个阶段反复重放全部历史。其余字节任何变化
// 都会截断缓存并从首个不同记录重新验证。
func controlApplicationRecordKey(record controlOperationRecordV1) (string, error) {
	record.Phases = nil
	record.Result = nil
	return wire.HashObject("loom-control-application-record-v1", record)
}

// 连续构造各代 projection，每条操作仍经过 reducer 和 Head 根校验。
// 配置 lineage 不应为每一个历史 Head 再从日志起点重放一次。
func (runtime *controlRuntime) walkApplications(limit int,
	visit func(int, *controlApplicationV1) error) (*controlApplicationV1, error) {
	var application *controlApplicationV1
	for i := 0; i < limit; i++ {
		var err error
		application, err = runtime.reduceApplicationRecord(i, application)
		if err != nil {
			return nil, err
		}
		if visit != nil {
			if err := visit(i, application); err != nil {
				return nil, err
			}
		}
	}
	return application, nil
}

func (runtime *controlRuntime) reduceApplicationRecord(index int,
	application *controlApplicationV1) (*controlApplicationV1, error) {
	record := &runtime.journal.Records[index]
	if activation := record.Activation; activation != nil {
		if application != nil {
			return nil, errors.New("[D104 daemon] 重复 application 激活")
		}
		copy := controlClone(activation.Application)
		application = &copy
	} else if record.Invite != nil {
		var err error
		application, err = application.reduceInvite(*record.Invite, record.Operation.Body, record.Candidate.Body.Payload.CommittedLogicalTime)
		if err != nil {
			return nil, err
		}
	} else if record.DevicePublication != nil {
		var err error
		application, err = application.reduceDevicePublication(*record.DevicePublication, record.Operation.Body, record.Candidate.Body.Payload.CommittedLogicalTime)
		if err != nil {
			return nil, err
		}
	} else if record.BootstrapAdvertisement != nil {
		if application == nil {
			return nil, errors.New("[bootstrap advertise] application 尚未激活")
		}
		preparedHead, err := runtime.bootstrapPreparedHeadBefore(index, application,
			record.BootstrapAdvertisement.Payload)
		if err != nil {
			return nil, err
		}
		next, transitions, err := application.reduceBootstrapAdvertisement(
			record.BootstrapAdvertisement.Payload, record.Operation.Body,
			record.Candidate.Body.Payload.CommittedLogicalTime, preparedHead, record.Candidate.HeadHash)
		if err != nil || !wire.EqualCanonical(transitions, record.BootstrapAdvertisement.Transitions) {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("[bootstrap advertise] durable transition 与 evidence 派生结果不一致")
		}
		application = next
	} else if record.Enrollment != nil {
		var err error
		application, err = application.reduceEnrollment(record.Enrollment.Mutation,
			controlEnrollmentCoordinate(record.Candidate), runtime.config.ControlSet)
		if err != nil {
			return nil, err
		}
	} else if application != nil && record.AdminRotation != nil {
		var err error
		application, err = application.reduceAdminRotation(record.AdminRotation.Payload)
		if err != nil {
			return nil, err
		}
	}
	if application != nil {
		roots, err := application.roots()
		if err != nil {
			return nil, err
		}
		expected := record.Candidate.Body
		controlApplyRoots(&expected, roots)
		if !wire.EqualCanonical(expected, record.Candidate.Body) {
			return nil, errors.New("[D104 daemon] application 重放与 Head 根不一致")
		}
	}
	return application, nil
}

func (runtime *controlRuntime) verifyEnrollmentRecord(index int) error {
	record := &runtime.journal.Records[index]
	if record.Enrollment == nil || record.Activation != nil || record.AdminRotation != nil || record.Invite != nil || record.DevicePublication != nil || record.BootstrapAdvertisement != nil || len(record.AdditionalLeaves) != 0 ||
		!wire.EqualCanonical(record.Leaf, record.Enrollment.Mutation.OperationLeaf) {
		return errors.New("[D130 daemon] enrollment operation union/leaf 不一致")
	}
	application, err := runtime.applicationBefore(index)
	if err != nil {
		return err
	}
	next, err := application.reduceEnrollment(record.Enrollment.Mutation, controlEnrollmentCoordinate(record.Candidate), runtime.config.ControlSet)
	if err != nil {
		return err
	}
	parent, heads, err := runtime.enrollmentLineage(record.Enrollment.LineageFrom, record.Candidate.Body.Payload.ParentHeadHash)
	if err != nil {
		return err
	}
	if err := enrollmentv2.VerifyEnrollmentHeadLineage(&record.Enrollment.LineageFrom, heads, nil, &record.Candidate, &runtime.config.ControlSet); err != nil {
		return err
	}
	expected, actual := parent.Body, record.Candidate.Body
	expected.Payload.HeadKind = "ordinary"
	expected.Payload.RaftTerm, expected.Payload.RaftIndex = actual.Payload.RaftTerm, actual.Payload.RaftIndex
	expected.Payload.ControlRevision, expected.Payload.PreviousLogEntryHash = actual.Payload.RaftIndex, actual.Payload.PreviousLogEntryHash
	expected.Payload.ParentHeadHash, expected.Payload.OperationRoot = parent.HeadHash, actual.Payload.OperationRoot
	expected.Payload.CommittedLogicalTime = actual.Payload.CommittedLogicalTime
	expected.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	roots, err := next.roots()
	if err != nil {
		return err
	}
	controlApplyRoots(&expected, roots)
	if !wire.EqualCanonical(expected, actual) {
		return errors.New("[D104 daemon] enrollment 改写了 reducer 外的 Head")
	}
	return wire.ValidateHeadEntry(&record.Candidate, &parent)
}

func (runtime *controlRuntime) enrollmentLineage(from wire.HeadEntryV2, parentHash string) (wire.HeadEntryV2, []wire.HeadEntryV2, error) {
	found := false
	heads := []wire.HeadEntryV2{}
	for _, log := range runtime.controlRaftLog() {
		if log.Head == nil {
			continue
		}
		if !found {
			if log.Head.HeadHash != from.HeadHash {
				continue
			}
			if !wire.EqualCanonical(*log.Head, from) {
				break
			}
			found = true
		} else {
			heads = append(heads, *log.Head)
		}
		if log.Head.HeadHash == parentHash {
			return *log.Head, heads, nil
		}
	}
	return wire.HeadEntryV2{}, nil, errors.New("[D130 daemon] Enrollment lineage 不属于现有日志")
}

// CommitEnrollmentOperation 和管理操作共用 runtime.mu、Raft 与累计 operation
// journal；不存在能绕过管理员事务或覆盖同一 parent 的独立 Enrollment head。
func (runtime *controlRuntime) CommitEnrollmentOperation(ctx context.Context, operationID string,
	from *wire.HeadEntryV2, build enrollmentv2.EnrollmentOperationBuilder) (enrollmentv2.EnrollmentOperationCommitResultV1, error) {
	if from == nil || operationID == "" || build == nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, errors.New("[D130 daemon] Enrollment builder/base 缺失")
	}
	if err := ctx.Err(); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err := runtime.restoreProvisionalResultsLocked(); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	for i := range runtime.journal.Records {
		record := &runtime.journal.Records[i]
		if record.Leaf.OperationID != operationID {
			continue
		}
		if record.Enrollment == nil || !wire.EqualCanonical(record.Enrollment.LineageFrom, *from) {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, errors.New("[D130 daemon] operation ID/base 冲突")
		}
		if err := runtime.finishCommittedLocked(); err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		if record.Result == nil {
			if err := runtime.recoverPendingOperationsLocked(); err != nil {
				return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
			}
		}
		return runtime.enrollmentResult(i)
	}
	for _, record := range runtime.journal.Records {
		if record.Result == nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, errors.New("[D104 daemon] 先恢复已有 pending operation")
		}
	}
	state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil ||
		raft.LastApplied != raft.CommitIndex || int64(len(raft.Log)) != raft.CommitIndex || len(raft.Log) == 0 {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, errors.New("[D104 daemon] 当前 quorum/prefix 不可写")
	}
	if _, _, err := runtime.enrollmentLineage(*from, state.CertifiedHead.HeadHash); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	application, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	if application == nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, errors.New("[D130 daemon] 正式入网状态尚未激活")
	}
	parent := state.CertifiedHead
	body := parent.Body
	body.Payload.HeadKind = "ordinary"
	body.Payload.RaftTerm, body.Payload.RaftIndex = raft.CurrentTerm, int64(len(raft.Log))+1
	body.Payload.ControlRevision, body.Payload.PreviousLogEntryHash = body.Payload.RaftIndex, raft.Log[len(raft.Log)-1].EntryHash
	body.Payload.ParentHeadHash = parent.HeadHash
	body.Payload.CommittedLogicalTime = runtime.now().UTC().Truncate(time.Second).Format(time.RFC3339)
	if body.Payload.CommittedLogicalTime < parent.Body.Payload.CommittedLogicalTime {
		body.Payload.CommittedLogicalTime = parent.Body.Payload.CommittedLogicalTime
	}
	body.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
	mutation, err := build(controlEnrollmentCoordinate(wire.HeadEntryV2{Body: body}))
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	if mutation.OperationLeaf.OperationID != operationID {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, errors.New("[D130 daemon] builder 替换 operation ID")
	}
	next, err := application.reduceEnrollment(mutation, controlEnrollmentCoordinate(wire.HeadEntryV2{Body: body}), state.ControlSet)
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	leaves := runtime.operationLeaves(len(runtime.journal.Records))
	leaves = append(leaves, mutation.OperationLeaf)
	body.Payload.OperationRoot, err = wire.ControlOperationRoot(leaves)
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	roots, err := next.roots()
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	controlApplyRoots(&body, roots)
	candidate, err := wire.NewHeadEntry(body)
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	index := len(runtime.journal.Records)
	runtime.journal.Records = append(runtime.journal.Records, controlOperationRecordV1{Schema: 1,
		Leaf: mutation.OperationLeaf, Candidate: candidate, Phases: []controlplane.Phase{controlplane.PhasePending},
		Enrollment: &controlEnrollmentOperationV1{Mutation: controlClone(mutation), LineageFrom: *from}})
	if err := runtime.verifyPendingHead(ctx, candidate); err != nil {
		runtime.journal.Records = runtime.journal.Records[:index]
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	if err := runtime.persistJournalLocked(); err != nil {
		runtime.journal.Records = runtime.journal.Records[:index]
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	if runtime.checkpoint != nil {
		if err := runtime.checkpoint(controlplane.PhasePending); err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
	}
	if _, err := runtime.leader.ReplicateHead(ctx, runtime.store, candidate); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	if err := runtime.finishCommittedLocked(); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	return runtime.enrollmentResult(index)
}

func (runtime *controlRuntime) operationLeaves(limit int) []wire.ControlOperationLeafV1 {
	leaves := make([]wire.ControlOperationLeafV1, 0, limit)
	for i := 0; i < limit; i++ {
		leaves = append(leaves, runtime.journal.Records[i].Leaf)
		leaves = append(leaves, runtime.journal.Records[i].AdditionalLeaves...)
	}
	return leaves
}

func (runtime *controlRuntime) enrollmentResult(index int) (enrollmentv2.EnrollmentOperationCommitResultV1, error) {
	record := &runtime.journal.Records[index]
	if record.Enrollment == nil || record.Result == nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, errors.New("[D130 daemon] operation 尚未 certified")
	}
	result := record.Result
	_, heads, err := runtime.enrollmentLineage(record.Enrollment.LineageFrom, record.Candidate.Body.Payload.ParentHeadHash)
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	response := enrollmentv2.EnrollmentOperationCommitResultV1{Certification: enrollmentv2.CertifiedEnrollmentOperationProofV1{
		Head: result.Head, ConfigQC: result.ConfigQC, ControlSet: runtime.config.ControlSet,
		OperationLeaf: result.OperationLeaf, OperationLeafIndex: result.OperationLeafIndex,
		OperationTreeSize: result.OperationTreeSize, OperationAuditPath: result.OperationAuditPath}, IntermediateHeads: heads}
	if mutation := record.Enrollment.Mutation; mutation.InitialDeviceView != nil {
		application, err := runtime.applicationBefore(index + 1)
		if err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		envelope, err := application.deviceEnvelope(mutation.InitialDeviceView.DeviceID, result.Head, result.ConfigQC)
		if err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		if _, err := wire.VerifyDeviceViewEnvelope(&envelope, &runtime.config.ControlSet); err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		response.DeviceViewEnvelope = &envelope
	}
	return controlClone(response), nil
}

// 新任期 barrier 会占用下一条日志的 index。已经签出 provisional certificate
// 的 pending candidate 必须先以原 bytes 恢复到原日志位置，再选举和提交；不能重签。
func (runtime *controlRuntime) restorePendingEnrollmentBeforeCampaign() error {
	if err := runtime.restoreProvisionalResultsLocked(); err != nil {
		return err
	}
	for i, record := range runtime.journal.Records {
		if record.Enrollment == nil || record.Result != nil {
			continue
		}
		if err := runtime.verifyEnrollmentRecord(i); err != nil {
			return err
		}
		if err := runtime.storage.AppendLocal(record.Candidate); err != nil {
			return err
		}
	}
	return nil
}

// CA first-result 的 fsync 先于 journal。重启或下一次写入必须先将已经签发的
// exact bytes 补回原日志坐标，不能让选举 barrier 或另一项管理操作占用该位置。
func (runtime *controlRuntime) restoreProvisionalResultsLocked() error {
	results, err := enrollmentv2.ReadDurableProvisionalResults(filepath.Join(runtime.dir, controlProvisionalResultsName))
	if err != nil {
		return err
	}
	for _, result := range results {
		found := false
		for _, record := range runtime.journal.Records {
			if record.Leaf.OperationID != result.Prepared.Operation.OperationID {
				continue
			}
			if record.Enrollment == nil || record.Enrollment.Mutation.Preimage == nil ||
				record.Enrollment.Mutation.Preimage.Provisional == nil ||
				!wire.EqualCanonical(record.Enrollment.Mutation.Preimage.Provisional.Prepared, result.Prepared) ||
				!wire.EqualCanonical(record.Enrollment.Mutation.Preimage.Provisional.Record, result.Reservation) ||
				!wire.EqualCanonical(controlEnrollmentCoordinate(record.Candidate), result.Coordinate) {
				return errors.New("[D130 daemon] first-result 与 operation journal 冲突")
			}
			found = true
			break
		}
		if found {
			continue
		}
		for _, record := range runtime.journal.Records {
			if record.Result == nil {
				return errors.New("[D130 daemon] 未入 journal 的 first-result 与另一 pending operation 冲突")
			}
		}
		state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
		coordinate := result.Coordinate
		if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil ||
			state.CertifiedHead.HeadHash != coordinate.ParentHeadHash ||
			coordinate.RecoveryEpoch != state.CertifiedHead.Body.Payload.RecoveryEpoch ||
			coordinate.ClusterID != runtime.config.ClusterID || len(raft.Log) == 0 ||
			int64(len(raft.Log))+1 != coordinate.RaftIndex || raft.Log[len(raft.Log)-1].EntryHash != coordinate.PreviousLogEntryHash ||
			raft.CurrentTerm != coordinate.RaftTerm {
			return errors.New("[D130 daemon] first-result 原日志坐标已被改变，禁止重签或隐式迁移")
		}
		application, err := runtime.applicationBefore(len(runtime.journal.Records))
		if err != nil {
			return err
		}
		objectID, err := wire.HashObject(enrollmentv2.DomainProvisionalOperation, result.Prepared.Operation)
		if err != nil {
			return err
		}
		mutation := enrollmentv2.EnrollmentHeadMutationV1{
			OperationLeaf: wire.ControlOperationLeafV1{Schema: 1, OperationID: result.Prepared.Operation.OperationID, ObjectID: objectID},
			Preimage: &enrollmentv2.EnrollmentMutationPreimageV1{Schema: 1, Kind: "provisional",
				Provisional: &enrollmentv2.EnrollmentProvisionalPreimageV1{Record: result.Reservation, Prepared: result.Prepared}},
		}
		next, err := application.reduceEnrollment(mutation, coordinate, state.ControlSet)
		if err != nil {
			return err
		}
		body := state.CertifiedHead.Body
		body.Payload.HeadKind = "ordinary"
		body.Payload.ParentHeadHash = coordinate.ParentHeadHash
		body.Payload.RaftTerm, body.Payload.RaftIndex, body.Payload.ControlRevision = coordinate.RaftTerm, coordinate.RaftIndex, coordinate.RaftIndex
		body.Payload.PreviousLogEntryHash, body.Payload.CommittedLogicalTime = coordinate.PreviousLogEntryHash, coordinate.CommittedLogicalTime
		body.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"ordinary"}`)
		body.Payload.OperationRoot, err = wire.ControlOperationRoot(append(runtime.operationLeaves(len(runtime.journal.Records)), mutation.OperationLeaf))
		if err != nil {
			return err
		}
		roots, err := next.roots()
		if err != nil {
			return err
		}
		controlApplyRoots(&body, roots)
		candidate, err := wire.NewHeadEntry(body)
		if err != nil {
			return err
		}
		index := len(runtime.journal.Records)
		runtime.journal.Records = append(runtime.journal.Records, controlOperationRecordV1{Schema: 1,
			Leaf: mutation.OperationLeaf, Candidate: candidate, Phases: []controlplane.Phase{controlplane.PhasePending},
			Enrollment: &controlEnrollmentOperationV1{Mutation: mutation, LineageFrom: result.Reservation.ReservationCertification.Head}})
		if err := runtime.verifyEnrollmentRecord(index); err != nil {
			runtime.journal.Records = runtime.journal.Records[:index]
			return err
		}
		if err := runtime.persistJournalLocked(); err != nil {
			runtime.journal.Records = runtime.journal.Records[:index]
			return err
		}
	}
	return nil
}

func (runtime *controlRuntime) reconcileEnrollmentPrefixLocked() error {
	for i := range runtime.journal.Records {
		record := &runtime.journal.Records[i]
		if record.Enrollment == nil || record.Result == nil {
			continue
		}
		if runtime.enrollmentStore == nil {
			return errors.New("[D130 daemon] 缺耐久 transaction store")
		}
		result, err := runtime.enrollmentResult(i)
		if err != nil {
			return err
		}
		p := record.Enrollment.Mutation.Preimage
		if p == nil {
			return errors.New("[D130 daemon] 缺 transaction preimage")
		}
		switch p.Kind {
		case "reservation":
			r := p.Reservation
			invite := enrollmentv2.InviteContext{ClusterID: r.Material.Record.ClusterID, InviteID: r.Operation.InviteID,
				Status: "available", CertifiedInviteRecordHash: r.Operation.CertifiedInviteRecordHash,
				DeviceEnrollmentIntentCommitmentHash: r.Operation.DeviceEnrollmentIntentCommitmentHash,
				DeviceEnrollmentIntentOpeningHash:    r.Operation.DeviceEnrollmentIntentOpeningHash,
				TokenCommitment:                      r.Operation.TokenCommitment, ExpiresAt: r.Material.Record.ExpiresAt,
				MaximumReservationRetrySeconds: r.Material.Policy.MaximumReservationRetrySeconds}
			_, err = runtime.enrollmentStore.Reserve(invite, r.Evidence, r.Operation, &r.Admission,
				&r.Material.ControlSet, record.Enrollment.LineageFrom, result.IntermediateHeads,
				result.ControlSetTransitions, result.Certification)
		case "provisional":
			r := p.Provisional.Prepared
			_, err = runtime.enrollmentStore.RecordProvisional(r.Operation, r.Issuance, r.Profile, r.Result,
				result.Certification, result.IntermediateHeads, result.ControlSetTransitions)
		case "completion":
			r := p.Completion
			if result.DeviceViewEnvelope == nil {
				return errors.New("[D130 daemon] completion 缺同一 Head 的 Device view")
			}
			_, err = runtime.enrollmentStore.Complete(r.Operation, &r.Approval, &result.Certification.ControlSet,
				enrollmentv2.CompletionCertificationV1{Schema: 1, Operation: result.Certification,
					IntermediateHeads: result.IntermediateHeads, ControlSetTransitions: result.ControlSetTransitions,
					DeviceViewEnvelope: *result.DeviceViewEnvelope})
		case "expiry":
			_, err = runtime.enrollmentStore.Expire(enrollmentv2.EnrollmentExpiryEvidenceV1{
				Operation: p.Expiry.Operation, Certification: result.Certification,
				IntermediateHeads: result.IntermediateHeads, ControlSetTransitions: result.ControlSetTransitions})
		default:
			return errors.New("[D130 daemon] 未知 transaction mutation")
		}
		if err != nil {
			return err
		}
	}
	return nil
}
