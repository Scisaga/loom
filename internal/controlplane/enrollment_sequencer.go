package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type EnrollmentHeadProjectionV1 struct {
	Head                wire.HeadEntryV2       `json:"head"`
	OperationLeafIndex  int64                  `json:"operation_leaf_index"`
	OperationTreeSize   int64                  `json:"operation_tree_size"`
	OperationAuditPath  []string               `json:"operation_audit_path"`
	DeviceViewLeaf      *wire.DeviceViewLeafV2 `json:"device_view_leaf,omitempty"`
	DeviceViewLeafIndex int64                  `json:"device_view_leaf_index,omitempty"`
	DeviceViewTreeSize  int64                  `json:"device_view_tree_size,omitempty"`
	DeviceViewAuditPath []string               `json:"device_view_audit_path,omitempty"`
}

// EnrollmentHeadProjector 必须先把 exact private operation/view preimage 耐久暂存，
// 再从当前全局状态确定性投影 candidate Head 与两棵 inclusion proof（D104、D130）。
type EnrollmentHeadProjector func(context.Context, wire.HeadEntryV2,
	enrollmentv2.EnrollmentCommitCoordinateV1, enrollmentv2.EnrollmentHeadMutationV1) (EnrollmentHeadProjectionV1, error)

type enrollmentCommitJournalRecordV1 struct {
	OperationID string                                         `json:"operation_id"`
	ObjectID    string                                         `json:"object_id"`
	LineageFrom *wire.HeadEntryV2                              `json:"lineage_from,omitempty"`
	Result      enrollmentv2.EnrollmentOperationCommitResultV1 `json:"result"`
}

type enrollmentCommitJournalStateV1 struct {
	Schema         int                               `json:"schema"`
	ClusterID      string                            `json:"cluster_id"`
	ControlSetHash string                            `json:"control_set_hash"`
	Records        []enrollmentCommitJournalRecordV1 `json:"records"`
}

// EnrollmentCommitJournal 先于 control Store 的 MarkApplied 落盘。这样进程在
// certification 后、Coordinator CAS 前崩溃，仍能按 operation ID 返回第一次结果。
type EnrollmentCommitJournal struct {
	mu    sync.Mutex
	path  string
	set   wire.ControlSetV1
	state enrollmentCommitJournalStateV1
}

func OpenEnrollmentCommitJournal(path string, set wire.ControlSetV1) (*EnrollmentCommitJournal, error) {
	if path == "" {
		return nil, errors.New("[D130 Enrollment] commit journal path 不能为空")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	setHash, _ := wire.ControlSetHash(&set)
	journal := &EnrollmentCommitJournal{path: path, set: set,
		state: enrollmentCommitJournalStateV1{Schema: 1, ClusterID: set.ClusterID,
			ControlSetHash: setHash, Records: []enrollmentCommitJournalRecordV1{}}}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return journal, nil
	}
	if err != nil {
		return nil, err
	}
	var state enrollmentCommitJournalStateV1
	if _, err := wire.DecodeStrict(body, 64<<20, &state); err != nil {
		return nil, fmt.Errorf("[D130 Enrollment] commit journal 非规范或损坏: %w", err)
	}
	if err := validateEnrollmentCommitJournal(&state, &set); err != nil {
		return nil, err
	}
	journal.state = state
	return journal, nil
}

func (journal *EnrollmentCommitJournal) lookup(operationID string,
	lineageFrom *wire.HeadEntryV2) (enrollmentv2.EnrollmentOperationCommitResultV1, bool, error) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	index := sort.Search(len(journal.state.Records), func(index int) bool {
		return journal.state.Records[index].OperationID >= operationID
	})
	if index == len(journal.state.Records) || journal.state.Records[index].OperationID != operationID {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, false, nil
	}
	record := journal.state.Records[index]
	if !equalOptionalHead(record.LineageFrom, lineageFrom) {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, false,
			errors.New("[D130 Enrollment] 相同 operation ID 使用了不同 Head lineage 起点")
	}
	return cloneEnrollmentCommitResult(record.Result), true, nil
}

func (journal *EnrollmentCommitJournal) put(operationID, objectID string, lineageFrom *wire.HeadEntryV2,
	result enrollmentv2.EnrollmentOperationCommitResultV1) error {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record := enrollmentCommitJournalRecordV1{OperationID: operationID, ObjectID: objectID,
		LineageFrom: cloneHeadPointer(lineageFrom), Result: cloneEnrollmentCommitResult(result)}
	if err := validateEnrollmentCommitJournalRecord(&record, &journal.set); err != nil {
		return err
	}
	index := sort.Search(len(journal.state.Records), func(index int) bool {
		return journal.state.Records[index].OperationID >= operationID
	})
	if index < len(journal.state.Records) && journal.state.Records[index].OperationID == operationID {
		if wire.EqualCanonical(journal.state.Records[index], record) {
			return nil
		}
		return errors.New("[D130 Enrollment] commit journal 拒绝相同 operation ID 的不同 first-result")
	}
	candidate := cloneEnrollmentCommitJournalState(journal.state)
	candidate.Records = append(candidate.Records, enrollmentCommitJournalRecordV1{})
	copy(candidate.Records[index+1:], candidate.Records[index:])
	candidate.Records[index] = record
	if err := journal.persistLocked(candidate); err != nil {
		return err
	}
	journal.state = candidate
	return nil
}

func (journal *EnrollmentCommitJournal) persistLocked(candidate enrollmentCommitJournalStateV1) error {
	if err := validateEnrollmentCommitJournal(&candidate, &journal.set); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(candidate)
	if err != nil {
		return err
	}
	directory := filepath.Dir(journal.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, filepath.Base(journal.path)+".tmp-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, journal.path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = directoryHandle.Sync()
	closeErr = directoryHandle.Close()
	if err != nil {
		return err
	}
	return closeErr
}

type StableEnrollmentOperationSequencer struct {
	mu        sync.Mutex
	storage   *RaftStorage
	store     *Store
	leader    *StableRaftLeader
	collector *HeadAttestationCollector
	journal   *EnrollmentCommitJournal
	project   EnrollmentHeadProjector
	recompute HeadRecomputer
	now       func() time.Time
	set       wire.ControlSetV1
}

func NewStableEnrollmentOperationSequencer(storage *RaftStorage, store *Store,
	leader *StableRaftLeader, collector *HeadAttestationCollector,
	journal *EnrollmentCommitJournal, project EnrollmentHeadProjector,
	recompute HeadRecomputer, now func() time.Time) (*StableEnrollmentOperationSequencer, error) {
	if storage == nil || store == nil || leader == nil || collector == nil || journal == nil ||
		project == nil || recompute == nil || now == nil || leader.storage != storage {
		return nil, errors.New("[D130 Enrollment] stable sequencer dependencies 不完整")
	}
	state := store.Snapshot()
	setHash, err := wire.ControlSetHash(&state.ControlSet)
	if err != nil {
		return nil, err
	}
	leaderHash, _ := wire.ControlSetHash(&leader.set)
	collectorHash, _ := wire.ControlSetHash(&collector.set)
	journalHash, _ := wire.ControlSetHash(&journal.set)
	storageHash, _ := wire.ControlSetHash(&storage.set)
	if storage.jointSet != nil || setHash != leaderHash || setHash != collectorHash ||
		setHash != journalHash || setHash != storageHash {
		return nil, errors.New("[D130 Enrollment] stable sequencer ControlSet authority 不一致")
	}
	return &StableEnrollmentOperationSequencer{storage: storage, store: store, leader: leader,
		collector: collector, journal: journal, project: project, recompute: recompute,
		now: now, set: state.ControlSet}, nil
}

func (sequencer *StableEnrollmentOperationSequencer) CommitEnrollmentOperation(ctx context.Context,
	operationID string, lineageFrom *wire.HeadEntryV2,
	build enrollmentv2.EnrollmentOperationBuilder) (enrollmentv2.EnrollmentOperationCommitResultV1, error) {
	if sequencer == nil || operationID == "" || build == nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{},
			errors.New("[D130 Enrollment] commit operation/build 无效")
	}
	if err := ctx.Err(); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	sequencer.mu.Lock()
	defer sequencer.mu.Unlock()
	if cached, found, err := sequencer.journal.lookup(operationID, lineageFrom); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	} else if found {
		if active := sequencer.store.Snapshot().Active; active != nil {
			if active.Entry.EntryHash != cached.Certification.Head.EntryHash {
				return enrollmentv2.EnrollmentOperationCommitResultV1{},
					errors.New("[D130 Enrollment] cached result 与 active Head 冲突")
			}
			if err := sequencer.store.MarkApplied(active.Entry.EntryHash); err != nil {
				return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
			}
		}
		return cached, nil
	}

	// 先恢复此前已 committed、但尚未 apply/certify 的 entry。Head 一旦进入
	// Active，后面的流程只认证它，绝不会为同一 operation 再追加一个 Head。
	if _, err := ApplyCommittedPrefix(ctx, sequencer.storage, sequencer.store, sequencer.recompute); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	control := sequencer.store.Snapshot()
	var parent wire.HeadEntryV2
	if control.Active != nil {
		var err error
		parent, err = committedParentHead(sequencer.storage, &control.Active.Entry)
		if err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
	} else {
		if control.CertifiedHead == nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{},
				errors.New("[D130 Enrollment] ordinary enrollment 缺 certified parent Head")
		}
		parent = *control.CertifiedHead
	}
	var entry wire.HeadEntryV2
	var projection EnrollmentHeadProjectionV1
	var mutation enrollmentv2.EnrollmentHeadMutationV1
	if control.Active != nil {
		entry = control.Active.Entry
		coordinate := enrollmentCoordinateForHead(&entry)
		var err error
		mutation, err = build(coordinate)
		if err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		projection, err = sequencer.project(ctx, parent, coordinate, mutation)
		if err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		if !wire.EqualCanonical(projection.Head, entry) {
			return enrollmentv2.EnrollmentOperationCommitResultV1{},
				errors.New("[D130 Enrollment] active Head 不能由 exact staged operation 重算")
		}
		if err := validateEnrollmentHeadProjection(&projection, &parent, &coordinate,
			&mutation, &sequencer.set); err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
	} else {
		var coordinate enrollmentv2.EnrollmentCommitCoordinateV1
		raft := sequencer.storage.SnapshotRaft()
		if raft.LastApplied != raft.CommitIndex {
			return enrollmentv2.EnrollmentOperationCommitResultV1{},
				errors.New("[D104 Raft] committed prefix 尚未完成 enrollment apply")
		}
		uncommitted, found, err := uncommittedHeadCandidate(&raft)
		if err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		if found {
			entry = uncommitted
			coordinate = enrollmentCoordinateForHead(&entry)
		} else {
			coordinate, err = sequencer.nextCoordinate(&raft, &parent)
			if err != nil {
				return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
			}
		}
		mutation, err = build(coordinate)
		if err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		projection, err = sequencer.project(ctx, parent, coordinate, mutation)
		if err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		if err := validateEnrollmentHeadProjection(&projection, &parent, &coordinate,
			&mutation, &sequencer.set); err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		if found && !wire.EqualCanonical(projection.Head, entry) {
			return enrollmentv2.EnrollmentOperationCommitResultV1{},
				errors.New("[D104 Raft] uncommitted Head 属于不同 operation")
		}
		entry = projection.Head
		commit, replicateErr := sequencer.leader.ReplicateHead(ctx, sequencer.store, entry)
		if replicateErr != nil && commit.CommitIndex < entry.Body.Payload.RaftIndex {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, replicateErr
		}
		if _, err := ApplyCommittedPrefix(ctx, sequencer.storage, sequencer.store,
			sequencer.recompute); err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
	}
	if err := sequencer.collector.CertifyActive(ctx, sequencer.store); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	certified := sequencer.store.Snapshot()
	if certified.Active == nil || certified.Active.Phase != PhaseCertified ||
		certified.Active.QC == nil || certified.Active.Entry.EntryHash != entry.EntryHash {
		return enrollmentv2.EnrollmentOperationCommitResultV1{},
			errors.New("[D130 Enrollment] committed Head 未形成 exact durable config QC")
	}
	qcRaw, err := wire.MarshalCanonical(*certified.Active.QC)
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	proof := enrollmentv2.CertifiedEnrollmentOperationProofV1{Head: entry, ConfigQC: qcRaw,
		ControlSet: sequencer.set, OperationLeaf: mutation.OperationLeaf,
		OperationLeafIndex: projection.OperationLeafIndex, OperationTreeSize: projection.OperationTreeSize,
		OperationAuditPath: append([]string(nil), projection.OperationAuditPath...)}
	if err := verifySequencedOperationProof(&proof, operationID, mutation.OperationLeaf.ObjectID,
		&sequencer.set); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	intermediate, err := committedHeadLineage(sequencer.storage, lineageFrom, &entry)
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	result := enrollmentv2.EnrollmentOperationCommitResultV1{Certification: proof,
		IntermediateHeads: intermediate}
	if mutation.InitialDeviceView != nil {
		if projection.DeviceViewLeaf == nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{},
				errors.New("[D130 Enrollment] completion projection 缺 Device leaf")
		}
		envelope := wire.DeviceViewEnvelopeV2{Schema: 2,
			Payload: *mutation.InitialDeviceView, Leaf: *projection.DeviceViewLeaf,
			LeafIndex: projection.DeviceViewLeafIndex, TreeSize: projection.DeviceViewTreeSize,
			AuditPath: append([]string(nil), projection.DeviceViewAuditPath...),
			SignedCurrent: wire.SignedCurrentV2{Schema: 2, Head: entry,
				QuorumCertificate: qcRaw, PublishedAt: entry.Body.Payload.CommittedLogicalTime},
			SecretArtifactRefs: cloneRawMessages(mutation.SecretArtifactRefs)}
		if _, err := wire.VerifyDeviceViewEnvelope(&envelope, &sequencer.set); err != nil {
			return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
		}
		result.DeviceViewEnvelope = &envelope
	}
	if err := sequencer.journal.put(operationID, mutation.OperationLeaf.ObjectID,
		lineageFrom, result); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	if err := sequencer.store.MarkApplied(entry.EntryHash); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}, err
	}
	return cloneEnrollmentCommitResult(result), nil
}

func (sequencer *StableEnrollmentOperationSequencer) nextCoordinate(raft *RaftPersistentStateV1,
	parent *wire.HeadEntryV2) (enrollmentv2.EnrollmentCommitCoordinateV1, error) {
	if raft == nil || parent == nil || raft.CurrentTerm != sequencer.leader.term ||
		raft.VotedFor != raft.MemberID || len(raft.Log) != int(raft.CommitIndex) {
		return enrollmentv2.EnrollmentCommitCoordinateV1{},
			errors.New("[D104 Raft] enrollment sequencer leader/log 状态无效")
	}
	previous := wire.EmptyHashV1
	if len(raft.Log) > 0 {
		previous = raft.Log[len(raft.Log)-1].EntryHash
	}
	committedAt := sequencer.now().UTC().Truncate(time.Second)
	parentTime, err := wire.ParseTimeZ(parent.Body.Payload.CommittedLogicalTime)
	if err != nil || committedAt.Before(parentTime) {
		return enrollmentv2.EnrollmentCommitCoordinateV1{},
			errors.New("[D104 Raft] enrollment logical time 早于 certified parent")
	}
	return enrollmentv2.EnrollmentCommitCoordinateV1{Schema: 1, ClusterID: raft.ClusterID,
		RecoveryEpoch: parent.Body.Payload.RecoveryEpoch, RaftTerm: raft.CurrentTerm,
		RaftIndex: int64(len(raft.Log)) + 1, PreviousLogEntryHash: previous,
		ParentHeadHash: parent.HeadHash, CommittedLogicalTime: committedAt.Format(time.RFC3339)}, nil
}

func uncommittedHeadCandidate(raft *RaftPersistentStateV1) (wire.HeadEntryV2, bool, error) {
	if raft == nil || raft.CommitIndex < 0 || raft.CommitIndex > int64(len(raft.Log)) {
		return wire.HeadEntryV2{}, false, errors.New("[D104 Raft] persistent log/commitIndex 无效")
	}
	if raft.CommitIndex == int64(len(raft.Log)) {
		return wire.HeadEntryV2{}, false, nil
	}
	if int64(len(raft.Log))-raft.CommitIndex != 1 {
		return wire.HeadEntryV2{}, false,
			errors.New("[D104 Raft] enrollment sequencer 不接受多个未提交日志项")
	}
	record := raft.Log[len(raft.Log)-1]
	if record.Kind != RaftRecordHead || record.Head == nil {
		return wire.HeadEntryV2{}, false,
			errors.New("[D104 Raft] 未提交日志项不是可恢复 enrollment Head")
	}
	return *record.Head, true, nil
}

func validateEnrollmentHeadProjection(projection *EnrollmentHeadProjectionV1,
	parent *wire.HeadEntryV2, coordinate *enrollmentv2.EnrollmentCommitCoordinateV1,
	mutation *enrollmentv2.EnrollmentHeadMutationV1, set *wire.ControlSetV1) error {
	if projection == nil || parent == nil || coordinate == nil || mutation == nil || set == nil {
		return errors.New("[D130 Enrollment] Head projection 输入不完整")
	}
	head := &projection.Head
	payload := &head.Body.Payload
	setHash, _ := wire.ControlSetHash(set)
	if payload.HeadKind != "ordinary" || payload.ClusterID != coordinate.ClusterID ||
		payload.RecoveryEpoch != coordinate.RecoveryEpoch || payload.RaftTerm != coordinate.RaftTerm ||
		payload.RaftIndex != coordinate.RaftIndex || payload.ControlRevision != coordinate.RaftIndex ||
		payload.PreviousLogEntryHash != coordinate.PreviousLogEntryHash ||
		payload.ParentHeadHash != coordinate.ParentHeadHash || payload.ParentHeadHash != parent.HeadHash ||
		payload.CommittedLogicalTime != coordinate.CommittedLogicalTime || payload.ControlSetHash != setHash {
		return errors.New("[D130 Enrollment] projected Head 未绑定 exact Raft coordinate/parent/ControlSet")
	}
	if err := wire.ValidateHeadEntry(head, parent); err != nil {
		return err
	}
	if mutation.OperationLeaf.OperationID == "" ||
		wire.VerifyControlOperationInclusion(&mutation.OperationLeaf, projection.OperationLeafIndex,
			projection.OperationTreeSize, projection.OperationAuditPath, head) != nil {
		return errors.New("[D130 Enrollment] projected Head 缺 exact operation inclusion")
	}
	if mutation.InitialDeviceView == nil {
		if projection.DeviceViewLeaf != nil || projection.DeviceViewLeafIndex != 0 ||
			projection.DeviceViewTreeSize != 0 || len(projection.DeviceViewAuditPath) != 0 ||
			mutation.SecretArtifactRefs != nil {
			return errors.New("[D130 Enrollment] 非 completion mutation 携带 Device projection")
		}
		return nil
	}
	if projection.DeviceViewLeaf == nil {
		return errors.New("[D130 Enrollment] completion mutation 缺 Device projection")
	}
	_, err := wire.VerifyDeviceViewProjection(mutation.InitialDeviceView, projection.DeviceViewLeaf,
		projection.DeviceViewLeafIndex, projection.DeviceViewTreeSize,
		projection.DeviceViewAuditPath, mutation.SecretArtifactRefs, payload.DeviceViewsRoot)
	return err
}

func committedHeadLineage(storage *RaftStorage, from, to *wire.HeadEntryV2) ([]wire.HeadEntryV2, error) {
	if from == nil {
		return nil, nil
	}
	if storage == nil || to == nil || to.Body.Payload.RaftIndex <= from.Body.Payload.RaftIndex {
		return nil, errors.New("[D130 Enrollment] Head lineage endpoints 无效")
	}
	state := storage.SnapshotRaft()
	if to.Body.Payload.RaftIndex > state.CommitIndex ||
		from.Body.Payload.RaftIndex > int64(len(state.Log)) {
		return nil, errors.New("[D130 Enrollment] Head lineage 不在本机 committed prefix")
	}
	fromRecord := state.Log[from.Body.Payload.RaftIndex-1]
	toRecord := state.Log[to.Body.Payload.RaftIndex-1]
	if fromRecord.Kind != RaftRecordHead || fromRecord.Head == nil ||
		toRecord.Kind != RaftRecordHead || toRecord.Head == nil ||
		!wire.EqualCanonical(*fromRecord.Head, *from) || !wire.EqualCanonical(*toRecord.Head, *to) {
		return nil, errors.New("[D130 Enrollment] Head lineage endpoint 与 Raft log 不一致")
	}
	intermediate := make([]wire.HeadEntryV2, 0)
	parent := *from
	for index := from.Body.Payload.RaftIndex + 1; index < to.Body.Payload.RaftIndex; index++ {
		record := state.Log[index-1]
		if record.Kind != RaftRecordHead {
			continue
		}
		if record.Head == nil || wire.ValidateHeadEntry(record.Head, &parent) != nil {
			return nil, errors.New("[D130 Enrollment] intermediate Head lineage 断裂")
		}
		intermediate = append(intermediate, *record.Head)
		parent = *record.Head
	}
	if err := wire.ValidateHeadEntry(to, &parent); err != nil {
		return nil, errors.New("[D130 Enrollment] target Head lineage 断裂")
	}
	return intermediate, nil
}

func committedParentHead(storage *RaftStorage, entry *wire.HeadEntryV2) (wire.HeadEntryV2, error) {
	if storage == nil || entry == nil || entry.Body.Payload.RaftIndex < 2 {
		return wire.HeadEntryV2{}, errors.New("[D130 Enrollment] active ordinary Head parent 坐标无效")
	}
	state := storage.SnapshotRaft()
	index := entry.Body.Payload.RaftIndex
	if index > state.CommitIndex || index > int64(len(state.Log)) {
		return wire.HeadEntryV2{}, errors.New("[D130 Enrollment] active Head 不在 committed Raft prefix")
	}
	for candidateIndex := index - 1; candidateIndex >= 1; candidateIndex-- {
		record := state.Log[candidateIndex-1]
		if record.Kind != RaftRecordHead {
			continue
		}
		if record.Head == nil || record.Head.HeadHash != entry.Body.Payload.ParentHeadHash ||
			wire.ValidateHeadEntry(entry, record.Head) != nil {
			return wire.HeadEntryV2{}, errors.New("[D130 Enrollment] active Head parent 与 committed log 不一致")
		}
		return *record.Head, nil
	}
	return wire.HeadEntryV2{}, errors.New("[D130 Enrollment] active Head 缺 committed parent")
}

func verifySequencedOperationProof(proof *enrollmentv2.CertifiedEnrollmentOperationProofV1,
	operationID, objectID string, set *wire.ControlSetV1) error {
	if proof == nil || set == nil || proof.PreviousControlSet != nil ||
		proof.OperationLeaf.OperationID != operationID || proof.OperationLeaf.ObjectID != objectID ||
		!wire.EqualCanonical(proof.ControlSet, *set) {
		return errors.New("[D130 Enrollment] sequenced operation proof header 无效")
	}
	if err := wire.VerifyConfigQCAuthority(proof.Head.HeadHash, proof.ConfigQC,
		&proof.Head, set, nil); err != nil {
		return err
	}
	return wire.VerifyControlOperationInclusion(&proof.OperationLeaf, proof.OperationLeafIndex,
		proof.OperationTreeSize, proof.OperationAuditPath, &proof.Head)
}

func validateEnrollmentCommitJournal(state *enrollmentCommitJournalStateV1,
	set *wire.ControlSetV1) error {
	if state == nil || set == nil || state.Schema != 1 || state.Records == nil {
		return errors.New("[D130 Enrollment] commit journal schema 无效")
	}
	setHash, err := wire.ControlSetHash(set)
	if err != nil || state.ClusterID != set.ClusterID || state.ControlSetHash != setHash {
		return errors.New("[D130 Enrollment] commit journal ControlSet authority 无效")
	}
	for index := range state.Records {
		if index > 0 && state.Records[index-1].OperationID >= state.Records[index].OperationID {
			return errors.New("[D130 Enrollment] commit journal operation ID 未严格排序")
		}
		if err := validateEnrollmentCommitJournalRecord(&state.Records[index], set); err != nil {
			return err
		}
	}
	return nil
}

func validateEnrollmentCommitJournalRecord(record *enrollmentCommitJournalRecordV1,
	set *wire.ControlSetV1) error {
	if record == nil || record.OperationID == "" {
		return errors.New("[D130 Enrollment] commit journal record header 无效")
	}
	if _, err := wire.ParseHash(record.ObjectID); err != nil {
		return err
	}
	if err := verifySequencedOperationProof(&record.Result.Certification,
		record.OperationID, record.ObjectID, set); err != nil {
		return err
	}
	if record.LineageFrom == nil {
		if len(record.Result.IntermediateHeads) != 0 {
			return errors.New("[D130 Enrollment] 无 lineage 起点却携 intermediate Heads")
		}
	} else {
		parent := *record.LineageFrom
		for index := range record.Result.IntermediateHeads {
			if err := wire.ValidateHeadEntry(&record.Result.IntermediateHeads[index], &parent); err != nil {
				return errors.New("[D130 Enrollment] journal intermediate Head lineage 断裂")
			}
			parent = record.Result.IntermediateHeads[index]
		}
		if err := wire.ValidateHeadEntry(&record.Result.Certification.Head, &parent); err != nil {
			return errors.New("[D130 Enrollment] journal target Head lineage 断裂")
		}
	}
	if envelope := record.Result.DeviceViewEnvelope; envelope != nil {
		if !wire.EqualCanonical(envelope.SignedCurrent.Head, record.Result.Certification.Head) ||
			!equalCanonicalRaw(envelope.SignedCurrent.QuorumCertificate,
				record.Result.Certification.ConfigQC) {
			return errors.New("[D130 Enrollment] journal Device view 未绑定 operation Head/QC")
		}
		if _, err := wire.VerifyDeviceViewEnvelope(envelope, set); err != nil {
			return err
		}
	}
	return nil
}

func enrollmentCoordinateForHead(head *wire.HeadEntryV2) enrollmentv2.EnrollmentCommitCoordinateV1 {
	payload := head.Body.Payload
	return enrollmentv2.EnrollmentCommitCoordinateV1{Schema: 1, ClusterID: payload.ClusterID,
		RecoveryEpoch: payload.RecoveryEpoch, RaftTerm: payload.RaftTerm,
		RaftIndex: payload.RaftIndex, PreviousLogEntryHash: payload.PreviousLogEntryHash,
		ParentHeadHash: payload.ParentHeadHash, CommittedLogicalTime: payload.CommittedLogicalTime}
}

func cloneEnrollmentCommitResult(value enrollmentv2.EnrollmentOperationCommitResultV1) enrollmentv2.EnrollmentOperationCommitResultV1 {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}
	}
	var result enrollmentv2.EnrollmentOperationCommitResultV1
	if _, err := wire.DecodeStrict(body, 64<<20, &result); err != nil {
		return enrollmentv2.EnrollmentOperationCommitResultV1{}
	}
	return result
}

func cloneEnrollmentCommitJournalState(value enrollmentCommitJournalStateV1) enrollmentCommitJournalStateV1 {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return enrollmentCommitJournalStateV1{}
	}
	var result enrollmentCommitJournalStateV1
	if _, err := wire.DecodeStrict(body, 64<<20, &result); err != nil {
		return enrollmentCommitJournalStateV1{}
	}
	return result
}

func cloneHeadPointer(value *wire.HeadEntryV2) *wire.HeadEntryV2 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func equalOptionalHead(left, right *wire.HeadEntryV2) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return wire.EqualCanonical(*left, *right)
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	if values == nil {
		return nil
	}
	result := make([]json.RawMessage, len(values))
	for index := range values {
		result[index] = append(json.RawMessage(nil), values[index]...)
	}
	return result
}

func equalCanonicalRaw(left, right json.RawMessage) bool {
	leftCanonical, leftErr := wire.CanonicalizeStrict(left)
	rightCanonical, rightErr := wire.CanonicalizeStrict(right)
	return leftErr == nil && rightErr == nil && string(leftCanonical) == string(rightCanonical)
}
