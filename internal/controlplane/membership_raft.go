package controlplane

import (
	"context"
	"errors"
	"fmt"

	"loom/internal/wire"
)

// MembershipFinalMaterializer 必须从 frozen transition inputs 重算 Final 的两个
// materialized roots；调用方不能把 leader 提供的 hash 原样返回（D112）。
type MembershipFinalMaterializer func(context.Context, wire.HeadEntryV2) (snapshotHash, effectiveSSOTHash string, err error)

// ApplyCommittedMembershipPrefix 恢复 Joint→Final 专用日志段。每个 durable write
// 都可重放：先把 exact committed record 投影到 ledger，再推进 last_applied；Final
// materialize 后原子安装新稳定 ControlSet，移除的本机身份同时停止投票（D104、D112）。
func ApplyCommittedMembershipPrefix(ctx context.Context, storage *RaftStorage,
	ledger *MembershipLedger, materialize MembershipFinalMaterializer) (int, error) {
	if storage == nil || ledger == nil || materialize == nil {
		return 0, errors.New("[D112 joint apply] storage/ledger/materializer 不能为空")
	}
	applied := 0
	for {
		if err := ctx.Err(); err != nil {
			return applied, err
		}
		raft := storage.SnapshotRaft()
		if raft.LastApplied == raft.CommitIndex {
			return applied, nil
		}
		if raft.LastApplied < 0 || raft.LastApplied >= int64(len(raft.Log)) {
			return applied, errors.New("[D112 joint apply] committed prefix 坐标无效")
		}
		record := raft.Log[raft.LastApplied]
		switch record.Kind {
		case RaftRecordNoOp:
			// current-term barrier 不改变 membership projection。
		case RaftRecordJointControlSet:
			if record.JointControlSet == nil {
				return applied, errors.New("[D112 joint apply] Joint record 缺 payload")
			}
			if err := ledger.RecordJointCommitFromRaft(storage, *record.JointControlSet); err != nil {
				return applied, err
			}
		case RaftRecordHead:
			if record.Head == nil || record.Head.Body.Payload.HeadKind != "control_set_final" {
				return applied, errors.New("[D112 joint apply] membership prefix 含非 Final Head")
			}
			snapshotHash, effectiveSSOTHash, err := materialize(ctx, *record.Head)
			if err != nil {
				return applied, fmt.Errorf("[D112 joint apply] Final deterministic materialize 失败: %w", err)
			}
			ledgerState := ledger.Snapshot()
			alreadyRecorded := ledgerState.Final != nil &&
				wire.EqualCanonical(ledgerState.Final.Head, *record.Head) &&
				ledgerState.Final.ExpectedSnapshotHash == snapshotHash &&
				ledgerState.Final.ExpectedEffectiveSSOTHash == effectiveSSOTHash
			if !alreadyRecorded {
				if err := ledger.RecordFinalCommitFromRaft(storage, *record.Head,
					snapshotHash, effectiveSSOTHash); err != nil {
					return applied, err
				}
			}
			if err := storage.ActivateFinalControlSet(ledgerState.Candidate.NewControlSet,
				record.EntryHash); err != nil {
				return applied, err
			}
		default:
			return applied, errors.New("[D112 joint apply] committed prefix 含未知 record kind")
		}
		if err := storage.MarkRaftApplied(record.Index); err != nil {
			return applied, err
		}
		applied++
	}
}
