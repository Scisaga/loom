package main

import (
	"errors"
	"testing"
	"time"

	"loom/internal/rollout"
)

func TestSameVerifiedSnapshotIsReconcileNotNewRollout(t *testing.T) {
	prev := &rollout.Record{Snapshot: "snap", Stage: rollout.Verified,
		StartedAt: "2026-08-26T10:00:00Z", EnteredAt: "2026-08-26T10:01:00Z"}
	if shouldTrackRollout(prev, "snap", "snap") {
		t.Fatal("相同且 verified 的定时 reconcile 不应覆盖有意义的 rollout 记录")
	}
	// 连续第二轮仍然是 no-op，旧记录的时间/步骤由调用方原样保留。
	if shouldTrackRollout(prev, "snap", "snap") {
		t.Fatal("连续 no-op 不应变成新 rollout")
	}
}

func TestSameSnapshotReconcileFailureBecomesFailed(t *testing.T) {
	prev := &rollout.Record{Snapshot: "snap", Stage: rollout.Verified,
		StartedAt: "2026-08-26T10:00:00Z", EnteredAt: "2026-08-26T10:01:00Z", LastGood: "snap"}
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	got := failRollout(nil, prev, "snap", errors.New("验签失败"), now)
	if got == nil || got.Stage != rollout.Failed || got.Snapshot != "snap" || got.LastGood != "snap" || got.Error != "验签失败" {
		t.Fatalf("同快照 reconcile 失败仍会假绿:%+v", got)
	}
	if prev.Stage != rollout.Verified || prev.EnteredAt != "2026-08-26T10:01:00Z" {
		t.Fatalf("失败处理改写了旧 Verified 记录:%+v", prev)
	}
}

func TestSuccessfulSameSnapshotReconcileLeavesVerifiedUntouched(t *testing.T) {
	prev := &rollout.Record{Snapshot: "snap", Stage: rollout.Verified,
		StartedAt: "2026-08-26T10:00:00Z", EnteredAt: "2026-08-26T10:01:00Z"}
	if got := failRollout(nil, prev, "snap", nil, time.Now()); got != nil {
		t.Fatalf("成功 no-op 不应创建 rollout:%+v", got)
	}
	if prev.EnteredAt != "2026-08-26T10:01:00Z" || prev.Stage != rollout.Verified {
		t.Fatalf("成功 no-op 改写了旧记录:%+v", prev)
	}
}

func TestRolloutTrackingStartsForChangeOrRecovery(t *testing.T) {
	if !shouldTrackRollout(nil, "new", "old") {
		t.Error("目标快照变化必须记录")
	}
	for _, stage := range []rollout.Stage{rollout.Failed, rollout.Activating} {
		prev := &rollout.Record{Snapshot: "snap", Stage: stage}
		if !shouldTrackRollout(prev, "snap", "snap") {
			t.Errorf("同目标从 %s 恢复的尝试必须记录", stage)
		}
	}
	oldFailure := &rollout.Record{Snapshot: "older", Stage: rollout.Failed}
	if !shouldTrackRollout(oldFailure, "snap", "snap") {
		t.Error("旧目标失败必须由当前快照 reconcile 收口，否则健康状态会永久报坏")
	}
}
