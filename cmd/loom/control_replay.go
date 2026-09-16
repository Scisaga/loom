package main

import (
	"context"
	"errors"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

// 响应丢失后的同一请求只能读取第一次提交的结果；旧 expected head 不能变成
// 新写入的授权。匹配整个签名对象，不能只用客户端自报 request ID 命中缓存。
func (runtime *controlRuntime) readCommittedOperation(ctx context.Context, operation wire.ControlOperationV1) (*controlplane.ControlOperationReplayV1, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for index, record := range runtime.journal.Records {
		if record.Leaf.OperationID != operation.Body.OperationID {
			continue
		}
		if !wire.EqualCanonical(record.Operation, operation) || record.Result == nil {
			return nil, errors.New("[D104 replay] request 与已提交操作不一致")
		}
		if err := runtime.verifyAdminOperationRecord(index); err != nil {
			return nil, err
		}
		result, err := controlplaneResult(record.Result)
		if err != nil {
			return nil, err
		}
		for _, log := range runtime.storage.SnapshotRaft().Log {
			if log.Head != nil && log.Head.HeadHash == operation.Body.ParentHeadHash {
				return &controlplane.ControlOperationReplayV1{Parent: *log.Head, ControlSet: controlClone(runtime.config.ControlSet), Result: result}, nil
			}
		}
		return nil, errors.New("[D104 replay] 原 parent 缺持久日志")
	}
	return nil, nil
}
