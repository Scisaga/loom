package main

import (
	"errors"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

// 只缓存已验证日志的内存投影；不写独立状态文件，也不缓存 sealed artifact。
// key 包含完整日志与认证状态，同一 Head 下的 preimage 变化也必须重新验证。
type controlApplicationCache struct {
	key     string
	history []*controlApplicationV1
}

// 调用方必须持有 runtime.mu，并将返回值视为只读。面向外部的 reader 另做深拷贝。
func (runtime *controlRuntime) certifiedApplicationsLocked() ([]*controlApplicationV1, error) {
	state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil ||
		raft.LastApplied != raft.CommitIndex || int64(len(raft.Log)) != raft.CommitIndex {
		return nil, errors.New("[daemon] certified application 暂不可读")
	}
	for _, record := range runtime.journal.Records {
		if record.Result == nil {
			return nil, errors.New("[daemon] 有未恢复的私有事务")
		}
	}
	if n := len(runtime.journal.Records); n == 0 ||
		!wire.EqualCanonical(runtime.journal.Records[n-1].Result.Head, *state.CertifiedHead) {
		return nil, errors.New("[daemon] 日志末尾不是当前 certified Head")
	}
	key, err := wire.HashObject("loom-verified-application-cache-v1", struct {
		State      controlplane.State        `json:"state"`
		ControlSet wire.ControlSetV1         `json:"control_set"`
		Journal    controlOperationJournalV1 `json:"journal"`
	}{state, runtime.config.ControlSet, runtime.journal})
	if err != nil {
		return nil, err
	}
	if key == runtime.applicationCache.key {
		return runtime.applicationCache.history, nil
	}
	history := make([]*controlApplicationV1, len(runtime.journal.Records))
	_, err = runtime.walkApplications(len(history), func(i int, application *controlApplicationV1) error {
		if application != nil {
			copy := controlClone(*application)
			history[i] = &copy
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	runtime.applicationCache = controlApplicationCache{key: key, history: history}
	return history, nil
}
