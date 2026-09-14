package agent

import (
	"context"
	"errors"
	"sync"
	"time"
)

// EntryProbeRegistry 由 Windows 客户端宿主按 Service 生命周期持有。每个
// underlay generation 的第一份授权入口快照会被冻结并并行探测一次；同代后续
// 配置或 profile 只能复用该结果，新出现的候选保持 unknown（§5.6）。
type EntryProbeRegistry struct {
	ctx context.Context
	mu  sync.Mutex
	gen *entryProbeGeneration
}

type entryProbeGeneration struct {
	id      string
	entries map[string]ClientEntry
	results map[string]ClientEntryResult
	done    chan struct{}
}

func NewEntryProbeRegistry(ctx context.Context) (*EntryProbeRegistry, error) {
	if ctx == nil {
		return nil, errors.New("[§5.6] 入口探测注册表缺少 Service context")
	}
	return &EntryProbeRegistry{ctx: ctx}, nil
}

func (registry *EntryProbeRegistry) results(ctx context.Context, generation string,
	entries []ClientEntry, probe func(context.Context, ClientEntry) (time.Duration, error),
) (map[string]ClientEntryResult, map[string]bool, error) {
	if registry == nil || ctx == nil || generation == "" {
		return nil, nil, errors.New("[§5.6] underlay probe generation 输入无效")
	}
	current, err := canonicalClientEntries(entries)
	if err != nil {
		return nil, nil, err
	}
	registry.mu.Lock()
	frozen := registry.gen
	if frozen == nil || frozen.id != generation {
		frozen = &entryProbeGeneration{id: generation, entries: current,
			results: make(map[string]ClientEntryResult), done: make(chan struct{})}
		registry.gen = frozen
		go measureFrozenEntries(registry.ctx, frozen, probe)
	}
	registry.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-frozen.done:
	}
	results := make(map[string]ClientEntryResult)
	measured := make(map[string]bool)
	for node, entry := range current {
		original, ok := frozen.entries[node]
		if !ok || original.Address != entry.Address || original.Source != entry.Source {
			continue
		}
		measured[node] = true
		results[node] = frozen.results[node]
	}
	return results, measured, nil
}

func canonicalClientEntries(entries []ClientEntry) (map[string]ClientEntry, error) {
	out := make(map[string]ClientEntry, len(entries))
	for _, entry := range entries {
		if entry.Node == "" || entry.Address == "" {
			return nil, errors.New("[§5.6] 授权入口 identity/address 不完整")
		}
		if previous, ok := out[entry.Node]; ok && previous != entry {
			return nil, errors.New("[§5.6] 同一入口 identity 出现分叉坐标")
		}
		out[entry.Node] = entry
	}
	return out, nil
}

func measureFrozenEntries(ctx context.Context, generation *entryProbeGeneration,
	probe func(context.Context, ClientEntry) (time.Duration, error),
) {
	defer close(generation.done)
	byAddress := make(map[string][]ClientEntry)
	for _, entry := range generation.entries {
		key := entry.Address + "\x00" + entry.Source
		byAddress[key] = append(byAddress[key], entry)
	}
	var mu sync.Mutex
	var workers sync.WaitGroup
	for _, group := range byAddress {
		group := append([]ClientEntry(nil), group...)
		workers.Add(1)
		go func() {
			defer workers.Done()
			var result ClientEntryResult
			probeContext, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			if probe == nil {
				result.Err = errors.New("入口探测不可用")
			} else {
				result.RTT, result.Err = probe(probeContext, group[0])
			}
			result.At = time.Now()
			mu.Lock()
			defer mu.Unlock()
			for _, entry := range group {
				generation.results[entry.Node] = result
			}
		}()
	}
	workers.Wait()
}
