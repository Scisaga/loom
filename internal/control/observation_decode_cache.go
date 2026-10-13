package control

import (
	"container/list"
	"encoding/json"
	"strings"
	"sync"
)

const reportCacheBytes = 16 << 20

type reportCacheEntry struct {
	id          string
	verifiedKey string
	cost        int
	position    reportPosition
	runtime     RuntimeReadback
}

// Immutable canonical-validation and signature results only. Dynamic authorization is never cached.
type reportCache struct {
	mu    sync.Mutex
	items map[string]*list.Element
	lru   list.List
	bytes int
}

func (cache *reportCache) clear() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.items = nil
	cache.lru.Init()
	cache.bytes = 0
}
func (store *ObservationStore) decodedReport(raw []byte) (DeviceReport, error) {
	id := ReleaseDigest(raw)
	cache := &store.cache
	cache.mu.Lock()
	if element := cache.items[id]; element != nil {
		cache.lru.MoveToFront(element)
		cache.mu.Unlock()
		// The digest names the same bytes that already passed strict canonical
		// decoding. Reparse the value without repeating the canonical proof.
		var report DeviceReport
		err := json.Unmarshal(raw, &report)
		return report, err
	}
	cache.mu.Unlock()
	var report DeviceReport
	if err := decodeStoredReport(raw, &report); err != nil {
		return report, err
	}
	// Keep only immutable validation results, never entire report bodies.
	const cost = 512
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.items == nil {
		cache.items = map[string]*list.Element{}
	}
	if cache.items[id] == nil {
		for cache.bytes+cost > reportCacheBytes || len(cache.items) >= reportCacheBytes/cost {
			old := cache.lru.Back()
			value := old.Value.(*reportCacheEntry)
			cache.bytes -= value.cost
			delete(cache.items, value.id)
			cache.lru.Remove(old)
		}
		cache.items[id] = cache.lru.PushFront(&reportCacheEntry{id: id, cost: cost})
		cache.bytes += cost
	}
	return report, nil
}
func (store *ObservationStore) verifiedReport(raw []byte, key string) (DeviceReport, error) {
	report, err := store.decodedReport(raw)
	if err != nil {
		return report, err
	}
	id := ReleaseDigest(raw)
	cache := &store.cache
	cache.mu.Lock()
	if element := cache.items[id]; element != nil && key != "" && element.Value.(*reportCacheEntry).verifiedKey == key {
		cache.mu.Unlock()
		return report, nil
	}
	cache.mu.Unlock()
	if err := report.Verify(key); err != nil {
		return DeviceReport{}, err
	}
	cache.mu.Lock()
	if element := cache.items[id]; element != nil {
		value := element.Value.(*reportCacheEntry)
		// Keep only the immutable identity position and scalar runtime fields.
		// Listener arrays and all business observations stay in the original.
		cost := 512 + len(report.NetworkID) + len(report.DeviceID) + len(key) + len(report.Runtime.State) + len(report.Runtime.AppliedViewDigest) + len(report.Runtime.ErrorCode)
		cache.bytes -= value.cost
		value.cost, value.verifiedKey = cost, strings.Clone(key)
		value.position = reportPosition{reportOwner{strings.Clone(report.NetworkID), strings.Clone(report.DeviceID)}, report.ReportSequence}
		value.runtime = RuntimeReadback{State: strings.Clone(report.Runtime.State), AppliedViewDigest: strings.Clone(report.Runtime.AppliedViewDigest), ErrorCode: strings.Clone(report.Runtime.ErrorCode)}
		cache.bytes += cost
		cache.lru.MoveToFront(element)
		for cache.bytes > reportCacheBytes {
			old := cache.lru.Back()
			entry := old.Value.(*reportCacheEntry)
			cache.bytes -= entry.cost
			delete(cache.items, entry.id)
			cache.lru.Remove(old)
		}
	}
	cache.mu.Unlock()
	return report, nil
}

// The input remains freshly read original bytes. This projection never renews
// an observation or supplies authorization; callers still check its position.
func (store *ObservationStore) originalRuntime(raw []byte, key string) (reportReference, RuntimeReadback, error) {
	id := ReleaseDigest(raw)
	cache := &store.cache
	cache.mu.Lock()
	if element := cache.items[id]; element != nil {
		value := element.Value.(*reportCacheEntry)
		if key != "" && value.verifiedKey == key && value.runtime.State != "" {
			cache.lru.MoveToFront(element)
			position, runtime := value.position, value.runtime
			cache.mu.Unlock()
			return reportReference{NetworkID: position.owner.network, DeviceID: position.owner.device, ReportSequence: position.sequence}, runtime, nil
		}
	}
	cache.mu.Unlock()
	report, err := store.verifiedReport(raw, key)
	if err != nil {
		return reportReference{}, RuntimeReadback{}, err
	}
	return referenceOf(report), RuntimeReadback{State: report.Runtime.State, AppliedViewDigest: report.Runtime.AppliedViewDigest, ErrorCode: report.Runtime.ErrorCode}, nil
}
