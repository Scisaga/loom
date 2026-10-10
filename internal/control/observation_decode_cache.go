package control

import (
	"container/list"
	"encoding/json"
	"sync"
)

const reportCacheBytes = 16 << 20

type reportCacheEntry struct {
	id          string
	verifiedKey string
	cost        int
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
		element.Value.(*reportCacheEntry).verifiedKey = key
	}
	cache.mu.Unlock()
	return report, nil
}
