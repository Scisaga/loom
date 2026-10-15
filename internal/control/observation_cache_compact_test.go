package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func assertReportCacheAccounting(t *testing.T, cache *reportCache) {
	t.Helper()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	identityRefs := map[*reportCacheIdentity]int{}
	runtimeRefs := map[*reportCacheRuntime]int{}
	cost := 0
	if cache.items != nil {
		cost = reportCacheBaseCost
	}
	for _, element := range cache.items {
		entry := element.Value.(*reportCacheEntry)
		cost += entry.cost
		if (entry.identity == nil) != (entry.runtime == nil) {
			t.Fatal("a cache entry retained only half of its verified projection")
		}
		if entry.identity != nil {
			identityRefs[entry.identity]++
			runtimeRefs[entry.runtime]++
		}
	}
	for _, identity := range cache.identities {
		if identity.refs != identityRefs[identity] || identity.refs == 0 {
			t.Fatal("identity pool outlived its referring entries")
		}
		cost += identity.cost
	}
	for _, runtime := range cache.runtimes {
		if runtime.refs != runtimeRefs[runtime] || runtime.refs == 0 {
			t.Fatal("runtime pool outlived its referring entries")
		}
		cost += runtime.cost
	}
	if cost != cache.bytes || cost > reportCacheBytes || cache.lru.Len() != len(cache.items) {
		t.Fatal("the entry, pool, and LRU costs escaped the fixed budget")
	}
}

func TestReportCacheSharesScalarsWithinBudget(t *testing.T) {
	store := &ObservationStore{}
	key := base64.RawURLEncoding.EncodeToString(testKey(t).Public().(ed25519.PublicKey))
	report := DeviceReport{NetworkID: "demo-network", DeviceID: "demo-device", Runtime: RuntimeReadback{
		State: "running", AppliedViewDigest: "sha256:" + strings.Repeat("a", 64),
	}}
	// Exercise cache storage after its existing canonical/signature admission;
	// no report bodies or fabricated business observations enter this cache.
	const count = 42000
	for i := range count {
		id := fmt.Sprintf("sha256:%064x", i)
		report.ReportSequence = U64(i + 1)
		store.cache.rememberCanonical(id)
		store.rememberVerifiedRuntime(id, key, report)
		store.rememberVerifiedRuntime(id, key, report)
	}
	if len(store.cache.items) != count || len(store.cache.identities) != 1 || len(store.cache.runtimes) != 1 {
		t.Fatal("repeated public scalars unnecessarily evicted a complete synthetic window")
	}
	assertReportCacheAccounting(t, &store.cache)
	store.cache.clear()
	assertReportCacheAccounting(t, &store.cache)
	if store.cache.items != nil || store.cache.identities != nil || store.cache.runtimes != nil || store.cache.bytes != 0 {
		t.Fatal("clear retained a cache pool or its budget")
	}
}

func TestReportCacheDistinctScalarsEvictAndReleasePools(t *testing.T) {
	store := &ObservationStore{}
	key := base64.RawURLEncoding.EncodeToString(testKey(t).Public().(ed25519.PublicKey))
	for i := range 40000 {
		id := fmt.Sprintf("sha256:%064x", i)
		report := DeviceReport{NetworkID: "demo-network", DeviceID: fmt.Sprintf("demo-device-%d", i), ReportSequence: 1,
			Runtime: RuntimeReadback{State: "error", AppliedViewDigest: "sha256:" + strings.Repeat("a", 64), ErrorCode: fmt.Sprintf("demo-error-%d", i)}}
		store.cache.rememberCanonical(id)
		store.rememberVerifiedRuntime(id, key, report)
		if store.cache.bytes > reportCacheBytes {
			t.Fatal("distinct shared values exceeded the unchanged cache budget")
		}
	}
	if len(store.cache.items) == 40000 || len(store.cache.identities) != len(store.cache.items) || len(store.cache.runtimes) != len(store.cache.items) {
		t.Fatal("eviction kept zero-reference identity/runtime values")
	}
	assertReportCacheAccounting(t, &store.cache)
	store.cache.mu.Lock()
	for store.cache.lru.Len() != 0 {
		store.cache.evict()
	}
	store.cache.mu.Unlock()
	if len(store.cache.identities) != 0 || len(store.cache.runtimes) != 0 || store.cache.bytes != reportCacheBaseCost {
		t.Fatal("last-reference eviction retained pool data")
	}
	assertReportCacheAccounting(t, &store.cache)
}

func TestReportCacheConcurrentProofReadsAndClear(t *testing.T) {
	private, other := testKey(t), testKey(t)
	public := base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	wrong := base64.RawURLEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: 1,
		ViewDigest: "sha256:" + strings.Repeat("a", 64), NetworkGeneration: "demo-network", ReportedAt: 1,
		Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalEncode(report)
	if err != nil {
		t.Fatal(err)
	}
	store := &ObservationStore{}
	var workers sync.WaitGroup
	failures := make(chan error, 4)
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 50 {
				ref, runtime, err := store.originalRuntimeKeys(raw, []string{public})
				if err != nil || ref.ReportSequence != 1 || runtime.State != "stopped" || runtime.Resources != nil {
					failures <- errors.New("concurrent eviction changed a verified projection")
					return
				}
				if _, _, err := store.originalRuntimeKeys(raw, []string{wrong}); err == nil {
					failures <- errors.New("a pooled identity supplied a key outside the query")
					return
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for range 100 {
			store.cache.clear()
		}
	}()
	workers.Wait()
	close(failures)
	for failure := range failures {
		t.Fatal(failure)
	}
	assertReportCacheAccounting(t, &store.cache)
}
