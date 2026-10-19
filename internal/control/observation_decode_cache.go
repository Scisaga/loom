package control

import (
	"bytes"
	"container/list"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
)

const reportCacheBytes = 16 << 20

// Conservative charges include allocator rounding, entry/list/map slots, ID
// backing storage and retained Swiss-map split slack. Pool map/value overhead is charged
// separately from the shared strings, never once per referring report.
const reportCacheEntryCost = 352
const reportCachePoolCost = 256
const reportCacheBaseCost = 1024

type reportCacheEntry struct {
	id       string
	sequence U64
	identity *reportCacheIdentity
	runtime  *reportCacheRuntime
	cost     int
}

type reportCacheIdentityKey struct {
	owner       reportOwner
	verifiedKey string
}

type reportCacheIdentity struct {
	value reportCacheIdentityKey
	refs  int
	cost  int
}

type reportCacheRuntimeKey struct {
	state, appliedViewDigest, errorCode string
}

type reportCacheRuntime struct {
	value reportCacheRuntimeKey
	refs  int
	cost  int
}

// Immutable canonical-validation and signature results only. Dynamic authorization is never cached.
// Shared identity/runtime scalars have exactly the referring LRU entries' lifetime.
type reportCache struct {
	mu         sync.Mutex
	items      map[string]*list.Element
	identities map[reportCacheIdentityKey]*reportCacheIdentity
	runtimes   map[reportCacheRuntimeKey]*reportCacheRuntime
	lru        list.List
	bytes      int
}

func (cache *reportCache) clear() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.items, cache.identities, cache.runtimes = nil, nil, nil
	cache.lru.Init()
	cache.bytes = 0
}

func reportCacheStringCost(value string) int {
	return (len(value) + 15) &^ 15
}

func (cache *reportCache) rememberCanonical(id string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.items == nil {
		cache.items = map[string]*list.Element{}
		cache.identities = map[reportCacheIdentityKey]*reportCacheIdentity{}
		cache.runtimes = map[reportCacheRuntimeKey]*reportCacheRuntime{}
		cache.bytes = reportCacheBaseCost
	}
	if cache.items[id] != nil {
		return
	}
	for cache.bytes+reportCacheEntryCost > reportCacheBytes {
		cache.evict()
	}
	cache.items[id] = cache.lru.PushFront(&reportCacheEntry{id: id, cost: reportCacheEntryCost})
	cache.bytes += reportCacheEntryCost
}

// All pool mutations and evictions run under cache.mu.
func (cache *reportCache) release(value *reportCacheEntry) {
	if identity := value.identity; identity != nil {
		identity.refs--
		if identity.refs == 0 {
			delete(cache.identities, identity.value)
			cache.bytes -= identity.cost
		}
		value.identity = nil
	}
	if runtime := value.runtime; runtime != nil {
		runtime.refs--
		if runtime.refs == 0 {
			delete(cache.runtimes, runtime.value)
			cache.bytes -= runtime.cost
		}
		value.runtime = nil
	}
}

func (cache *reportCache) evict() {
	old := cache.lru.Back()
	value := old.Value.(*reportCacheEntry)
	cache.release(value)
	cache.bytes -= value.cost
	delete(cache.items, value.id)
	cache.lru.Remove(old)
}

func (store *ObservationStore) decodedReport(raw []byte) (DeviceReport, error) {
	return store.decodedReportWithID(raw, ReleaseDigest(raw))
}

// Return a value that passed complete canonical and static value validation.
// DecodeCanonical runs DeviceReport.Validate and all nested validators before
// a digest enters this cache. id comes from these freshly read bytes.
func (store *ObservationStore) decodedReportWithID(raw []byte, id string) (DeviceReport, error) {
	return store.decodedReportWithCodec(raw, id, nil)
}

func (store *ObservationStore) decodedReportWithCodec(raw []byte, id string, codec *contractCodec) (DeviceReport, error) {
	cache := &store.cache
	cache.mu.Lock()
	if element := cache.items[id]; element != nil {
		cache.lru.MoveToFront(element)
		cache.mu.Unlock()
		// The digest names the same bytes and already validated value. Reparse
		// without repeating their canonical or static validation proof.
		var report DeviceReport
		err := json.Unmarshal(raw, &report)
		return report, err
	}
	cache.mu.Unlock()
	var report DeviceReport
	if codec == nil {
		codec = newContractCodec()
	}
	if err := decodeStoredReportWithCodec(raw, &report, codec); err != nil {
		return report, err
	}
	// Keep only immutable validation results, never entire report bodies.
	cache.rememberCanonical(id)
	return report, nil
}
func (store *ObservationStore) verifiedReport(raw []byte, key string) (DeviceReport, error) {
	id := ReleaseDigest(raw)
	report, err := store.decodedReportWithID(raw, id)
	if err != nil {
		return report, err
	}
	return store.verifiedHistoryOriginal(&reportHistoryOriginal{id: id, report: report}, key)
}

// The caller already decoded the exact canonical bytes named by this digest.
// Reuse that one value while still requiring this call's exact key; neither
// the current authorization nor report contents enter the proof cache.
func (store *ObservationStore) verifiedHistoryOriginal(original *reportHistoryOriginal, key string) (DeviceReport, error) {
	if original == nil {
		return DeviceReport{}, errors.New("report original is unavailable")
	}
	id, report := original.id, original.report
	cache := &store.cache
	cache.mu.Lock()
	if element := cache.items[id]; element != nil && key != "" {
		value := element.Value.(*reportCacheEntry)
		if value.identity != nil && value.identity.value.verifiedKey == key {
			cache.mu.Unlock()
			return report, nil
		}
	}
	cache.mu.Unlock()
	if err := report.Verify(key); err != nil {
		return DeviceReport{}, err
	}
	store.rememberVerifiedRuntime(id, key, report)
	return report, nil
}

func (store *ObservationStore) rememberVerifiedRuntime(id, key string, report DeviceReport) {
	cache := &store.cache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element := cache.items[id]
	if element == nil {
		return
	}
	value := element.Value.(*reportCacheEntry)
	identityKey := reportCacheIdentityKey{reportOwner{report.NetworkID, report.DeviceID}, key}
	runtimeKey := reportCacheRuntimeKey{report.Runtime.State, report.Runtime.AppliedViewDigest, report.Runtime.ErrorCode}
	cache.lru.MoveToFront(element)
	if value.identity != nil && value.runtime != nil && value.identity.value == identityKey && value.runtime.value == runtimeKey {
		return
	}
	cache.release(value)
	identityCost := reportCachePoolCost + reportCacheStringCost(report.NetworkID) + reportCacheStringCost(report.DeviceID) + reportCacheStringCost(key)
	runtimeCost := reportCachePoolCost + reportCacheStringCost(report.Runtime.State) + reportCacheStringCost(report.Runtime.AppliedViewDigest) + reportCacheStringCost(report.Runtime.ErrorCode)
	for {
		extra := 0
		if cache.identities[identityKey] == nil {
			extra += identityCost
		}
		if cache.runtimes[runtimeKey] == nil {
			extra += runtimeCost
		}
		if cache.bytes+extra <= reportCacheBytes {
			break
		}
		cache.evict()
	}
	identity := cache.identities[identityKey]
	if identity == nil {
		owned := reportCacheIdentityKey{reportOwner{strings.Clone(report.NetworkID), strings.Clone(report.DeviceID)}, strings.Clone(key)}
		identity = &reportCacheIdentity{value: owned, cost: identityCost}
		cache.identities[owned] = identity
		cache.bytes += identityCost
	}
	runtime := cache.runtimes[runtimeKey]
	if runtime == nil {
		owned := reportCacheRuntimeKey{strings.Clone(report.Runtime.State), strings.Clone(report.Runtime.AppliedViewDigest), strings.Clone(report.Runtime.ErrorCode)}
		runtime = &reportCacheRuntime{value: owned, cost: runtimeCost}
		cache.runtimes[owned] = runtime
		cache.bytes += runtimeCost
	}
	identity.refs++
	runtime.refs++
	value.identity, value.runtime, value.sequence = identity, runtime, report.ReportSequence
}

// The input remains freshly read original bytes. This projection never renews
// an observation or supplies authorization; callers still check its position.
func (store *ObservationStore) originalRuntime(raw []byte, key string) (reportReference, RuntimeReadback, error) {
	return store.originalRuntimeKeys(raw, []string{key})
}

// Historical identity alternatives share one canonical report and signature
// message; no failed key causes another full decode or message construction.
func (store *ObservationStore) originalRuntimeKeys(raw []byte, keys []string) (reportReference, RuntimeReadback, error) {
	return store.originalRuntimeKeysWithID(raw, ReleaseDigest(raw), keys)
}

// Reuse only a digest freshly computed for this read, never a storage-key hint.
func (store *ObservationStore) originalRuntimeKeysWithID(raw []byte, id string, keys []string) (reportReference, RuntimeReadback, error) {
	return store.originalRuntimeKeysWithCodec(raw, id, keys, nil)
}

func (store *ObservationStore) originalRuntimeKeysWithCodec(raw []byte, id string, keys []string, codec *contractCodec) (reportReference, RuntimeReadback, error) {
	reference, runtime, _, err := store.originalRuntimeKeysWithCodecAndKey(raw, id, keys, codec)
	return reference, runtime, err
}

// The successful key is a query-local ordering hint, never an additional
// identity. Cache hits and cold verification both require it in this key set.
func (store *ObservationStore) originalRuntimeKeysWithCodecAndKey(raw []byte, id string, keys []string, codec *contractCodec) (reportReference, RuntimeReadback, string, error) {
	if reference, runtime, key, found := store.cachedOriginalRuntime(id, keys); found {
		return reference, runtime, key, nil
	}
	report, err := store.decodedReportWithCodec(raw, id, codec)
	if err != nil {
		return reportReference{}, RuntimeReadback{}, "", err
	}
	message, err := reportMessageFromCanonical(raw, report.Signature)
	if err != nil {
		return reportReference{}, RuntimeReadback{}, "", err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(report.Signature)
	for _, key := range keys {
		public, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != key {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(public), message, signature) {
			store.rememberVerifiedRuntime(id, key, report)
			return referenceOf(report), RuntimeReadback{State: report.Runtime.State, AppliedViewDigest: report.Runtime.AppliedViewDigest, ErrorCode: report.Runtime.ErrorCode}, key, nil
		}
	}
	return reportReference{}, RuntimeReadback{}, "", errors.New("no historical identity verifies report")
}

// The caller freshly hashed the actual original bytes. This lookup retains only
// immutable scalar copies, never transaction bytes, and never enters a database.
// It may run in a short database read transaction: cache.mu is released before
// returning, and no cache-locked path acquires a database transaction.
func (store *ObservationStore) cachedOriginalRuntime(id string, keys []string) (reportReference, RuntimeReadback, string, bool) {
	cache := &store.cache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	element := cache.items[id]
	if element == nil {
		return reportReference{}, RuntimeReadback{}, "", false
	}
	value := element.Value.(*reportCacheEntry)
	if value.identity == nil || value.runtime == nil || !containsString(keys, value.identity.value.verifiedKey) {
		return reportReference{}, RuntimeReadback{}, "", false
	}
	cache.lru.MoveToFront(element)
	identity, runtime := value.identity.value, value.runtime.value
	return reportReference{NetworkID: identity.owner.network, DeviceID: identity.owner.device, ReportSequence: value.sequence},
		RuntimeReadback{State: runtime.state, AppliedViewDigest: runtime.appliedViewDigest, ErrorCode: runtime.errorCode}, identity.verifiedKey, true
}

// Only reorder an existing key in a caller-owned query copy. The accepted set
// and the order of every other historical key stay unchanged.
func preferHistoricalReportKey(keys []string, verified string) {
	for i, key := range keys {
		if key == verified {
			copy(keys[1:i+1], keys[:i])
			keys[0] = verified
			return
		}
	}
}

// Only for an original that already passed strict canonical decoding and
// DeviceReport.Validate. Removing its own signature preserves every other
// canonical byte, including optional fields, without encoding the report again.
func reportMessageFromCanonical(raw []byte, signature string) ([]byte, error) {
	const field = `"signature":`
	depth, quoted, escaped := 0, false, false
	for i, c := range raw {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case '"':
			if depth == 1 && i > 0 && (raw[i-1] == '{' || raw[i-1] == ',') && bytes.HasPrefix(raw[i:], []byte(field)) {
				value := i + len(field)
				end := value + len(signature) + 2
				if end >= len(raw) || raw[value] != '"' || raw[end-1] != '"' || !bytes.Equal(raw[value+1:end-1], []byte(signature)) {
					return nil, errors.New("canonical report signature field differs")
				}
				start := i
				if raw[end] == ',' {
					end++
				} else if raw[end] == '}' {
					if start > 1 {
						start--
					}
				} else {
					return nil, errors.New("canonical report signature boundary differs")
				}
				message := make([]byte, 0, len(reportDomain)+len(raw)-(end-start))
				message = append(message, reportDomain...)
				message = append(message, raw[:start]...)
				return append(message, raw[end:]...), nil
			}
			quoted = true
		}
	}
	return nil, errors.New("canonical report has no top-level signature")
}
