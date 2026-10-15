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
	id := ReleaseDigest(raw)
	report, err := store.decodedReportWithID(raw, id)
	if err != nil {
		return report, err
	}
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
	store.rememberVerifiedRuntime(id, key, report)
	return report, nil
}

func (store *ObservationStore) rememberVerifiedRuntime(id, key string, report DeviceReport) {
	cache := &store.cache
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
	cache := &store.cache
	cache.mu.Lock()
	if element := cache.items[id]; element != nil {
		value := element.Value.(*reportCacheEntry)
		if value.verifiedKey != "" && containsString(keys, value.verifiedKey) && value.runtime.State != "" {
			cache.lru.MoveToFront(element)
			position, runtime := value.position, value.runtime
			cache.mu.Unlock()
			return reportReference{NetworkID: position.owner.network, DeviceID: position.owner.device, ReportSequence: position.sequence}, runtime, nil
		}
	}
	cache.mu.Unlock()
	report, err := store.decodedReportWithCodec(raw, id, codec)
	if err != nil {
		return reportReference{}, RuntimeReadback{}, err
	}
	message, err := reportMessageFromCanonical(raw, report.Signature)
	if err != nil {
		return reportReference{}, RuntimeReadback{}, err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(report.Signature)
	for _, key := range keys {
		public, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != key {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(public), message, signature) {
			store.rememberVerifiedRuntime(id, key, report)
			return referenceOf(report), RuntimeReadback{State: report.Runtime.State, AppliedViewDigest: report.Runtime.AppliedViewDigest, ErrorCode: report.Runtime.ErrorCode}, nil
		}
	}
	return reportReference{}, RuntimeReadback{}, errors.New("no historical identity verifies report")
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
