package loomcore

import (
	"bytes"
	"crypto/sha256"
	"sync"

	"loom/internal/deviceclient"
)

// Successful canonical inputs retain only disposable owned decode results.
// A hit returns a deep copy, never the mutable value held by this reader.
type androidStateReadCache struct {
	mu      sync.Mutex
	digests [4][sha256.Size]byte
	states  [4]deviceclient.State
	count   int
	next    int
}

var androidStateReads androidStateReadCache

func (cache *androidStateReadCache) decode(input []byte, validate func([]byte) (deviceclient.State, error)) (deviceclient.State, error) {
	// This is a cache allocation budget, not a second wire limit. Larger inputs
	// retain the sole canonical decoder's original acceptance and rejection.
	if len(input) == 0 || len(input) > 1<<20 {
		return validate(input)
	}
	body := bytes.Clone(input)
	defer clear(body)
	digest := sha256.Sum256(body)
	cache.mu.Lock()
	for index, prior := range cache.digests[:cache.count] {
		if prior == digest {
			state := cache.states[index].Clone()
			cache.mu.Unlock()
			return state, nil
		}
	}
	cache.mu.Unlock()
	state, err := validate(body)
	if err == nil {
		cache.mu.Lock()
		cache.digests[cache.next] = digest
		cache.states[cache.next] = state.Clone()
		cache.next = (cache.next + 1) % len(cache.digests)
		if cache.count < len(cache.digests) {
			cache.count++
		}
		cache.mu.Unlock()
	}
	return state, err
}
