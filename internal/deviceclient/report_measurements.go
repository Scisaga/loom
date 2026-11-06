package deviceclient

import (
	"crypto/sha256"
	"errors"
	"loom/internal/control"
	"sync"
)

// This bounded cache saves upload bytes only. Losing it causes duplicates, and
// remembering a sample requires an ACK for the complete signed original.
type reportMeasurementCache struct {
	mu    sync.Mutex
	items map[[sha256.Size]byte]bool
	ring  [][sha256.Size]byte
	next  int
}

var confirmedMeasurements = reportMeasurementCache{ring: make([][sha256.Size]byte, 16384)}

func measurementDigests(report control.DeviceReport, publicKey string) ([][sha256.Size]byte, error) {
	if control.ValidateID(report.NetworkID) != nil || control.ValidateID(report.DeviceID) != nil || control.ValidatePublicKey(publicKey) != nil {
		return nil, errors.New("report measurement source is invalid")
	}
	if err := control.ValidateReportObservations(report.Observations, report.NetworkGeneration); err != nil {
		return nil, err
	}
	values := make([][sha256.Size]byte, 0, len(report.Observations))
	for _, sample := range report.Observations {
		body, err := control.CanonicalEncode(map[string]any{"network_id": report.NetworkID, "device_id": report.DeviceID, "public_key": publicKey, "observation": sample})
		if err != nil {
			return nil, err
		}
		values = append(values, sha256.Sum256(append([]byte("loom-confirmed-measurement-v3\x00"), body...)))
	}
	return values, nil
}

// UnreportedObservations runs before signing a newly reserved report. It never
// changes an original that has already been sent or its immutable retry body.
func UnreportedObservations(report control.DeviceReport, publicKey string) ([]control.Observation, error) {
	return confirmedMeasurements.pending(report, publicKey)
}

func (cache *reportMeasurementCache) pending(report control.DeviceReport, publicKey string) ([]control.Observation, error) {
	digests, err := measurementDigests(report, publicKey)
	if err != nil {
		return nil, err
	}
	result := make([]control.Observation, 0, len(report.Observations))
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for index, digest := range digests {
		if !cache.items[digest] {
			result = append(result, report.Observations[index])
		}
	}
	return result, nil
}

func (cache *reportMeasurementCache) remember(report control.DeviceReport, publicKey string) error {
	digests, err := measurementDigests(report, publicKey)
	if err != nil {
		return err
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.ring) == 0 {
		return nil
	}
	if cache.items == nil {
		cache.items = make(map[[sha256.Size]byte]bool, len(cache.ring))
	}
	for _, digest := range digests {
		if cache.items[digest] {
			continue
		}
		delete(cache.items, cache.ring[cache.next])
		cache.ring[cache.next] = digest
		cache.items[digest] = true
		cache.next = (cache.next + 1) % len(cache.ring)
	}
	return nil
}
