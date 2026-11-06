package control

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// This bounded, deletable cache only avoids resending unchanged report samples.
// Losing it, changing control or restarting produces a fresh full snapshot.
type measurementSnapshot struct {
	token, device, view string
	values              []DeviceLinkObservation
	bytes               int
}

func MeasurementItemID(value DeviceLinkObservation) (string, error) {
	sample := value.Observation
	return digestContractValue("loom-measurement-item-v3\x00", map[string]any{
		"source": value.DeviceID, "level": sample.Level, "network_generation": sample.NetworkGeneration,
		"resource_id": sample.ResourceID, "link_id": sample.LinkID, "target": sample.Target,
		"action": sample.Action, "spec_digest": sample.SpecDigest,
	})
}
func measurementDeliveryOrder(value DeviceLinkObservation) string {
	sample := value.Observation
	if sample.Level == "link" {
		return "link\x00" + sample.LinkID
	}
	return "egress\x00" + value.DeviceID + "\x00" + sample.Target + "\x00" + sample.SpecDigest + "\x00" + sample.NetworkGeneration
}
func sameDeliveredMeasurement(left, right DeviceLinkObservation) bool {
	// A repeated report is another reference to the same original sample. Its
	// new report number does not make that sample newer or extend its validity.
	return left.DeviceID == right.DeviceID && left.CurrentUntil == right.CurrentUntil && reflect.DeepEqual(left.Observation, right.Observation)
}
func measurementMap(values []DeviceLinkObservation) (map[string]DeviceLinkObservation, error) {
	result := map[string]DeviceLinkObservation{}
	for _, value := range values {
		id, err := MeasurementItemID(value)
		if err != nil {
			return nil, err
		}
		if _, found := result[id]; found {
			return nil, errors.New("duplicate measurement item")
		}
		result[id] = value
	}
	return result, nil
}

// MeasurementDeliveryLimit bounds the complete disposable client snapshot,
// not the number of Services or authorized measurement specifications.
const MeasurementDeliveryLimit = 8 << 20

type measurementDeliveryBounds struct{ Bytes, CacheBytes, Entries, Scans, Queries, Sources int }

var defaultMeasurementDeliveryBounds = measurementDeliveryBounds{MeasurementDeliveryLimit, MeasurementDeliveryLimit, 64, 1024, 256, 8}

func (b measurementDeliveryBounds) valid() bool {
	return b.Bytes > 0 && b.CacheBytes >= b.Bytes && b.Entries > 0 && b.Scans > 0 && b.Queries > 0 && b.Sources > 0
}
func measurementPosition(cursor string) uint64 {
	if len(cursor) != 51 || !strings.HasPrefix(cursor, "m-") || cursor[34] != '-' {
		return 0
	}
	value, err := strconv.ParseUint(cursor[35:], 16, 64)
	if err != nil {
		return 0
	}
	return value
}
func measurementCursor(position uint64) (string, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "m-" + base64.RawURLEncoding.EncodeToString(nonce[:]) + fmt.Sprintf("-%016x", position), nil
}

// All minted tokens use identical JSON-safe lengths, so this has the exact
// final envelope byte cost without drawing randomness in a pure projection.
func measurementCursorSizeValue(position uint64) string {
	return "m-" + strings.Repeat("0", 32) + fmt.Sprintf("-%016x", position)
}

type measurementDeliveryOptions struct {
	next   uint64
	bounds measurementDeliveryBounds
}

func (server *Server) issueMeasurementDelivery(full DeviceLinkObservations, previous string, option measurementDeliveryOptions) (DeviceLinkObservations, error) {
	if !option.bounds.valid() {
		return DeviceLinkObservations{}, errors.New("invalid measurement delivery bounds")
	}

	// Snapshot values are immutable. Expensive maps/encoding do not hold the
	// shared Server mutex and cannot delay independent control operations.
	before := server.measurementBase(previous, full.DeviceID, full.ViewDigest)

	full.Reset = true
	full.Removed = []string{}
	full.Cursor = measurementCursorSizeValue(option.next)
	if full.Validate() != nil {
		return DeviceLinkObservations{}, errors.New("invalid measurement working set")
	}
	current, err := measurementMap(full.Observations)
	if err != nil {
		return DeviceLinkObservations{}, err
	}
	body, err := CanonicalEncode(full)
	if err != nil || len(body) > option.bounds.Bytes {
		return DeviceLinkObservations{}, errors.New("measurement working set exceeds byte budget")
	}
	result := full
	result.Reset = before == nil
	if before != nil {
		old, err := measurementMap(before.values)
		if err != nil {
			return DeviceLinkObservations{}, err
		}
		result.Observations = []DeviceLinkObservation{}
		for id, value := range current {
			if prior, found := old[id]; !found || !sameDeliveredMeasurement(value, prior) {
				result.Observations = append(result.Observations, value)
			}
		}
		for id := range old {
			if _, found := current[id]; !found {
				result.Removed = append(result.Removed, id)
			}
		}
		sort.Strings(result.Removed)
		sort.Slice(result.Observations, func(i, j int) bool {
			return measurementDeliveryOrder(result.Observations[i]) < measurementDeliveryOrder(result.Observations[j])
		})
		encoded, err := CanonicalEncode(result)
		if err != nil {
			return DeviceLinkObservations{}, err
		}
		if len(encoded) > option.bounds.Bytes {
			result = full
		}
	}
	result.Cursor, err = measurementCursor(option.next)
	if err != nil {
		return DeviceLinkObservations{}, err
	}
	full.Cursor = result.Cursor
	body, err = CanonicalEncode(full)
	if err != nil || len(body) > option.bounds.Bytes {
		return DeviceLinkObservations{}, errors.New("measurement working set exceeds final byte budget")
	}
	encoded, err := CanonicalEncode(result)
	if err != nil || len(encoded) > option.bounds.Bytes || result.Validate() != nil {
		return DeviceLinkObservations{}, errors.New("measurement response exceeds byte budget")
	}
	snapshot := measurementSnapshot{result.Cursor, full.DeviceID, full.ViewDigest, append([]DeviceLinkObservation{}, full.Observations...), len(body)}
	server.mu.Lock()
	defer server.mu.Unlock()
	server.measurements = append(server.measurements, snapshot)
	used := 0
	for _, item := range server.measurements {
		used += item.bytes
	}
	for len(server.measurements) > option.bounds.Entries || used > option.bounds.CacheBytes {
		used -= server.measurements[0].bytes
		server.measurements[0] = measurementSnapshot{}
		server.measurements = server.measurements[1:]
	}
	return result, nil
}

// MergeMeasurementDelivery returns a complete disposable client snapshot. A
// delta requires the exact prior complete scope; permission still comes from View.
func MergeMeasurementDelivery(previous *DeviceLinkObservations, next DeviceLinkObservations, view DeviceView) (DeviceLinkObservations, error) {
	return mergeMeasurementDelivery(previous, next, view, MeasurementDeliveryLimit)
}
func mergeMeasurementDelivery(previous *DeviceLinkObservations, next DeviceLinkObservations, view DeviceView, limit int) (DeviceLinkObservations, error) {
	if err := next.ValidateForView(view); err != nil {
		return DeviceLinkObservations{}, err
	}
	values := map[string]DeviceLinkObservation{}
	if !next.Reset {
		if previous == nil || !previous.Reset || previous.ValidateForView(view) != nil {
			return DeviceLinkObservations{}, errors.New("measurement delta has no matching complete cache")
		}
		var err error
		values, err = measurementMap(previous.Observations)
		if err != nil {
			return DeviceLinkObservations{}, err
		}
	}
	for _, id := range next.Removed {
		if _, found := values[id]; !found {
			return DeviceLinkObservations{}, errors.New("measurement delta removes an unknown cache item")
		}
		delete(values, id)
	}
	for _, value := range next.Observations {
		id, err := MeasurementItemID(value)
		if err != nil {
			return DeviceLinkObservations{}, err
		}
		values[id] = value
	}
	result := next
	result.Reset = true
	result.Removed = []string{}
	result.Observations = []DeviceLinkObservation{}
	for _, value := range values {
		result.Observations = append(result.Observations, value)
	}
	sort.Slice(result.Observations, func(i, j int) bool {
		return measurementDeliveryOrder(result.Observations[i]) < measurementDeliveryOrder(result.Observations[j])
	})
	if err := result.ValidateForView(view); err != nil {
		return DeviceLinkObservations{}, err
	}
	body, err := CanonicalEncode(result)
	if err != nil || len(body) > limit {
		return DeviceLinkObservations{}, errors.New("merged measurement working set exceeds byte budget")
	}
	return result, nil
}

func (server *Server) measurementBase(cursor, device, view string) *measurementSnapshot {
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, item := range server.measurements {
		if item.token == cursor && item.device == device && item.view == view {
			copy := item
			return &copy
		}
	}
	return nil
}
