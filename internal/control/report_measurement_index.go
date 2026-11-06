package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Only immutable original locations are indexed. This child can be deleted and
// reconstructed without changing a report, a sequence or any authorization.
var reportMeasurementBucket = []byte("measurement-items")

type reportMeasurementQuery struct {
	source, publicKey string
	spec              Observation
}

// This is the current specification inventory, not work to execute. Consumers
// query the same original locations whether producers send full or delta reports.
func ownMeasurementQueries(view DeviceView, report DeviceReport) ([]reportMeasurementQuery, error) {
	queries := []reportMeasurementQuery{}
	add := func(sample Observation) {
		queries = append(queries, reportMeasurementQuery{view.DeviceID, view.DevicePublicKey, sample})
	}
	execution := DeviceExecution{DeviceView: view, Routes: []RouteCandidate{}}
	var err error
	if containsString(view.Responsibilities, "access") && len(report.SelectedPolicyIDs()) > 0 {
		execution, err = ProjectDeviceCandidates(view, report.SelectedPolicyIDs())
		if err != nil {
			return nil, err
		}
	}
	first, err := FirstHopProbes(execution)
	if err != nil {
		return nil, err
	}
	for _, probe := range first {
		add(Observation{Level: "resource", ResourceID: probe.Resource.ID, SpecDigest: probe.SpecDigest, Target: probe.Target(), Action: probe.Action()})
	}
	nodes := viewNodes(view)
	owned := ""
	for _, resource := range view.Resources {
		if resource.Kind == "wireguard" && resource.OwnerNodeID == view.DeviceID {
			owned = resource.ID
		}
	}
	for _, resource := range view.Resources {
		link, allowed, err := nodeNetworkLink(view.NetworkID, nodes[view.DeviceID], nodes[resource.OwnerNodeID], resource, owned)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		spec, err := directedLinkSpec(view.NetworkID, link, nodes[view.DeviceID], resource)
		if err != nil {
			return nil, err
		}
		add(Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)), Action: link.ProbeTarget.Action})
	}
	egress, err := EgressProbes(view)
	if err != nil {
		return nil, err
	}
	for _, probe := range egress {
		add(Observation{Level: "egress", Target: probe.Target, Action: "https_request", SpecDigest: probe.SpecDigest})
	}
	targets := map[string][]string{}
	for _, service := range view.Services {
		targets[service.ID] = service.ProbeURLs
	}
	selected := map[string]bool{}
	for _, selection := range report.Selections {
		selected[selection.CandidateID] = true
	}
	for _, route := range execution.Routes {
		if !selected[route.ID] {
			continue
		}
		for _, target := range targets[route.ServiceID] {
			add(Observation{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, Target: target, Action: "https_request", SpecDigest: route.SpecDigest})
		}
	}
	return queries, nil
}

func measurementSpecIndex(sample Observation) ([sha256.Size]byte, error) {
	if err := validateObservationSpec(sample); err != nil {
		return [sha256.Size]byte{}, err
	}
	body, err := CanonicalEncode(map[string]any{
		"level": sample.Level, "service_id": sample.ServiceID, "candidate_id": sample.CandidateID,
		"resource_id": sample.ResourceID, "link_id": sample.LinkID, "target": sample.Target,
		"action": sample.Action, "spec_digest": sample.SpecDigest,
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(append([]byte("loom-measurement-location-v3\x00"), body...)), nil
}

func measurementIndexPrefix(owner reportOwner, generation string, sample Observation) ([]byte, error) {
	if ValidateID(owner.network) != nil || ValidateID(owner.device) != nil || ValidateID(generation) != nil {
		return nil, errors.New("measurement location has an invalid source")
	}
	spec, err := measurementSpecIndex(sample)
	if err != nil {
		return nil, err
	}
	key := append(reportOwnerPrefix(owner), []byte(generation)...)
	key = append(key, 0)
	return append(key, spec[:]...), nil
}

func measurementIndexLocation(report DeviceReport, sample Observation) ([]byte, error) {
	key, err := measurementIndexPrefix(reportOwner{report.NetworkID, report.DeviceID}, sample.NetworkGeneration, sample)
	if err != nil {
		return nil, err
	}
	body, err := CanonicalEncode(sample)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	key = binary.BigEndian.AppendUint64(key, ^uint64(sample.ObservedAt))
	return append(key, sum[:]...), nil
}

func indexReportMeasurements(tx *bolt.Tx, key []byte, report DeviceReport) error {
	index := tx.Bucket(reportIndexBucket).Bucket(reportMeasurementBucket)
	if index == nil || index.Sequence() != 0 {
		return errors.New("measurement locations are missing or have an independent sequence")
	}
	for offset, sample := range report.Observations {
		location, err := measurementIndexLocation(report, sample)
		if err != nil {
			return err
		}
		// A repeated sample has one deterministic original reference. Reporting
		// the same old bytes at a larger sequence cannot make the sample newer.
		previous := index.Get(location)
		if previous != nil && len(previous) < 4 {
			return errors.New("measurement original location is truncated")
		}
		if previous == nil || bytes.Compare(key, previous[:len(previous)-4]) < 0 {
			if err := index.Put(location, binary.BigEndian.AppendUint32(bytes.Clone(key), uint32(offset))); err != nil {
				return err
			}
		}
	}
	return nil
}

func rebuildReportMeasurements(ctx context.Context, tx *bolt.Tx, keys map[reportOwner]string) error {
	parent := tx.Bucket(reportIndexBucket)
	if parent == nil {
		return errors.New("report index is missing")
	}
	if parent.Bucket(reportMeasurementBucket) != nil {
		if err := parent.DeleteBucket(reportMeasurementBucket); err != nil {
			return err
		}
	}
	if _, err := parent.CreateBucket(reportMeasurementBucket); err != nil {
		return err
	}
	codec := newContractCodec()
	return tx.Bucket(observationBucket).ForEach(func(location, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		report, _, err := verifyStoredReportOriginal(raw, location, keys, codec)
		if err != nil {
			return err
		}
		return indexReportMeasurements(tx, location, report)
	})
}

func verifyReportMeasurements(ctx context.Context, tx *bolt.Tx, keys map[reportOwner]string) error {
	parent := tx.Bucket(reportIndexBucket)
	if parent == nil || parent.Bucket(reportMeasurementBucket) == nil || parent.Bucket(reportMeasurementBucket).Sequence() != 0 {
		return errors.New("measurement locations are unavailable")
	}
	index := parent.Bucket(reportMeasurementBucket)
	expected := map[string][]byte{}
	codec := newContractCodec()
	if err := tx.Bucket(observationBucket).ForEach(func(key, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		report, _, err := verifyStoredReportOriginal(raw, key, keys, codec)
		if err != nil {
			return err
		}
		for offset, sample := range report.Observations {
			location, err := measurementIndexLocation(report, sample)
			if err != nil {
				return err
			}
			value := binary.BigEndian.AppendUint32(bytes.Clone(key), uint32(offset))
			if previous := expected[string(location)]; previous == nil || bytes.Compare(value, previous) < 0 {
				expected[string(location)] = value
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := index.ForEach(func(location, value []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if value == nil || !bytes.Equal(value, expected[string(location)]) {
			return errors.New("measurement location differs from its verified original")
		}
		delete(expected, string(location))
		return nil
	}); err != nil {
		return err
	}
	if len(expected) != 0 {
		return errors.New("measurement originals are missing from the index")
	}
	return nil
}

func ensureReportMeasurementIndex(ctx context.Context, tx *bolt.Tx) error {
	parent := tx.Bucket(reportIndexBucket)
	if parent == nil {
		return errors.New("report index is missing")
	}
	if child := parent.Bucket(reportMeasurementBucket); child != nil {
		if child.Sequence() != 0 {
			return errors.New("measurement locations have an independent sequence")
		}
		return nil
	}
	if _, err := parent.CreateBucket(reportMeasurementBucket); err != nil {
		return err
	}
	codec := newContractCodec()
	return tx.Bucket(observationBucket).ForEach(func(key, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var report DeviceReport
		if err := decodeStoredReportWithCodec(raw, &report, codec); err != nil {
			return err
		}
		if !bytes.Equal(referenceOf(report).key(ReleaseDigest(raw)), key) {
			return errors.New("measurement index original differs from its storage key")
		}
		return indexReportMeasurements(tx, key, report)
	})
}

// latestMeasurements reads exact specifications across reports. The highest
// report supplies current generation/runtime only; omission is not deletion.
// Callers derive queries from current authenticated roles and permissions.
func (store *ObservationStore) latestMeasurements(ctx context.Context, network string, queries []reportMeasurementQuery, now time.Time) ([]DeviceLinkObservation, error) {
	rows, _, _, err := store.latestMeasurementWindow(ctx, network, queries, now, 0)
	return rows, err
}
func (store *ObservationStore) latestMeasurementWindow(ctx context.Context, network string, queries []reportMeasurementQuery, now time.Time, originalBytes int) (rows []DeviceLinkObservation, checked int, generations map[string]string, failure error) {
	keys := map[string]string{}
	for _, query := range queries {
		if ValidateID(query.source) != nil || ValidatePublicKey(query.publicKey) != nil {
			return nil, 0, nil, errors.New("measurement query source is invalid")
		}
		if previous, found := keys[query.source]; found && previous != query.publicKey {
			return nil, 0, nil, errors.New("measurement source has conflicting identities")
		}
		keys[query.source] = query.publicKey
	}
	var latest []DeviceReport
	var err error
	if originalBytes > 0 {
		latest, err = store.measurementHeads(ctx, network, keys)
	} else {
		latest, err = store.LatestForDevices(ctx, network, keys)
	}
	if err != nil {
		return nil, 0, nil, err
	}
	generations = map[string]string{}
	heads := map[string]DeviceReport{}
	for _, report := range latest {
		generations[report.DeviceID] = ""
		if measurementHeadReady(report, now) {
			heads[report.DeviceID] = report
			generations[report.DeviceID] = report.NetworkGeneration
		}
	}
	type pinned struct {
		location, key, raw []byte
		query              reportMeasurementQuery
		offset             uint32
	}
	positions := []pinned{}
	seen := map[string]bool{}
	copies := map[string][]byte{}
	copiedBytes := 0
	err = store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		index := tx.Bucket(reportIndexBucket).Bucket(reportMeasurementBucket)
		if index == nil || index.Sequence() != 0 {
			return errors.New("measurement locations are unavailable")
		}
		for queryIndex, query := range queries {
			checked = queryIndex + 1
			if err := ctx.Err(); err != nil {
				return err
			}
			head, exists := heads[query.source]
			if !exists {
				continue
			}
			prefix, err := measurementIndexPrefix(reportOwner{network, query.source}, head.NetworkGeneration, query.spec)
			if err != nil {
				return err
			}
			if seen[string(prefix)] {
				continue
			}
			seen[string(prefix)] = true
			cursor := index.Cursor()
			location, key := cursor.Seek(prefix)
			if !bytes.HasPrefix(location, prefix) {
				continue
			}
			if len(location) != len(prefix)+8+sha256.Size {
				return errors.New("invalid measurement location")
			}
			if len(key) < 4 {
				return errors.New("measurement original location is truncated")
			}
			position := pinned{location: bytes.Clone(location), key: bytes.Clone(key[:len(key)-4]), query: query, offset: binary.BigEndian.Uint32(key[len(key)-4:])}
			// Equal-time contradictory originals have no winner. Expiry, future
			// clocks and failures also never revive an older successful sample.
			if next, _ := cursor.Next(); bytes.HasPrefix(next, position.location[:len(prefix)+8]) {
				continue
			}
			_, ref, err := locateReportKey(position.key)
			if err != nil || ref.NetworkID != network || ref.DeviceID != query.source {
				return errors.New("measurement reference belongs to another source")
			}
			originals := tx.Bucket(observationBucket)
			sequencePrefix := reportEventPositionPrefix(reportPosition{reportOwner{network, query.source}, ref.ReportSequence})
			originalCursor := originals.Cursor()
			first, _ := originalCursor.Seek(sequencePrefix)
			if !bytes.HasPrefix(first, sequencePrefix) {
				return errors.New("measurement original is missing")
			}
			if next, _ := originalCursor.Next(); bytes.HasPrefix(next, sequencePrefix) {
				continue
			}
			raw := originals.Get(position.key)
			if len(raw) == 0 || len(raw) > controlHTTPBodyLimit {
				return errors.New("measurement original is absent or oversized")
			}
			position.raw = copies[string(position.key)]
			if position.raw == nil {
				if originalBytes > 0 && copiedBytes > 0 && copiedBytes+len(raw) > originalBytes {
					checked = queryIndex
					break
				}
				copiedBytes += len(raw)
				position.raw = bytes.Clone(raw)
				copies[string(position.key)] = position.raw
			}
			positions = append(positions, position)
		}
		return nil
	})
	if err != nil {
		return nil, 0, nil, err
	}
	type original struct {
		report DeviceReport
		digest string
	}
	originals := map[string]original{}
	result := []DeviceLinkObservation{}
	for _, position := range positions {
		item, found := originals[string(position.key)]
		report := item.report
		if !found {
			report, err = store.verifiedReport(position.raw, position.query.publicKey)
			if err != nil {
				return nil, 0, nil, err
			}
			item.digest = ReleaseDigest(position.raw)
			if !bytes.Equal(referenceOf(report).key(item.digest), position.key) {
				return nil, 0, nil, errors.New("measurement original differs from its pinned position")
			}
			item.report = report
			originals[string(position.key)] = item
		}
		if uint64(position.offset) >= uint64(len(report.Observations)) {
			return nil, 0, nil, errors.New("measurement sample position is outside its original")
		}
		sample := report.Observations[position.offset]
		location, err := measurementIndexLocation(report, sample)
		if err != nil {
			return nil, 0, nil, err
		}
		if !bytes.Equal(location, position.location) {
			return nil, 0, nil, errors.New("measurement location has no matching original sample")
		}
		until := measurementObservationUntil(report, sample, now)
		if sample.ObservedAt <= now.UnixMilli() && until > now.UnixMilli() {
			result = append(result, DeviceLinkObservation{DeviceID: report.DeviceID, ReportSequence: report.ReportSequence,
				ReportDigest: item.digest, CurrentUntil: until, Observation: sample})
		}
	}
	sort.Slice(result, func(i, j int) bool { return measurementDeliveryOrder(result[i]) < measurementDeliveryOrder(result[j]) })
	return result, checked, generations, ctx.Err()
}

// Delivery pages bound source count before reaching this reader. Each unique
// head copies at most one legal original at a time. A highest fork supplies no
// facts; detecting its second key needs no unbounded scan of fork originals.
func (store *ObservationStore) measurementHeads(ctx context.Context, network string, keys map[string]string) ([]DeviceReport, error) {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := []DeviceReport{}
	for _, id := range ids {
		var key, raw []byte
		fork := false
		err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			bucket := tx.Bucket(observationBucket)
			highest, err := highestReportPosition(bucket, reportOwner{network, id})
			if err != nil {
				return err
			}
			if highest == 0 {
				return nil
			}
			prefix := binary.BigEndian.AppendUint64(reportOwnerPrefix(reportOwner{network, id}), uint64(highest))
			cursor := bucket.Cursor()
			first, value := cursor.Seek(prefix)
			if !bytes.HasPrefix(first, prefix) {
				return nil
			}
			second, _ := cursor.Next()
			if bytes.HasPrefix(second, prefix) {
				fork = true
				return nil
			}
			if len(value) == 0 || len(value) > controlHTTPBodyLimit {
				return errors.New("measurement head original is absent or oversized")
			}
			key, raw = bytes.Clone(first), bytes.Clone(value)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if raw == nil {
			if fork {
				result = append(result, DeviceReport{DeviceID: id})
			}
			continue
		}
		report, err := store.verifiedReport(raw, keys[id])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(referenceOf(report).key(ReleaseDigest(raw)), key) {
			return nil, errors.New("measurement head differs from its original")
		}
		result = append(result, DeviceReport{DeviceID: report.DeviceID, NetworkGeneration: report.NetworkGeneration, ReportedAt: report.ReportedAt, ViewDigest: report.ViewDigest, Runtime: report.Runtime})
	}
	return result, ctx.Err()
}
