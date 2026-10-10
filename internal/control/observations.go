package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	bolt "go.etcd.io/bbolt"
)

var ErrReportEquivocation = errors.New("device signed different reports at one sequence")
var ErrReportReplay = errors.New("device report sequence is below the durable high-water mark")

func reportBefore(left DeviceReport, leftBody []byte, right DeviceReport, rightBody []byte) bool {
	if left.NetworkID != right.NetworkID {
		return left.NetworkID < right.NetworkID
	}
	if left.DeviceID != right.DeviceID {
		return left.DeviceID < right.DeviceID
	}
	if left.ReportSequence != right.ReportSequence {
		return left.ReportSequence < right.ReportSequence
	}
	return bytes.Compare(leftBody, rightBody) < 0
}

type ObservationStore struct {
	path     string
	entry    os.FileInfo
	db       *bolt.DB
	lifetime sync.RWMutex
	write    chan struct{}
	cache    reportCache
}

type reportOwner struct{ network, device string }
type reportPosition struct {
	owner    reportOwner
	sequence U64
}

func OpenObservationStore(root string) (*ObservationStore, error) {
	if err := validateControlRoot(root); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(root, ".observations.lock")
	_, priorLock := os.Lstat(lockPath)
	_, nodeErr := os.Lstat(filepath.Join(root, "node.json"))
	lock, err := lockProtectedControlPath(context.Background(), lockPath)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := rejectObservationJSON(root); err != nil {
		return nil, err
	}
	path := filepath.Join(root, "observations.db")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if !errors.Is(priorLock, os.ErrNotExist) || !errors.Is(nodeErr, os.ErrNotExist) {
			return nil, errors.New("existing observation history is missing; report high-water marks cannot be reinitialized")
		}
		if err := initializeObservationDB(path); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	db, entry, err := openReportDatabase(context.Background(), path, false)
	if err != nil {
		return nil, err
	}
	store := &ObservationStore{path: path, entry: entry, db: db, write: make(chan struct{}, 1)}
	indexed := false
	err = db.View(func(tx *bolt.Tx) error { indexed = tx.Bucket(reportIndexBucket) != nil; return nil })
	if err == nil && !indexed {
		err = store.withDatabase(context.Background(), true, ensureReportIndexes)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}
func (store *ObservationStore) Put(report DeviceReport, publicKey string) error {
	return store.mergeReports(context.Background(), []DeviceReport{report}, map[reportOwner]string{{report.NetworkID, report.DeviceID}: publicKey}, false)
}
func (store *ObservationStore) mergeReportHistory(ctx context.Context, reports []DeviceReport, projection Projection) error {
	keys := map[reportOwner]string{}
	for _, report := range reports {
		authorization, ok := identityFor(projection, report.DeviceID)
		if !ok || report.NetworkID != projection.NetworkID {
			return errors.New("peer report is outside current device authorization")
		}
		keys[reportOwner{report.NetworkID, report.DeviceID}] = authorization.DevicePublicKey
	}
	return store.mergeReports(ctx, reports, keys, true)
}
func (store *ObservationStore) mergeReports(ctx context.Context, reports []DeviceReport, keys map[reportOwner]string, historical bool) error {
	if len(reports) == 0 {
		return errors.New("empty report merge")
	}
	bodies := make([][]byte, len(reports))
	positions := map[reportPosition]bool{}
	owners := []reportOwner{}
	seenOwners := map[reportOwner]bool{}
	for i, report := range reports {
		if err := ctx.Err(); err != nil {
			return err
		}
		owner := reportOwner{report.NetworkID, report.DeviceID}
		if err := report.Verify(keys[owner]); err != nil {
			return err
		}
		body, err := CanonicalEncode(report)
		if err != nil || len(body) > controlHTTPBodyLimit {
			return errors.New("report exceeds its input boundary")
		}
		bodies[i] = body
		positions[reportPosition{owner, report.ReportSequence}] = true
		if !seenOwners[owner] {
			owners = append(owners, owner)
			seenOwners[owner] = true
		}
	}
	sort.Slice(owners, func(i, j int) bool {
		return owners[i].network < owners[j].network || owners[i].network == owners[j].network && owners[i].device < owners[j].device
	})
	fork := false
	err := store.withDatabase(ctx, true, func(tx *bolt.Tx) error {
		touched := map[storedReportRange]bool{}
		bucket := tx.Bucket(observationBucket)
		high := map[reportOwner]U64{}
		known := map[reportPosition]map[string]bool{}
		// Only the durable highest position and incoming positions determine
		// replay, idempotence and equivocation. Read every fork at those positions.
		for _, owner := range owners {
			highest, err := highestReportPosition(bucket, owner)
			if err != nil {
				return err
			}
			high[owner] = highest
			needed := map[U64]bool{}
			if highest != 0 {
				needed[highest] = true
			}
			for position := range positions {
				if position.owner == owner {
					needed[position.sequence] = true
				}
			}
			sequences := make([]U64, 0, len(needed))
			for sequence := range needed {
				sequences = append(sequences, sequence)
			}
			sort.Slice(sequences, func(i, j int) bool { return sequences[i] < sequences[j] })
			for _, sequence := range sequences {
				err := readReportPosition(ctx, bucket, owner, sequence, func(id string, ref reportReference, prior DeviceReport) error {
					if prior.Verify(keys[owner]) != nil {
						return errors.New("stored report position does not verify against the immutable device key")
					}
					position := reportPosition{owner, ref.ReportSequence}
					if positions[position] {
						if known[position] == nil {
							known[position] = map[string]bool{}
						}
						known[position][id] = true
					}
					return ctx.Err()
				})
				if err != nil {
					return err
				}
			}
		}
		for i, report := range reports {
			if err := ctx.Err(); err != nil {
				return err
			}
			owner := reportOwner{report.NetworkID, report.DeviceID}
			position := reportPosition{owner, report.ReportSequence}
			id := ReleaseDigest(bodies[i])
			ids := known[position]
			if ids[id] {
				fork = fork || len(ids) > 1
				continue
			}
			if !historical && report.ReportSequence < high[owner] && len(ids) == 0 {
				return ErrReportReplay
			}
			fork = fork || len(ids) > 0
			if ids == nil {
				ids = map[string]bool{}
				known[position] = ids
			}
			ids[id] = true
			key := referenceOf(report).key(id)
			if err := bucket.Put(key, bodies[i]); err != nil {
				return err
			}
			if err := indexReport(tx, key, report); err != nil {
				return err
			}
			touched[storedReportRange{report.NetworkID, reportScope{report.DeviceID, reportRangeStart(report.ReportSequence)}}] = true
		}
		for group := range touched {
			if err := updateReportRange(tx, group); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return err
	}
	if fork {
		return ErrReportEquivocation
	}
	return nil
}

// Latest returns original highest reports. A highest-sequence fork has no winner.
// Read failures are explicit so the UI cannot silently serve a cached success.
func (store *ObservationStore) Latest(ctx context.Context) ([]DeviceReport, error) {
	result := []DeviceReport{}
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		bucket := tx.Bucket(observationBucket)
		cursor := bucket.Cursor()
		for key, _ := cursor.First(); key != nil; {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, location, err := locateReportKey(key)
			if err != nil {
				return err
			}
			owner := reportOwner{location.NetworkID, location.DeviceID}
			highest, err := highestReportPosition(bucket, owner)
			if err != nil {
				return err
			}
			var original DeviceReport
			count := 0
			err = readReportPosition(ctx, bucket, owner, highest, func(_ string, _ reportReference, report DeviceReport) error {
				count++
				original = report
				return nil
			})
			if err != nil {
				return err
			}
			if count == 1 {
				result = append(result, original)
			}
			key, _ = cursor.Seek(reportOwnerEnd(owner))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return reportBefore(result[i], nil, result[j], nil) })
	return result, nil
}
func verifyCurrentReport(report DeviceReport, projection Projection, releases ...ReleaseSet) error {
	return verifyCurrentReportUsing(report, projection, func(id string) (DeviceView, error) {
		return ProjectDeviceView(projection, id, releases...)
	})
}

func verifyCurrentReportUsing(report DeviceReport, projection Projection, viewFor func(string) (DeviceView, error)) error {
	if report.NetworkID != projection.NetworkID {
		return errors.New("device report belongs to another network")
	}
	authorization, found := identityFor(projection, report.DeviceID)
	if !found || report.Verify(authorization.DevicePublicKey) != nil {
		return errors.New("device report signature or authorization rejected")
	}
	view, err := viewFor(report.DeviceID)
	if err != nil {
		return err
	}
	digest, err := DeviceViewDigest(view)
	if err != nil || report.ViewDigest != digest {
		return errors.New("device report view is stale")
	}
	return verifyReportViewFields(report, view)
}
func verifyReportViewFields(report DeviceReport, view DeviceView) error {
	if err := verifyWireGuardCounters(report.WireGuardCounters, view); err != nil {
		return err
	}
	if report.Preference != nil && !containsString(view.Responsibilities, "access") {
		return errors.New("routing preference report requires an access device")
	}
	owned := map[string]TransportResource{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID == view.DeviceID && (resource.Kind == "hysteria2" || resource.Kind == "wireguard") {
			owned[resource.ID] = resource
		}
	}
	if report.Runtime.Resources != nil {
		if report.Runtime.AppliedViewDigest != report.ViewDigest || len(*report.Runtime.Resources) != len(owned) {
			return errors.New("resource readback is not for the complete applied view")
		}
		for _, value := range *report.Runtime.Resources {
			resource, exists := owned[value.ResourceID]
			digest, err := InboundACLDigest(view, value.ResourceID)
			if !exists || resource.ListenerID != value.ListenerID || err != nil || value.ACLDigest != digest {
				return errors.New("resource readback does not match its current listener and ACL")
			}
			if resource.Kind == "wireguard" && (value.PublicKey != *resource.Authentication.PublicKey || value.CertificateDigest != "") || resource.Kind == "hysteria2" && (value.PublicKey != "" || ValidateDigest(value.CertificateDigest) != nil) {
				return errors.New("resource readback identity does not match its transport")
			}
		}
	} else if len(owned) != 0 && report.Runtime.State == "running" && report.Runtime.AppliedViewDigest == report.ViewDigest {
		return errors.New("running resource execution has no listener and ACL readback")
	}
	routes := map[string]RouteCandidate{}
	for _, route := range view.Routes {
		routes[route.ID] = route
	}
	for _, selection := range report.Selections {
		route, found := routes[selection.CandidateID]
		if !found || route.ServiceID != selection.ServiceID {
			return errors.New("report selection is outside the current view")
		}
	}
	var resourceProbes []ResourceProbe
	for _, observation := range report.Observations {
		if observation.Level == "resource" {
			if resourceProbes == nil {
				var err error
				resourceProbes, err = FirstHopProbes(view)
				if err != nil {
					return err
				}
			}
			if err := verifyResourceObservation(observation, resourceProbes); err != nil {
				return err
			}
			continue
		}
		if observation.Level == "link" {
			if err := verifyLinkObservation(observation, view); err != nil {
				return err
			}
			continue
		}
		route, found := routes[observation.CandidateID]
		if !found || observation.Level != "service" || route.ServiceID != observation.ServiceID || route.SpecDigest != observation.SpecDigest {
			return errors.New("report observation specification is outside the current view")
		}
		allowed := false
		for _, set := range view.BusinessProbeTargets {
			if set.ServiceID == observation.ServiceID {
				for _, target := range set.Targets {
					allowed = allowed || target == observation.Target
				}
			}
		}
		if !allowed {
			return errors.New("report observation target is outside the current view")
		}
	}
	return nil
}
