package control

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sync/semaphore"
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
	path           string
	mu             sync.Mutex
	verified       map[string]string // Exact content ID -> immutable verification key; disposable.
	index          atomic.Pointer[reportIndex]
	indexRead      chan struct{}
	databaseAccess *semaphore.Weighted // Per-operation admission; no database handle or durable state.
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
	store := &ObservationStore{path: path, indexRead: make(chan struct{}, 1), verified: map[string]string{}, databaseAccess: semaphore.NewWeighted(math.MaxInt64)}
	if _, err := store.reportIndexSnapshot(context.Background()); err != nil {
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
	for i, report := range reports {
		if err := report.Verify(keys[reportOwner{report.NetworkID, report.DeviceID}]); err != nil {
			return err
		}
		body, err := CanonicalEncode(report)
		if err != nil || len(body) > controlHTTPBodyLimit {
			return errors.New("report exceeds its input boundary")
		}
		bodies[i] = body
		positions[reportPosition{reportOwner{report.NetworkID, report.DeviceID}, report.ReportSequence}] = true
	}
	lock, err := lockProtectedControlPath(ctx, filepath.Join(filepath.Dir(store.path), ".observations.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	store.mu.Lock()
	defer store.mu.Unlock()
	var committed *reportIndex
	fork := false
	err = store.withDatabase(ctx, true, func(tx *bolt.Tx) error {
		base, err := scanObservationIndex(ctx, tx, store.index.Load())
		if err != nil {
			return err
		}
		bucket := tx.Bucket(observationBucket)
		high := map[reportOwner]U64{}
		known := map[reportPosition]map[string]bool{}
		for id, ref := range base.reports {
			if err := ctx.Err(); err != nil {
				return err
			}
			owner := reportOwner{ref.NetworkID, ref.DeviceID}
			key, concerned := keys[owner]
			if !concerned {
				continue
			}
			if store.verified[id] != key {
				var prior DeviceReport
				if err := decodeStoredReport(bucket.Get(ref.key(id)), &prior); err != nil {
					return err
				}
				if err := prior.Verify(key); err != nil {
					return errors.New("stored observation does not verify against the current immutable device key")
				}
				store.verified[id] = key
			}
			if ref.ReportSequence > high[owner] {
				high[owner] = ref.ReportSequence
			}
			position := reportPosition{owner, ref.ReportSequence}
			if positions[position] {
				if known[position] == nil {
					known[position] = map[string]bool{}
				}
				known[position][id] = true
			}
		}
		additions := []DeviceReport{}
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
			if err := bucket.Put(referenceOf(report).key(id), bodies[i]); err != nil {
				return err
			}
			additions = append(additions, report)
		}
		committed, err = base.withReports(additions)
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return err
	}
	if err := syncControlDirectory(filepath.Dir(store.path)); err != nil {
		return err
	}
	store.index.Store(committed)
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
		index, err := scanObservationIndex(ctx, tx, store.index.Load())
		if err != nil {
			return err
		}
		heads := map[reportOwner][]string{}
		for id, ref := range index.reports {
			owner := reportOwner{ref.NetworkID, ref.DeviceID}
			ids := heads[owner]
			if len(ids) == 0 || ref.ReportSequence > index.reports[ids[0]].ReportSequence {
				heads[owner] = []string{id}
			} else if ref.ReportSequence == index.reports[ids[0]].ReportSequence {
				heads[owner] = append(ids, id)
			}
		}
		for _, ids := range heads {
			if len(ids) != 1 {
				continue
			}
			id := ids[0]
			var report DeviceReport
			if err := decodeStoredReport(tx.Bucket(observationBucket).Get(index.reports[id].key(id)), &report); err != nil {
				return err
			}
			result = append(result, report)
		}
		store.index.Store(index)
		return nil
	})
	sort.Slice(result, func(i, j int) bool { return reportBefore(result[i], nil, result[j], nil) })
	return result, err
}
func verifyCurrentReport(report DeviceReport, projection Projection, releases ...ReleaseSet) error {
	if report.NetworkID != projection.NetworkID {
		return errors.New("device report belongs to another network")
	}
	authorization, found := identityFor(projection, report.DeviceID)
	if !found || report.Verify(authorization.DevicePublicKey) != nil {
		return errors.New("device report signature or authorization rejected")
	}
	view, err := ProjectDeviceView(projection, report.DeviceID, releases...)
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
