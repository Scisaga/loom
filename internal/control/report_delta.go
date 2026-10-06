package control

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"sort"
)

const reportRangeSize U64 = 1024
const reportBatchBytes = 16 << 20
const reportBatchCount = 1024
const reportScopeCount = 8

type reportScope struct {
	DeviceID      string `json:"device_id"`
	FirstSequence U64    `json:"first_sequence"`
}

func reportRangeStart(sequence U64) U64 {
	if sequence == 0 {
		return 0
	}
	return 1 + (sequence-1)/reportRangeSize*reportRangeSize
}
func validReportRange(device string, first U64) bool {
	return ValidateID(device) == nil && first != 0 && reportRangeStart(first) == first
}
func (v reportScope) Validate() error {
	if !validReportRange(v.DeviceID, v.FirstSequence) {
		return errors.New("invalid report range")
	}
	return nil
}
func scopeBefore(a, b reportScope) bool {
	return a.DeviceID < b.DeviceID || a.DeviceID == b.DeviceID && a.FirstSequence < b.FirstSequence
}

type reportRangeSummary struct {
	DeviceID      string `json:"device_id"`
	FirstSequence U64    `json:"first_sequence"`
	Digest        string `json:"digest"`
}

func (v reportRangeSummary) scope() reportScope { return reportScope{v.DeviceID, v.FirstSequence} }
func (v reportRangeSummary) Validate() error {
	if v.scope().Validate() != nil || ValidateDigest(v.Digest) != nil {
		return errors.New("invalid report range summary")
	}
	return nil
}

type reportRanges struct {
	Schema    int                  `json:"schema"`
	NetworkID string               `json:"network_id"`
	Ranges    []reportRangeSummary `json:"ranges"`
}

func (v reportRanges) Validate() error {
	if v.Schema != 3 || ValidateID(v.NetworkID) != nil || v.Ranges == nil {
		return errors.New("invalid report range index")
	}
	for i, item := range v.Ranges {
		if item.Validate() != nil || i > 0 && !scopeBefore(v.Ranges[i-1].scope(), item.scope()) {
			return errors.New("report ranges are not valid and uniquely sorted")
		}
	}
	return nil
}

type reportRangesRequest struct {
	Schema int           `json:"schema"`
	Ranges []reportScope `json:"ranges"`
}

func (v reportRangesRequest) Validate() error {
	if v.Schema != 3 || len(v.Ranges) == 0 || len(v.Ranges) > reportScopeCount {
		return errors.New("invalid report range request")
	}
	for i, s := range v.Ranges {
		if s.Validate() != nil || i > 0 && !scopeBefore(v.Ranges[i-1], s) {
			return errors.New("report scopes are not valid and uniquely sorted")
		}
	}
	return nil
}

type reportRangeIDs struct {
	DeviceID      string   `json:"device_id"`
	FirstSequence U64      `json:"first_sequence"`
	ReportIDs     []string `json:"report_ids"`
}

func (v reportRangeIDs) scope() reportScope { return reportScope{v.DeviceID, v.FirstSequence} }
func validateReportIDs(ids []string) error {
	if ids == nil {
		return errors.New("missing report IDs")
	}
	for i, id := range ids {
		if ValidateDigest(id) != nil || i > 0 && ids[i-1] >= id {
			return errors.New("report IDs are not uniquely sorted")
		}
	}
	return nil
}
func (v reportRangeIDs) Validate() error {
	if v.scope().Validate() != nil {
		return errors.New("invalid report ID scope")
	}
	return validateReportIDs(v.ReportIDs)
}

type reportIDs struct {
	Schema    int              `json:"schema"`
	NetworkID string           `json:"network_id"`
	Ranges    []reportRangeIDs `json:"ranges"`
}

func (v reportIDs) Validate() error {
	if v.Schema != 3 || ValidateID(v.NetworkID) != nil || len(v.Ranges) == 0 || len(v.Ranges) > reportScopeCount {
		return errors.New("invalid report ID index")
	}
	seen := map[string]bool{}
	for i, item := range v.Ranges {
		if item.Validate() != nil || i > 0 && !scopeBefore(v.Ranges[i-1].scope(), item.scope()) {
			return errors.New("report ID scopes are not valid and uniquely sorted")
		}
		for _, id := range item.ReportIDs {
			if seen[id] {
				return errors.New("one report ID occurs in different scopes")
			}
			seen[id] = true
		}
	}
	return nil
}

type reportBatchRequest struct {
	Schema    int      `json:"schema"`
	ReportIDs []string `json:"report_ids"`
}

func (v reportBatchRequest) Validate() error {
	if v.Schema != 3 || len(v.ReportIDs) == 0 || len(v.ReportIDs) > reportBatchCount {
		return errors.New("invalid report batch")
	}
	return validateReportIDs(v.ReportIDs)
}

type reportBatch struct {
	Schema  int            `json:"schema"`
	Reports []DeviceReport `json:"reports"`
}

func (v reportBatch) Validate() error {
	if v.Schema != 3 || len(v.Reports) == 0 || len(v.Reports) > reportBatchCount {
		return errors.New("invalid report batch")
	}
	prior := ""
	for _, report := range v.Reports {
		body, err := CanonicalEncode(report)
		if err != nil || len(body) > controlHTTPBodyLimit {
			return errors.New("invalid report batch member")
		}
		id := ReleaseDigest(body)
		if id <= prior {
			return errors.New("report batch is not in unique content ID order")
		}
		prior = id
	}
	return nil
}

type storedReportRange struct {
	network string
	scope   reportScope
}

// Immutable, disposable projections of the same original collection. No
// authorization or completion state is cached. Readers may retain a snapshot.
type reportIndex struct {
	canonical []byte
	reports   map[string]DeviceReport
	groups    map[storedReportRange][]string
	digests   map[storedReportRange]string
}

func emptyReportIndex() *reportIndex {
	return &reportIndex{reports: map[string]DeviceReport{}, groups: map[storedReportRange][]string{}, digests: map[storedReportRange]string{}}
}
func (index *reportIndex) withReports(reports []DeviceReport) (*reportIndex, error) {
	next := &reportIndex{reports: maps.Clone(index.reports), groups: maps.Clone(index.groups), digests: maps.Clone(index.digests)}
	changed := map[storedReportRange]bool{}
	for _, report := range reports {
		body, err := CanonicalEncode(report)
		if err != nil {
			return nil, err
		}
		id := ReleaseDigest(body)
		if _, found := next.reports[id]; found {
			continue
		}
		key := storedReportRange{report.NetworkID, reportScope{report.DeviceID, reportRangeStart(report.ReportSequence)}}
		if !changed[key] {
			next.groups[key] = append([]string{}, next.groups[key]...)
			changed[key] = true
		}
		next.groups[key] = append(next.groups[key], id)
		next.reports[id] = report
	}
	for key := range changed {
		sort.Strings(next.groups[key])
		body, err := CanonicalEncode(next.groups[key])
		if err != nil {
			return nil, err
		}
		next.digests[key] = ReleaseDigest(body)
	}
	return next, nil
}
func (store *ObservationStore) reportIndexSnapshot(ctx context.Context) (*reportIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case store.indexRead <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-store.indexRead }()
	cached := store.index.Load()
	// Writers replace the complete file atomically. An opened, validated file
	// is a committed snapshot even while another writer prepares its successor.
	var known []byte
	if cached != nil {
		known = cached.canonical
	}
	body, err := readProtectedControlFileMatching(store.path, known)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if current := store.index.Load(); current != nil && bytes.Equal(current.canonical, body) {
		return current, nil
	}
	if cached != nil && bytes.Equal(cached.canonical, body) {
		return cached, nil
	}
	var reports []DeviceReport
	if store.mu.TryRLock() {
		if bytes.Equal(store.canonical, body) {
			reports = store.state.Reports
		}
		store.mu.RUnlock()
	}
	if reports == nil {
		var state observationState
		if err := DecodeCanonical(body, &state, ContractDecodeLimits{MaxBytes: maxObservationStateBytes, MaxDepth: 128, MaxItems: len(body)}); err != nil {
			return nil, err
		}
		reports = state.Reports
	}
	built, err := emptyReportIndex().withReports(reports)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	built.canonical = body
	// A concurrent publication wins. This reader still returns its own complete
	// committed snapshot; the next request rechecks the actual file bytes.
	store.index.CompareAndSwap(cached, built)
	return built, nil
}
func (index *reportIndex) ranges(projection Projection) reportRanges {
	value := reportRanges{3, projection.NetworkID, []reportRangeSummary{}}
	allowed := map[string]bool{}
	for _, device := range projection.DeviceAuthorizations {
		allowed[device.ID] = true
	}
	for key, digest := range index.digests {
		if key.network == projection.NetworkID && allowed[key.scope.DeviceID] {
			value.Ranges = append(value.Ranges, reportRangeSummary{key.scope.DeviceID, key.scope.FirstSequence, digest})
		}
	}
	sort.Slice(value.Ranges, func(i, j int) bool { return scopeBefore(value.Ranges[i].scope(), value.Ranges[j].scope()) })
	return value
}
func (index *reportIndex) ids(projection Projection, scope reportScope) ([]string, error) {
	if _, ok := authorizationFor(projection, scope.DeviceID); !ok || scope.Validate() != nil {
		return nil, errors.New("report range is outside current device authorization")
	}
	ids := index.groups[storedReportRange{projection.NetworkID, scope}]
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}
func sortedReportIDs[T any](values map[string]T) []string {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
func (runtime *Runtime) peerReportJSON(ctx context.Context, member Member, method, path string, body []byte, result any, limit int) error {
	raw, err := runtime.peerBody(ctx, member, method, path, body)
	if err != nil {
		return err
	}
	return DecodeCanonical(raw, result, ContractDecodeLimits{MaxBytes: limit, MaxDepth: 128, MaxItems: len(raw)})
}
func (runtime *Runtime) reconcileReports(ctx context.Context, member Member) error {
	if runtime.Reports == nil {
		return errors.New("local report history unavailable")
	}
	projection := runtime.Authority.Snapshot()
	index, err := runtime.Reports.reportIndexSnapshot(ctx)
	if err != nil {
		return err
	}
	var remote reportRanges
	if err := runtime.peerReportJSON(ctx, member, http.MethodGet, "/internal/report-ranges", nil, &remote, maxControlInputBytes); err != nil {
		return err
	}
	if remote.NetworkID != projection.NetworkID {
		return errors.New("peer report index belongs to another network")
	}
	latest := map[string]U64{}
	for _, item := range remote.Ranges {
		latest[item.DeviceID] = item.FirstSequence
	}
	heads, older := []reportScope{}, []reportScope{}
	var failures error
	for _, item := range remote.Ranges {
		if _, ok := authorizationFor(projection, item.DeviceID); !ok {
			failures = errors.Join(failures, errors.New("peer report range is outside current authorization"))
			continue
		}
		if index.digests[storedReportRange{projection.NetworkID, item.scope()}] == item.Digest {
			continue
		}
		if item.FirstSequence == latest[item.DeviceID] {
			heads = append(heads, item.scope())
		} else {
			older = append(older, item.scope())
		}
	}
	pending := append(heads, older...)
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return errors.Join(failures, err)
		}
		selected := pending[:min(len(pending), reportScopeCount)]
		request := reportRangesRequest{3, append([]reportScope{}, selected...)}
		sort.Slice(request.Ranges, func(i, j int) bool { return scopeBefore(request.Ranges[i], request.Ranges[j]) })
		body, err := CanonicalEncode(request)
		if err != nil {
			return err
		}
		var ids reportIDs
		if err := runtime.peerReportJSON(ctx, member, http.MethodPost, "/internal/report-ids", body, &ids, maxControlInputBytes); err != nil {
			return errors.Join(failures, err)
		}
		if ids.NetworkID != projection.NetworkID || len(ids.Ranges) != len(request.Ranges) {
			return errors.New("peer report IDs differ from requested scope")
		}
		byScope := map[reportScope][]string{}
		for i, value := range ids.Ranges {
			if value.scope() != request.Ranges[i] {
				return errors.New("peer report IDs differ from requested scope")
			}
			byScope[value.scope()] = value.ReportIDs
		}
		wanted := map[string]reportScope{}
		for _, scope := range selected {
			for _, id := range byScope[scope] {
				if report, known := index.reports[id]; known {
					if report.NetworkID != projection.NetworkID || report.DeviceID != scope.DeviceID || reportRangeStart(report.ReportSequence) != scope.FirstSequence {
						return errors.New("known report differs from peer ID scope")
					}
					continue
				}
				if prior, duplicate := wanted[id]; duplicate && prior != scope {
					return errors.New("peer assigned one report ID to different scopes")
				}
				if len(wanted) == reportBatchCount {
					break
				}
				wanted[id] = scope
			}
		}
		if len(wanted) == 0 {
			pending = pending[len(selected):]
			continue
		}
		ordered := sortedReportIDs(wanted)
		body, err = CanonicalEncode(reportBatchRequest{3, ordered})
		if err != nil {
			return err
		}
		var batch reportBatch
		if err := runtime.peerReportJSON(ctx, member, http.MethodPost, "/internal/reports", body, &batch, reportBatchBytes); err != nil {
			return errors.Join(failures, err)
		}
		if len(batch.Reports) > len(ordered) {
			return errors.New("peer supplied unrequested reports")
		}
		for i, report := range batch.Reports {
			raw, err := CanonicalEncode(report)
			scope := wanted[ordered[i]]
			if err != nil || ReleaseDigest(raw) != ordered[i] || report.NetworkID != projection.NetworkID || report.DeviceID != scope.DeviceID || reportRangeStart(report.ReportSequence) != scope.FirstSequence {
				return errors.New("peer report differs from requested content or scope")
			}
		}
		if err := runtime.Reports.mergeReportHistory(ctx, batch.Reports, runtime.Authority.Snapshot()); err != nil && !errors.Is(err, ErrReportEquivocation) {
			return errors.Join(failures, err)
		}
		index, err = runtime.Reports.reportIndexSnapshot(ctx)
		if err != nil {
			return errors.Join(failures, err)
		}
	}
	return failures
}
