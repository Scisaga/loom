package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
)

const reportBatchBytes = 16 << 20
const reportBatchCount = 32

// Ranges and content IDs are disposable projections of the original reports.
// They never establish a sequence floor or certify current business health.
type reportRangeKey struct {
	device string
	first  U64
}

func reportRangeStart(sequence U64) U64 {
	if sequence == 0 {
		return 0
	}
	return 1 + (sequence-1)/64*64
}

func validReportRange(device string, first U64) bool {
	return ValidateID(device) == nil && first != 0 && reportRangeStart(first) == first
}

type reportRangeSummary struct {
	DeviceID      string `json:"device_id"`
	FirstSequence U64    `json:"first_sequence"`
	Digest        string `json:"digest"`
}

func (value reportRangeSummary) Validate() error {
	if !validReportRange(value.DeviceID, value.FirstSequence) || ValidateDigest(value.Digest) != nil {
		return errors.New("invalid report range summary")
	}
	return nil
}

type reportRanges struct {
	Schema    int                  `json:"schema"`
	NetworkID string               `json:"network_id"`
	Ranges    []reportRangeSummary `json:"ranges"`
}

func (value reportRanges) Validate() error {
	if value.Schema != 3 || ValidateID(value.NetworkID) != nil || value.Ranges == nil {
		return errors.New("invalid report range index")
	}
	for i, item := range value.Ranges {
		if err := item.Validate(); err != nil {
			return err
		}
		if i > 0 {
			prior := value.Ranges[i-1]
			if prior.DeviceID > item.DeviceID || prior.DeviceID == item.DeviceID && prior.FirstSequence >= item.FirstSequence {
				return errors.New("report ranges are not uniquely sorted")
			}
		}
	}
	return nil
}

type reportRangeIDs struct {
	Schema        int      `json:"schema"`
	NetworkID     string   `json:"network_id"`
	DeviceID      string   `json:"device_id"`
	FirstSequence U64      `json:"first_sequence"`
	ReportIDs     []string `json:"report_ids"`
}

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

func (value reportRangeIDs) Validate() error {
	if value.Schema != 3 || ValidateID(value.NetworkID) != nil || !validReportRange(value.DeviceID, value.FirstSequence) {
		return errors.New("invalid report ID scope")
	}
	return validateReportIDs(value.ReportIDs)
}

type reportBatchRequest struct {
	Schema        int      `json:"schema"`
	DeviceID      string   `json:"device_id"`
	FirstSequence U64      `json:"first_sequence"`
	ReportIDs     []string `json:"report_ids"`
}

func (value reportBatchRequest) Validate() error {
	if value.Schema != 3 || !validReportRange(value.DeviceID, value.FirstSequence) || len(value.ReportIDs) == 0 || len(value.ReportIDs) > reportBatchCount {
		return errors.New("invalid report batch scope")
	}
	return validateReportIDs(value.ReportIDs)
}

type reportBatch struct {
	Schema  int            `json:"schema"`
	Reports []DeviceReport `json:"reports"`
}

func (value reportBatch) Validate() error {
	if value.Schema != 3 || len(value.Reports) == 0 || len(value.Reports) > reportBatchCount {
		return errors.New("invalid report batch")
	}
	previous := ""
	for _, report := range value.Reports {
		body, err := CanonicalEncode(report)
		if err != nil || len(body) > controlHTTPBodyLimit {
			return errors.New("invalid report batch member")
		}
		id := ReleaseDigest(body)
		if id <= previous {
			return errors.New("report batch is not in unique content ID order")
		}
		previous = id
	}
	return nil
}

func (store *ObservationStore) withReportState(ctx context.Context, read func([]DeviceReport) error) error {
	lock, err := lockProtectedControlPath(ctx, filepath.Join(filepath.Dir(store.path), ".observations.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.reloadLocked(); err != nil {
		return err
	}
	return read(store.state.Reports)
}

func (store *ObservationStore) reportRanges(ctx context.Context, projection Projection) (reportRanges, error) {
	result := reportRanges{Schema: 3, NetworkID: projection.NetworkID, Ranges: []reportRangeSummary{}}
	allowed := map[string]bool{}
	for _, device := range projection.DeviceAuthorizations {
		allowed[device.ID] = true
	}
	groups := map[reportRangeKey][]string{}
	err := store.withReportState(ctx, func(reports []DeviceReport) error {
		for _, report := range reports {
			if report.NetworkID != projection.NetworkID || !allowed[report.DeviceID] {
				continue
			}
			body, err := CanonicalEncode(report)
			if err != nil {
				return err
			}
			key := reportRangeKey{report.DeviceID, reportRangeStart(report.ReportSequence)}
			groups[key] = append(groups[key], ReleaseDigest(body))
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	for key, ids := range groups {
		sort.Strings(ids)
		body, err := CanonicalEncode(ids)
		if err != nil {
			return result, err
		}
		result.Ranges = append(result.Ranges, reportRangeSummary{key.device, key.first, ReleaseDigest(body)})
	}
	sort.Slice(result.Ranges, func(i, j int) bool {
		left, right := result.Ranges[i], result.Ranges[j]
		return left.DeviceID < right.DeviceID || left.DeviceID == right.DeviceID && left.FirstSequence < right.FirstSequence
	})
	return result, nil
}

func (store *ObservationStore) reportRangeBodies(ctx context.Context, projection Projection, device string, first U64) (map[string][]byte, error) {
	if _, ok := authorizationFor(projection, device); !ok || !validReportRange(device, first) {
		return nil, errors.New("report range is outside current device authorization")
	}
	result := map[string][]byte{}
	err := store.withReportState(ctx, func(reports []DeviceReport) error {
		start := sort.Search(len(reports), func(i int) bool {
			r := reports[i]
			return r.NetworkID > projection.NetworkID || r.NetworkID == projection.NetworkID && (r.DeviceID > device || r.DeviceID == device && r.ReportSequence >= first)
		})
		for _, report := range reports[start:] {
			if report.NetworkID != projection.NetworkID || report.DeviceID != device || reportRangeStart(report.ReportSequence) != first {
				break
			}
			body, err := CanonicalEncode(report)
			if err != nil {
				return err
			}
			result[ReleaseDigest(body)] = body
		}
		return nil
	})
	return result, err
}

func sortedReportIDs(bodies map[string][]byte) []string {
	ids := make([]string, 0, len(bodies))
	for id := range bodies {
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
	local, err := runtime.Reports.reportRanges(ctx, projection)
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
	known := map[reportRangeKey]string{}
	for _, item := range local.Ranges {
		known[reportRangeKey{item.DeviceID, item.FirstSequence}] = item.Digest
	}
	var failures error
	for _, item := range remote.Ranges {
		if err := ctx.Err(); err != nil {
			return errors.Join(failures, err)
		}
		if known[reportRangeKey{item.DeviceID, item.FirstSequence}] == item.Digest {
			continue
		}
		// One damaged or unauthorized range must not prevent unrelated reports
		// from making progress. Every retry derives missing IDs from disk again.
		failures = errors.Join(failures, runtime.reconcileReportRange(ctx, member, item))
	}
	return failures
}

func (runtime *Runtime) reconcileReportRange(ctx context.Context, member Member, item reportRangeSummary) error {
	projection := runtime.Authority.Snapshot()
	local, err := runtime.Reports.reportRangeBodies(ctx, projection, item.DeviceID, item.FirstSequence)
	if err != nil {
		return err
	}
	query := url.Values{"device_id": {item.DeviceID}, "first_sequence": {fmt.Sprint(uint64(item.FirstSequence))}}
	var remote reportRangeIDs
	if err := runtime.peerReportJSON(ctx, member, http.MethodGet, "/internal/report-ids?"+query.Encode(), nil, &remote, maxControlInputBytes); err != nil {
		return err
	}
	if remote.NetworkID != projection.NetworkID || remote.DeviceID != item.DeviceID || remote.FirstSequence != item.FirstSequence {
		return errors.New("peer report IDs differ from requested scope")
	}
	missing := []string{}
	for _, id := range remote.ReportIDs {
		if _, found := local[id]; !found {
			missing = append(missing, id)
		}
	}
	for len(missing) > 0 {
		wanted := missing[:min(len(missing), reportBatchCount)]
		body, err := CanonicalEncode(reportBatchRequest{3, item.DeviceID, item.FirstSequence, wanted})
		if err != nil {
			return err
		}
		var batch reportBatch
		if err := runtime.peerReportJSON(ctx, member, http.MethodPost, "/internal/reports", body, &batch, reportBatchBytes); err != nil {
			return err
		}
		if len(batch.Reports) > len(wanted) {
			return errors.New("peer supplied unrequested reports")
		}
		for i, report := range batch.Reports {
			encoded, err := CanonicalEncode(report)
			if err != nil || ReleaseDigest(encoded) != wanted[i] || report.DeviceID != item.DeviceID || report.NetworkID != projection.NetworkID || reportRangeStart(report.ReportSequence) != item.FirstSequence {
				return errors.New("peer report differs from requested content or scope")
			}
		}
		if err := runtime.Reports.mergeReportHistory(ctx, batch.Reports, runtime.Authority.Snapshot()); err != nil && !errors.Is(err, ErrReportEquivocation) {
			return err
		}
		missing = missing[len(batch.Reports):]
	}
	return nil
}
