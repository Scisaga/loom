package control

import (
	"context"
	"errors"
	"net/http"
	"sort"
)

const reportLeafHeight = 4
const reportRangeSize U64 = 1 << reportLeafHeight
const reportBatchBytes = 16 << 20
const reportBatchCount = 1024
const reportScopeCount = 8

// A transport work bound, below the unchanged wire input limit. Keep room in
// one reconciliation round for verification and the durable report transaction.
const reportTransferCount = 64

// Once any original is missing, yield index work before a sparse history can
// consume the whole member attempt merely trying to fill the body batch.
const reportIndexRounds = 8

type reportScope struct {
	DeviceID      string `json:"device_id"`
	FirstSequence U64    `json:"first_sequence"`
	Height        int    `json:"height"`
}

func reportRangeStart(sequence U64) U64 {
	if sequence == 0 {
		return 0
	}
	return 1 + (sequence-1)/reportRangeSize*reportRangeSize
}
func validReportRange(device string, first U64) bool {
	return (reportScope{device, first, reportLeafHeight}).Validate() == nil
}
func (v reportScope) Validate() error {
	if ValidateID(v.DeviceID) != nil || v.FirstSequence == 0 || v.Height < reportLeafHeight || v.Height > 64 || v.Height == 64 && v.FirstSequence != 1 || v.Height < 64 && (uint64(v.FirstSequence)-1)&((uint64(1)<<v.Height)-1) != 0 {
		return errors.New("invalid report tree scope")
	}
	return nil
}
func scopeBefore(a, b reportScope) bool {
	return a.DeviceID < b.DeviceID || a.DeviceID == b.DeviceID && (a.FirstSequence < b.FirstSequence || a.FirstSequence == b.FirstSequence && a.Height > b.Height)
}
func (v reportScope) contains(other reportScope) bool {
	return v.DeviceID == other.DeviceID && other.Height < v.Height && (v.Height == 64 || (uint64(v.FirstSequence)-1)>>v.Height == (uint64(other.FirstSequence)-1)>>v.Height)
}
func (v reportScope) halves() [2]reportScope {
	h := v.Height - 1
	return [2]reportScope{{v.DeviceID, v.FirstSequence, h}, {v.DeviceID, v.FirstSequence + U64(1)<<h, h}}
}

type reportRangeSummary struct {
	DeviceID      string `json:"device_id"`
	FirstSequence U64    `json:"first_sequence"`
	Height        int    `json:"height"`
	Digest        string `json:"digest"`
}

func (v reportRangeSummary) scope() reportScope {
	return reportScope{v.DeviceID, v.FirstSequence, v.Height}
}
func (v reportRangeSummary) Validate() error {
	if v.scope().Validate() != nil || ValidateDigest(v.Digest) != nil {
		return errors.New("invalid report tree summary")
	}
	return nil
}
func summaryOf(scope reportScope, digest string) reportRangeSummary {
	return reportRangeSummary{scope.DeviceID, scope.FirstSequence, scope.Height, digest}
}

type reportRanges struct {
	Schema    int                  `json:"schema"`
	NetworkID string               `json:"network_id"`
	Ranges    []reportRangeSummary `json:"ranges"`
	Heads     []reportRangeSummary `json:"heads"`
}

func (v reportRanges) Validate() error {
	if v.Schema != 3 || ValidateID(v.NetworkID) != nil || v.Ranges == nil || v.Heads == nil || len(v.Ranges) != len(v.Heads) {
		return errors.New("invalid report tree roots")
	}
	for i, item := range v.Ranges {
		head := v.Heads[i]
		if item.Validate() != nil || item.Height != 64 || head.Validate() != nil || head.Height != reportLeafHeight || item.DeviceID != head.DeviceID || i > 0 && v.Ranges[i-1].DeviceID >= item.DeviceID {
			return errors.New("invalid or unsorted report tree roots/heads")
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
		return errors.New("invalid report tree request")
	}
	for i, s := range v.Ranges {
		if s.Validate() != nil || i > 0 && !scopeBefore(v.Ranges[i-1], s) {
			return errors.New("invalid or unsorted report tree scopes")
		}
	}
	return nil
}

type reportRangeIDs struct {
	DeviceID      string               `json:"device_id"`
	FirstSequence U64                  `json:"first_sequence"`
	Height        int                  `json:"height"`
	Children      []reportRangeSummary `json:"children"`
	ReportIDs     []string             `json:"report_ids"`
}

func (v reportRangeIDs) scope() reportScope {
	return reportScope{v.DeviceID, v.FirstSequence, v.Height}
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
func (v reportRangeIDs) Validate() error {
	scope := v.scope()
	if scope.Validate() != nil || v.Children == nil || v.ReportIDs == nil || len(v.Children) > 2 {
		return errors.New("invalid report tree expansion")
	}
	if scope.Height == reportLeafHeight && len(v.Children) != 0 || scope.Height > reportLeafHeight && len(v.ReportIDs) != 0 {
		return errors.New("report leaf and branch differ")
	}
	seen := map[string]bool{}
	for _, id := range v.ReportIDs {
		if ValidateDigest(id) != nil || seen[id] {
			return errors.New("invalid or repeated report IDs")
		}
		seen[id] = true
	}
	prior := -1
	for _, child := range v.Children {
		if child.Validate() != nil || !scope.contains(child.scope()) {
			return errors.New("report child is outside its parent")
		}
		half := int(((uint64(child.FirstSequence) - 1) >> (scope.Height - 1)) & 1)
		if half <= prior {
			return errors.New("report children are repeated or unsorted")
		}
		prior = half
	}
	return nil
}

type reportIDs struct {
	Schema    int              `json:"schema"`
	NetworkID string           `json:"network_id"`
	Ranges    []reportRangeIDs `json:"ranges"`
}

func (v reportIDs) Validate() error {
	if v.Schema != 3 || ValidateID(v.NetworkID) != nil || len(v.Ranges) == 0 || len(v.Ranges) > reportScopeCount {
		return errors.New("invalid report tree expansion response")
	}
	seen := map[string]bool{}
	for i, item := range v.Ranges {
		if item.Validate() != nil || i > 0 && !scopeBefore(v.Ranges[i-1].scope(), item.scope()) {
			return errors.New("invalid or unsorted report expansions")
		}
		for _, id := range item.ReportIDs {
			if seen[id] {
				return errors.New("one report ID occurs in different leaves")
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
	var remote reportRanges
	if err := runtime.peerReportJSON(ctx, member, http.MethodGet, "/internal/report-ranges", nil, &remote, maxControlInputBytes); err != nil {
		return err
	}
	if remote.NetworkID != projection.NetworkID {
		return errors.New("peer report tree belongs to another network")
	}
	// The latest leaves are independent of historical traversal, including a
	// newly opened leaf. All other pending nodes remain disposable local hints.
	pending := append(append([]reportRangeSummary{}, remote.Heads...), remote.Ranges...)
	queued := map[reportScope]bool{}
	visited := map[reportScope]bool{}
	for _, item := range pending {
		queued[item.scope()] = true
	}
	wanted := map[string]reportScope{}
	expansions := 0
	for len(pending) > 0 && len(wanted) < reportTransferCount && (len(wanted) == 0 || expansions < reportIndexRounds) {
		if err := ctx.Err(); err != nil {
			return err
		}
		selected := []reportScope{}
		for len(pending) > 0 && len(selected) < reportScopeCount {
			item := pending[0]
			pending = pending[1:]
			scope := item.scope()
			if visited[scope] {
				continue
			}
			visited[scope] = true
			if _, ok := identityFor(projection, scope.DeviceID); !ok {
				return errors.New("peer report tree is outside current authorization")
			}
			digest, err := runtime.Reports.reportTreeDigest(ctx, projection.NetworkID, scope)
			if err != nil {
				return err
			}
			if digest != item.Digest {
				selected = append(selected, scope)
			}
		}
		if len(selected) == 0 {
			continue
		}
		request := reportRangesRequest{3, append([]reportScope{}, selected...)}
		sort.Slice(request.Ranges, func(i, j int) bool { return scopeBefore(request.Ranges[i], request.Ranges[j]) })
		body, err := CanonicalEncode(request)
		if err != nil {
			return err
		}
		var ids reportIDs
		expansions++
		if err := runtime.peerReportJSON(ctx, member, http.MethodPost, "/internal/report-ids", body, &ids, maxControlInputBytes); err != nil {
			return err
		}
		if ids.NetworkID != projection.NetworkID || len(ids.Ranges) != len(request.Ranges) {
			return errors.New("peer report tree differs from requested scope")
		}
		byScope := map[reportScope][]string{}
		children := []reportRangeSummary{}
		allIDs := []string{}
		for i, value := range ids.Ranges {
			if value.scope() != request.Ranges[i] {
				return errors.New("peer report tree differs from requested scope")
			}
			byScope[value.scope()] = value.ReportIDs
			allIDs = append(allIDs, value.ReportIDs...)
			children = append(children, value.Children...)
		}
		known, err := runtime.Reports.knownReports(ctx, allIDs)
		if err != nil {
			return err
		}
		for position := 0; len(wanted) < reportTransferCount; position++ {
			remaining := false
			for _, scope := range selected {
				values := byScope[scope]
				if position >= len(values) {
					continue
				}
				remaining = true
				id := values[position]
				if report, ok := known[id]; ok {
					if report.NetworkID != projection.NetworkID || report.DeviceID != scope.DeviceID || reportRangeStart(report.ReportSequence) != scope.FirstSequence {
						return errors.New("known report differs from peer leaf")
					}
					continue
				}
				if prior, ok := wanted[id]; ok && prior != scope {
					return errors.New("peer assigned one report to different leaves")
				}
				wanted[id] = scope
				if len(wanted) == reportTransferCount {
					break
				}
			}
			if !remaining {
				break
			}
		}
		sort.Slice(children, func(i, j int) bool {
			a, b := children[i].scope(), children[j].scope()
			return a.DeviceID < b.DeviceID || a.DeviceID == b.DeviceID && (a.FirstSequence > b.FirstSequence || a.FirstSequence == b.FirstSequence && a.Height < b.Height)
		})
		next := []reportRangeSummary{}
		for _, child := range children {
			if !queued[child.scope()] {
				queued[child.scope()] = true
				next = append(next, child)
			}
		}
		pending = append(next, pending...)
	}
	if len(wanted) == 0 {
		return nil
	}
	ordered := sortedReportIDs(wanted)
	body, err := CanonicalEncode(reportBatchRequest{3, ordered})
	if err != nil {
		return err
	}
	var batch reportBatch
	if err := runtime.peerReportJSON(ctx, member, http.MethodPost, "/internal/reports", body, &batch, reportBatchBytes); err != nil {
		return err
	}
	if len(batch.Reports) > len(ordered) {
		return errors.New("peer supplied unrequested reports")
	}
	for i, report := range batch.Reports {
		raw, err := CanonicalEncode(report)
		scope := wanted[ordered[i]]
		if err != nil || ReleaseDigest(raw) != ordered[i] || report.NetworkID != projection.NetworkID || report.DeviceID != scope.DeviceID || reportRangeStart(report.ReportSequence) != scope.FirstSequence {
			return errors.New("peer report differs from requested content or leaf")
		}
	}
	if err := runtime.Reports.mergeReportHistory(ctx, batch.Reports, runtime.Authority.Snapshot()); err != nil && !errors.Is(err, ErrReportEquivocation) {
		return err
	}
	return nil
}
