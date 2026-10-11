package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Events are redacted projections of originals. Nothing in this response is
// persisted or accepted as a control operation.
type WebEvent struct {
	ID         string `json:"id"`
	At         string `json:"at"`
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Subject    string `json:"subject"`
	ObjectKind string `json:"object_kind"`
	Detail     string `json:"detail"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
}
type WebEventQuery struct {
	From         string `json:"from"`
	Until        string `json:"until"`
	Search       string `json:"q"`
	Kind         string `json:"kind"`
	Source       string `json:"source"`
	Subject      string `json:"object"`
	Interval     int    `json:"interval_minutes"`
	ResultDigest string `json:"result_digest,omitempty"`
}
type WebEventBucket struct {
	From    string         `json:"from"`
	Until   string         `json:"until"`
	Covered bool           `json:"covered"`
	Counts  map[string]int `json:"counts"`
	Total   int            `json:"total"`
}
type WebEvents struct {
	Schema       int              `json:"schema"`
	Query        WebEventQuery    `json:"query"`
	CoverageFrom string           `json:"coverage_from,omitempty"`
	Total        int              `json:"total"`
	Buckets      []WebEventBucket `json:"buckets"`
	Events       []WebEvent       `json:"events"`
	NextCursor   string           `json:"next_cursor,omitempty"`
}
type eventCursor struct {
	Query string `json:"query"`
	At    string `json:"at"`
	ID    string `json:"id"`
}

var errEventChanged = errors.New("event originals changed; refresh the query")

var errEventCursor = errors.New("cursor differs from fixed event query")

var eventKinds = []string{"authority", "membership", "enrollment", "revocation", "conflict", "runtime"}

func eventUTC(value string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || at.UnixNano() <= 0 || !time.Unix(0, at.UnixNano()).Equal(at) || at.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("canonical UTC time required")
	}
	return at, nil
}
func parseEventQuery(values url.Values, now time.Time) (WebEventQuery, string, bool, error) {
	q := WebEventQuery{Until: now.UTC().Format(time.RFC3339Nano), Interval: 10}
	for key, value := range values {
		if len(value) != 1 {
			return q, "", false, errors.New("duplicate event query field")
		}
		switch key {
		case "from", "until", "q", "kind", "source", "object", "interval", "cursor", "format", "result":
		default:
			return q, "", false, errors.New("unknown event query field")
		}
	}
	if value := values.Get("until"); value != "" {
		q.Until = value
	}
	until, err := eventUTC(q.Until)
	if err != nil || until.After(now) {
		return q, "", false, errors.New("invalid event cutoff")
	}
	q.From = until.Add(-72 * time.Hour).UTC().Format(time.RFC3339Nano)
	if value := values.Get("from"); value != "" {
		q.From = value
	}
	from, err := eventUTC(q.From)
	if err != nil || !from.Before(until) || until.Sub(from) > 30*24*time.Hour {
		return q, "", false, errors.New("event window must be positive and at most 30 days")
	}
	q.ResultDigest = values.Get("result")
	if q.ResultDigest != "" && ValidateDigest(q.ResultDigest) != nil {
		return q, "", false, errors.New("invalid event result digest")
	}
	q.Search, q.Kind, q.Source, q.Subject = values.Get("q"), values.Get("kind"), values.Get("source"), values.Get("object")
	if len(q.Search) > 256 || strings.TrimSpace(q.Search) != q.Search || q.Kind != "" && !containsString(eventKinds, q.Kind) || q.Source != "" && ValidateID(q.Source) != nil || q.Subject != "" && ValidateID(q.Subject) != nil {
		return q, "", false, errors.New("invalid event filter")
	}
	if value := values.Get("interval"); value != "" {
		q.Interval, err = strconv.Atoi(value)
		if err != nil || strconv.Itoa(q.Interval) != value || q.Interval != 10 && q.Interval != 30 && q.Interval != 60 {
			return q, "", false, errors.New("invalid event bucket interval")
		}
	}
	format := values.Get("format")
	if format != "" && format != "csv" || format == "csv" && values.Get("cursor") != "" {
		return q, "", false, errors.New("invalid event export")
	}
	if values.Get("cursor") != "" && (values.Get("from") == "" || values.Get("until") == "") {
		return q, "", false, errors.New("continuation requires its original window")
	}
	return q, values.Get("cursor"), format == "csv", nil
}
func eventQueryDigest(q WebEventQuery) string {
	raw, _ := CanonicalEncode(q)
	return ReleaseDigest(raw)
}

func (server *Server) events(w http.ResponseWriter, r *http.Request) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid event query", http.StatusBadRequest)
		return
	}
	q, cursor, export, err := parseEventQuery(values, server.now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if server.Runtime == nil || server.Runtime.Authority == nil || server.Runtime.Reports == nil {
		http.Error(w, "original event sources unavailable", http.StatusServiceUnavailable)
		return
	}
	result, all, err := server.eventWindow(r.Context(), q, cursor)
	if err != nil {
		if errors.Is(err, errEventChanged) {
			http.Error(w, errEventChanged.Error(), http.StatusConflict)
		} else if errors.Is(err, errEventCursor) {
			http.Error(w, errEventCursor.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, "original event query unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	if !export {
		writeJSON(w, http.StatusOK, result)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="loom-events.csv"`)
	w.Header().Set("X-Loom-Events-Total", strconv.Itoa(result.Total))
	w.Header().Set("X-Loom-Events-Coverage-From", result.CoverageFrom)
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"id", "received_at", "type", "source", "object", "from", "to", "detail"})
	for _, event := range all {
		if r.Context().Err() != nil {
			return
		}
		// Spreadsheet readers must not interpret public object text as formulas.
		row := []string{event.ID, event.At, event.Kind, event.Source, event.Subject, event.From, event.To, event.Detail}
		for i, text := range row {
			if len(strings.TrimSpace(text)) > 0 && strings.ContainsRune("=+-@", rune(strings.TrimSpace(text)[0])) {
				row[i] = "'" + text
			}
		}
		if err := writer.Write(row); err != nil {
			return
		}
	}
	writer.Flush()
}

func (server *Server) eventWindow(ctx context.Context, q WebEventQuery, cursor string) (WebEvents, []WebEvent, error) {
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		var position eventCursor
		if err != nil || len(raw) > 1024 || base64.RawURLEncoding.EncodeToString(raw) != cursor || DecodeCanonical(raw, &position, ContractDecodeLimits{MaxBytes: 1024, MaxDepth: 4, MaxItems: 16}) != nil || position.Query != eventQueryDigest(q) {
			return WebEvents{}, nil, errEventCursor
		}
	}
	from, _ := eventUTC(q.From)
	until, _ := eventUTC(q.Until)
	events, keys, since, err := server.Runtime.Authority.authorityEvents(ctx, from, until)
	if err != nil {
		return WebEvents{}, nil, err
	}
	runtime, reportSince, err := server.Runtime.Reports.runtimeEvents(ctx, server.Config.NetworkID, keys, from, until)
	if err != nil {
		return WebEvents{}, nil, err
	}
	if since.IsZero() || reportSince.IsZero() {
		since = time.Time{}
	} else if reportSince.After(since) {
		since = reportSince
	}
	events = append(events, runtime...)
	filtered := []WebEvent{}
	for _, event := range events {
		if q.Kind != "" && q.Kind != event.Kind || q.Source != "" && q.Source != event.Source || q.Subject != "" && q.Subject != event.Subject {
			continue
		}
		if q.Search != "" && !strings.Contains(strings.ToLower(event.Kind+" "+event.Source+" "+event.Subject+" "+event.Detail+" "+event.From+" "+event.To), strings.ToLower(q.Search)) {
			continue
		}
		filtered = append(filtered, event)
	}
	sort.Slice(filtered, func(i, j int) bool {
		a, _ := eventUTC(filtered[i].At)
		b, _ := eventUTC(filtered[j].At)
		return a.After(b) || a.Equal(b) && filtered[i].ID < filtered[j].ID
	})
	rawResult, err := CanonicalEncode(struct {
		Events   []WebEvent `json:"events"`
		Coverage string     `json:"coverage"`
	}{filtered, since.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return WebEvents{}, nil, err
	}
	resultDigest := ReleaseDigest(rawResult)
	if q.ResultDigest != "" && q.ResultDigest != resultDigest {
		return WebEvents{}, nil, errEventChanged
	}
	q.ResultDigest = resultDigest
	result := WebEvents{Schema: 3, Query: q, Total: len(filtered), Events: []WebEvent{}, Buckets: []WebEventBucket{}}
	if !since.IsZero() {
		result.CoverageFrom = since.Format(time.RFC3339Nano)
	}
	width := time.Duration(q.Interval) * time.Minute
	for at := from; at.Before(until); at = at.Add(width) {
		end := at.Add(width)
		if end.After(until) {
			end = until
		}
		result.Buckets = append(result.Buckets, WebEventBucket{From: at.Format(time.RFC3339Nano), Until: end.Format(time.RFC3339Nano), Covered: !since.IsZero() && !at.Before(since), Counts: map[string]int{}})
	}
	for _, event := range filtered {
		at, _ := eventUTC(event.At)
		index := int(at.Sub(from) / width)
		result.Buckets[index].Counts[event.Kind]++
		result.Buckets[index].Total++
	}
	offset := 0
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		var position eventCursor
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != cursor || DecodeCanonical(raw, &position, ContractDecodeLimits{MaxBytes: 1024, MaxDepth: 4, MaxItems: 16}) != nil || position.Query != eventQueryDigest(q) {
			return result, nil, errEventCursor
		}
		offset = -1
		for i, event := range filtered {
			if event.ID == position.ID && event.At == position.At {
				offset = i + 1
				break
			}
		}
		if offset < 0 {
			return result, nil, errEventCursor
		}
	}
	end := min(offset+100, len(filtered))
	result.Events = filtered[offset:end]
	if end < len(filtered) {
		event := filtered[end-1]
		raw, _ := CanonicalEncode(eventCursor{eventQueryDigest(q), event.At, event.ID})
		result.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return result, filtered, ctx.Err()
}

func (a *Authority) authorityEvents(ctx context.Context, from, until time.Time) ([]WebEvent, map[string][]string, time.Time, error) {
	a.mu.RLock()
	if a.blocked != nil {
		blocked := a.blocked
		a.mu.RUnlock()
		return nil, nil, time.Time{}, blocked
	}
	// Originals are immutable private values. Capture only their references;
	// file reads and history computation do not hold up authority submissions.
	genesisMaterial := a.genesis
	materials := append([]Material{}, a.materials...)
	certificates := append([]ControlCertificate{}, a.certificates...)
	invites := append([]Invite{}, a.projection.Invites...)
	a.mu.RUnlock()
	since, err := fileReception(a.root, coverageAttribute)
	if err != nil {
		return nil, nil, since, err
	}
	keys := map[string][]string{}
	remember := func(id, key string) {
		if !containsString(keys[id], key) {
			keys[id] = append(keys[id], key)
		}
	}
	genesis := genesisMaterial.Payload.(Genesis)
	for _, member := range genesis.ControlConfig.Members {
		remember(member.NodeID, member.PublicKey)
	}
	for _, cert := range certificates {
		for _, member := range cert.Config.Members {
			remember(member.NodeID, member.PublicKey)
		}
	}
	arrivals := map[string]time.Time{}
	inWindow := []Material{}
	for _, material := range materials {
		id, err := MaterialID(material)
		if err != nil {
			return nil, nil, since, err
		}
		path, _ := a.materialPath(id)
		at, err := fileReception(path, receptionAttribute)
		if err != nil {
			return nil, nil, since, err
		}
		arrivals[id] = at
		if at.IsZero() || at.Before(until) {
			inWindow = append(inWindow, material)
		}
	}
	materials = inWindow
	graph, err := newMaterialGraph(genesisMaterial, certificates, materials)
	if err != nil {
		return nil, nil, since, err
	}
	valid := map[string]bool{}
	for _, material := range materials {
		id, _ := MaterialID(material)
		valid[id] = graph.validate(id) == nil
	}
	all := append([]Material{genesisMaterial}, materials...)
	events := []WebEvent{}
	for _, material := range all {
		if err := ctx.Err(); err != nil {
			return nil, nil, since, err
		}
		if binding, ok := material.Payload.(EnrollmentBind); ok {
			for _, invite := range invites {
				if invite.ID == binding.TransactionID {
					remember(invite.DeviceID, binding.DevicePublicKey)
				}
			}
		}
		if device, ok := material.Payload.(DeviceAuthorization); ok {
			remember(device.ID, device.DevicePublicKey)
		}
		id, err := MaterialID(material)
		if err != nil {
			return nil, nil, since, err
		}
		raw, err := a.Material(id)
		if err != nil {
			return nil, nil, since, err
		}
		expected, _, err := EncodeMaterial(material)
		if err != nil || !bytes.Equal(raw, expected) {
			return nil, nil, since, errors.New("material original changed")
		}
		path, _ := a.materialPath(id)
		at, err := fileReception(path, receptionAttribute)
		if err != nil {
			return nil, nil, since, err
		}
		if at.IsZero() {
			info, err := os.Lstat(path)
			if err != nil {
				return nil, nil, since, err
			}
			// mtime only detects a suspicious gap; it never supplies event time.
			if !since.IsZero() && !info.ModTime().Before(since) {
				since = time.Time{}
			}
			continue
		}
		if at.Before(from) || !at.Before(until) {
			continue
		}
		kind := "authority"
		if strings.HasPrefix(material.Operation, "invite.") || material.Operation == "device.bind" {
			kind = "enrollment"
		}
		if strings.HasSuffix(material.Operation, ".delete") || material.Operation == "device.revoke" {
			kind = "revocation"
		}
		detail := material.TargetKind + ": " + material.Operation
		if material.Operation != "genesis" {
			prior := []string{}
			for otherID, when := range arrivals {
				if otherID == id || !when.IsZero() && (!when.Before(at) && !(when.Equal(at) && otherID < id)) {
					continue
				}
				other := graph.facts[otherID]
				if other.IssuerKeyID == material.IssuerKeyID && other.Sequence == material.Sequence {
					kind = "conflict"
					detail += "; signed sequence conflict with " + otherID
				}
				if valid[otherID] && other.TargetKind == material.TargetKind && other.TargetID == material.TargetID {
					prior = append(prior, otherID)
				}
			}
			if valid[id] {
				prior = append(prior, id)
				sort.Strings(prior)
				maxima := []string{}
				withdrawn := false
				for _, fact := range prior {
					superseded := false
					for _, other := range prior {
						if fact != other && graph.ancestors[other][fact] {
							superseded = true
							break
						}
					}
					if !superseded {
						maxima = append(maxima, fact)
						withdrawn = withdrawn || isWithdrawal(graph.facts[fact].Operation)
					}
				}
				if len(maxima) > 1 && !withdrawn {
					kind = "conflict"
					detail += "; concurrent facts: " + strings.Join(maxima, ", ")
				}

			} else if kind != "conflict" {
				detail += "; stored signed original, effectiveness not asserted"
			}
		}
		subject := material.TargetID
		if subject == "" {
			subject = material.NetworkID
		}
		events = append(events, WebEvent{ID: id, At: at.Format(time.RFC3339Nano), Kind: kind, Source: material.IssuerControlID, Subject: subject, ObjectKind: material.TargetKind, Detail: detail})
	}
	for _, cert := range certificates {
		raw, err := CanonicalEncode(cert)
		if err != nil {
			return nil, nil, since, err
		}
		id := ReleaseDigest(raw)
		path := filepath.Join(a.root, "control-certificates", strings.TrimPrefix(id, "sha256:")+".json")
		original, err := readProtectedControlFile(path)
		if err != nil || !bytes.Equal(raw, original) {
			return nil, nil, since, errors.New("member original changed")
		}
		at, err := fileReception(path, receptionAttribute)
		if err != nil {
			return nil, nil, since, err
		}
		if at.IsZero() || at.Before(from) || !at.Before(until) {
			continue
		}
		subject := cert.Config.TargetNodeID
		if subject == "" {
			subject = cert.Config.NetworkID
		}
		events = append(events, WebEvent{ID: id, At: at.Format(time.RFC3339Nano), Kind: "membership", Source: cert.Round.ProposerControlID, Subject: subject, ObjectKind: "control_config", Detail: "Control membership: " + cert.Config.Operation})
	}
	return events, keys, since, nil
}

func (store *ObservationStore) runtimeEvents(ctx context.Context, network string, keys map[string][]string, from, until time.Time) ([]WebEvent, time.Time, error) {
	type original struct {
		key      []byte
		at       time.Time
		previous []byte
	}
	locations := []original{}
	var since time.Time
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		metadata := tx.Bucket(reportReceptionBucket)
		if metadata == nil {
			return errors.New("reception metadata missing")
		}
		var err error
		since, err = receptionTime(metadata.Get(receptionSinceKey))
		if err != nil {
			return err
		}
		prefix := receptionIndexPrefix(network)
		cursor := tx.Bucket(reportIndexBucket).Cursor()
		start := binary.BigEndian.AppendUint64(bytes.Clone(prefix), uint64(from.UnixNano()))
		for index, _ := cursor.Seek(start); index != nil && bytes.HasPrefix(index, prefix); index, _ = cursor.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(index) < len(prefix)+8 {
				return errors.New("invalid reception location")
			}
			at, err := receptionTime(index[len(prefix) : len(prefix)+8])
			if err != nil {
				return err
			}
			if !at.Before(until) {
				break
			}
			key := bytes.Clone(index[len(prefix)+8:])
			if !bytes.Equal(metadata.Get(key), index[len(prefix):len(prefix)+8]) {
				return errors.New("reception location differs from original annotation")
			}
			_, ref, err := locateReportKey(key)
			if err != nil || ref.NetworkID != network {
				return errors.New("invalid reception original")
			}
			position := key[:len(key)-32]
			positionCursor := tx.Bucket(observationBucket).Cursor()
			forks := 0
			for k, _ := positionCursor.Seek(position); k != nil && bytes.HasPrefix(k, position); k, _ = positionCursor.Next() {
				received := metadata.Get(k)
				if len(received) == 0 {
					forks++
				} else if when, err := receptionTime(received); err != nil {
					return err
				} else if when.Before(until) {
					forks++
				}
			}
			if forks != 1 {
				continue
			}
			var previous []byte
			if ref.ReportSequence > 1 {
				priorPosition := binary.BigEndian.AppendUint64(reportOwnerPrefix(reportOwner{network, ref.DeviceID}), uint64(ref.ReportSequence-1))
				count := 0
				for k, _ := positionCursor.Seek(priorPosition); k != nil && bytes.HasPrefix(k, priorPosition); k, _ = positionCursor.Next() {
					received := metadata.Get(k)
					if len(received) != 0 {
						when, err := receptionTime(received)
						if err != nil {
							return err
						}
						if !when.Before(until) {
							continue
						}
					}
					count++
					previous = bytes.Clone(k)
				}
				if count != 1 {
					previous = nil
				}
			}
			if tx.Bucket(observationBucket).Get(key) == nil {
				return errors.New("received original is absent")
			}
			if previous == nil && ref.ReportSequence > 1 {
				// A gap or fork does not establish a change or a new baseline.
				owner := reportOwnerPrefix(reportOwner{network, ref.DeviceID})
				first, _ := tx.Bucket(observationBucket).Cursor().Seek(owner)
				if first == nil || !bytes.HasPrefix(first, owner) {
					return errors.New("report owner disappeared")
				}
				_, earliest, err := locateReportKey(first)
				if err != nil {
					return err
				}
				if earliest.ReportSequence != ref.ReportSequence {
					continue
				}
			}
			locations = append(locations, original{key, at, previous})
		}
		return nil
	})
	if err != nil {
		return nil, since, err
	}
	result := []WebEvent{}
	for _, location := range locations {
		var raw, prior []byte
		err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
			raw = bytes.Clone(tx.Bucket(observationBucket).Get(location.key))
			if raw == nil {
				return errors.New("received original disappeared")
			}
			if location.previous != nil {
				prior = bytes.Clone(tx.Bucket(observationBucket).Get(location.previous))
				if prior == nil {
					return errors.New("previous original disappeared")
				}
			}
			return ctx.Err()
		})
		if err != nil {
			return nil, since, err
		}
		report, err := store.decodedReport(raw)
		if err != nil {
			return nil, since, err
		}
		id := ReleaseDigest(raw)
		if !bytes.Equal(referenceOf(report).key(id), location.key) || verifyEventReport(store, raw, keys[report.DeviceID]) != nil {
			return nil, since, errors.New("received report does not verify")
		}
		previousState := ""
		detail := "Authenticated runtime baseline: " + report.Runtime.State + "."
		if prior != nil {
			var previous DeviceReport
			if decodeStoredReport(prior, &previous) != nil || verifyEventReport(store, prior, keys[report.DeviceID]) != nil || !bytes.Equal(referenceOf(previous).key(ReleaseDigest(prior)), location.previous) {
				return nil, since, errors.New("previous runtime report does not verify")
			}
			if previous.Runtime.State == report.Runtime.State && previous.Runtime.AppliedViewDigest == report.Runtime.AppliedViewDigest && previous.Runtime.ErrorCode == report.Runtime.ErrorCode {
				continue
			}
			previousState = previous.Runtime.State
			detail = fmt.Sprintf("Authenticated runtime change: %s → %s.", previous.Runtime.State, report.Runtime.State)
		}
		result = append(result, WebEvent{ID: id, At: location.at.Format(time.RFC3339Nano), Kind: "runtime", Source: report.DeviceID, Subject: report.DeviceID, ObjectKind: "device", From: previousState, To: report.Runtime.State, Detail: detail})
	}
	return result, since, ctx.Err()
}

func verifyEventReport(store *ObservationStore, raw []byte, keys []string) error {
	for _, key := range keys {
		if _, err := store.verifiedReport(raw, key); err == nil {
			return nil
		}
	}
	return errors.New("no historical identity verifies report")
}
