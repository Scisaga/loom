package control

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"sort"
	"time"
)

// All traffic values are rebuilt from original signed counter samples.
type WebTrafficHistory struct {
	Schema  int                `json:"schema"`
	Scope   string             `json:"scope"`
	From    int64              `json:"from"`
	Until   int64              `json:"until"`
	Devices []WebDeviceTraffic `json:"devices"`
}
type WebDeviceTraffic struct {
	DeviceID string             `json:"device_id"`
	Buckets  []WebTrafficBucket `json:"buckets"`
	Recent   *WebTrafficDelta   `json:"recent,omitempty"`
}
type WebTrafficBucket struct {
	Hour  int64            `json:"hour"`
	Delta *WebTrafficDelta `json:"delta,omitempty"`
}
type WebTrafficDelta struct {
	RXBytes   U64   `json:"rx_bytes"`
	TXBytes   U64   `json:"tx_bytes"`
	CoveredMS int64 `json:"covered_ms"`
	Intervals int   `json:"intervals"`
	FirstAt   int64 `json:"first_at"`
	LastAt    int64 `json:"last_at"`
}

// Only a derived query scope, with no identity, persistence, or lifecycle.
type trafficLinkScope struct{ id, spec, endpoint, peer string }

func addTrafficDelta(target **WebTrafficDelta, rx, tx U64, from, until int64) error {
	if *target == nil {
		*target = &WebTrafficDelta{FirstAt: from, LastAt: until}
	}
	value := *target
	if math.MaxUint64-uint64(value.RXBytes) < uint64(rx) || math.MaxUint64-uint64(value.TXBytes) < uint64(tx) {
		return errors.New("traffic sum exceeds unsigned counter range")
	}
	value.RXBytes += rx
	value.TXBytes += tx
	value.CoveredMS += until - from
	value.Intervals++
	value.FirstAt = min(value.FirstAt, from)
	value.LastAt = max(value.LastAt, until)
	return nil
}
func counterDifference(older, newer DeviceReport, scope *trafficLinkScope) (U64, U64, bool) {
	a, b := older.WireGuardCounters, newer.WireGuardCounters
	if a == nil || b == nil || uint64(older.ReportSequence) == math.MaxUint64 || older.ReportSequence+1 != newer.ReportSequence || older.NetworkGeneration != newer.NetworkGeneration || a.Interface != b.Interface || a.Epoch != b.Epoch || a.ObservedAt >= b.ObservedAt || b.ObservedAt-a.ObservedAt > 3*time.Minute.Milliseconds() || len(a.Peers) != len(b.Peers) {
		return 0, 0, false
	}
	var rx, tx U64
	found := scope == nil
	for i, first := range a.Peers {
		last := b.Peers[i]
		if first.PublicKey != last.PublicKey || first.RXBytes > last.RXBytes || first.TXBytes > last.TXBytes {
			return 0, 0, false
		}
		if scope != nil {
			binding := WireGuardCounterLink{LinkID: scope.id, SpecDigest: scope.spec}
			if a.Interface != scope.endpoint || first.PublicKey != scope.peer || !slices.Contains(first.Links, binding) || !slices.Contains(last.Links, binding) {
				continue
			}
			found = true
		}
		dx, dt := last.RXBytes-first.RXBytes, last.TXBytes-first.TXBytes
		if math.MaxUint64-uint64(rx) < uint64(dx) || math.MaxUint64-uint64(tx) < uint64(dt) {
			return 0, 0, false
		}
		rx += dx
		tx += dt
	}
	return rx, tx, found
}
func (store *ObservationStore) deviceTrafficHistory(ctx context.Context, network string, identity projectedDeviceIdentity, scope *trafficLinkScope, now time.Time) (WebDeviceTraffic, error) {
	start := now.UTC().Truncate(time.Hour).Add(-23 * time.Hour).UnixMilli()
	until := now.UnixMilli()
	result := WebDeviceTraffic{DeviceID: identity.ID, Buckets: make([]WebTrafficBucket, 24)}
	for i := range result.Buckets {
		result.Buckets[i].Hour = start + int64(i)*time.Hour.Milliseconds()
	}
	var newer *DeviceReport
	var current *DeviceReport
	// Sequence order is authoritative for adjacency, not for wall-clock time.
	// A backwards clock cannot make an older interval overlap a counted one.
	ceiling := until
	err := store.walkDeviceHistorySnapshot(ctx, network, identity.ID, func(highest U64, ref reportReference, raw []byte) error {
		if raw == nil || ref.CounterAt == nil || *ref.CounterAt < start || *ref.CounterAt > until {
			newer = nil
			return nil
		}
		var report DeviceReport
		if err := decodeStoredReport(raw, &report); err != nil {
			return err
		}
		if report.Verify(identity.DevicePublicKey) != nil || report.WireGuardCounters == nil || report.ReportedAt > until {
			newer = nil
			return nil
		}
		at := report.WireGuardCounters.ObservedAt
		if report.ReportSequence == highest && report.ReportedAt <= until && report.ReportedAt >= until-3*time.Minute.Milliseconds() && at >= until-3*time.Minute.Milliseconds() && at <= report.ReportedAt+5*time.Second.Milliseconds() {
			current = &report
		}
		if at > ceiling {
			newer = nil
			return nil
		}
		if newer != nil {
			if at == newer.WireGuardCounters.ObservedAt {
				// Repeated identical samples are one measurement; contradictions have
				// no winner and cannot serve as the endpoint of an earlier interval.
				if report.NetworkGeneration == newer.NetworkGeneration && reflect.DeepEqual(report.WireGuardCounters, newer.WireGuardCounters) {
					newer = &report
				} else {
					newer = nil
				}
				return nil
			}
			rx, tx, valid := counterDifference(report, *newer, scope)
			if valid {
				end := newer.WireGuardCounters.ObservedAt
				index := (end - 1 - start) / time.Hour.Milliseconds()
				if index >= 0 && index < 24 && at >= result.Buckets[index].Hour {
					if err := addTrafficDelta(&result.Buckets[index].Delta, rx, tx, at, end); err != nil {
						return err
					}
				}
				if current != nil && newer.NetworkGeneration == current.NetworkGeneration && newer.WireGuardCounters.Interface == current.WireGuardCounters.Interface && newer.WireGuardCounters.Epoch == current.WireGuardCounters.Epoch && end <= current.WireGuardCounters.ObservedAt && at >= until-5*time.Minute.Milliseconds() {
					if err := addTrafficDelta(&result.Recent, rx, tx, at, end); err != nil {
						return err
					}
				}
				ceiling = at
			}
		}
		newer = &report
		return nil
	}, func(ref reportReference) bool {
		return ref.CounterAt != nil && *ref.CounterAt >= start && *ref.CounterAt <= until
	})
	if result.Recent != nil && result.Recent.LastAt < until-3*time.Minute.Milliseconds() {
		result.Recent = nil
	}
	return result, err
}
func (server *Server) trafficHistory(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 1 {
		http.Error(w, "one traffic scope is required", http.StatusBadRequest)
		return
	}
	kind, value := "", ""
	for key, values := range q {
		if len(values) != 1 || (key != "device" && key != "link" && key != "network") || ValidateID(values[0]) != nil {
			http.Error(w, "invalid traffic scope", http.StatusBadRequest)
			return
		}
		kind, value = key, values[0]
	}
	if server.Runtime == nil || server.Runtime.Authority == nil || server.Runtime.Reports == nil {
		http.Error(w, "original report history unavailable", http.StatusServiceUnavailable)
		return
	}
	p := server.Runtime.Authority.Snapshot()
	now := server.now()
	identities := []projectedDeviceIdentity{}
	scopes := map[string]*trafficLinkScope{}
	switch kind {
	case "device":
		id, found := identityFor(p, value)
		if found {
			identities = append(identities, id)
		}
	case "network":
		if value == p.NetworkID {
			for _, id := range p.DeviceAuthorizations {
				if actual, ok := identityFor(p, id.ID); ok {
					identities = append(identities, actual)
				}
			}
		}
	case "link":
		resources := map[string]TransportResource{}
		for _, v := range p.NetworkIntent.Resources {
			resources[v.ID] = v
		}
		for _, link := range projectWebLinks(p) {
			if link.ID != value || !link.Authorized {
				continue
			}
			for _, native := range p.NetworkIntent.Links {
				if native.ID != value {
					continue
				}
				for _, node := range []string{native.FromNodeID, native.ToNodeID} {
					id, found := identityFor(p, node)
					if !found {
						continue
					}
					local, remote := resources[native.FromResourceID], resources[native.ResourceID]
					if node == native.ToNodeID {
						local, remote = remote, local
					}
					if remote.Authentication.PublicKey == nil {
						continue
					}
					identities = append(identities, id)
					scopes[node] = &trafficLinkScope{id: native.ID, spec: link.SpecDigest, endpoint: ResourceInboundTag(local.ID), peer: *remote.Authentication.PublicKey}
				}
			}
		}
	}
	if len(identities) == 0 && !(kind == "network" && value == p.NetworkID) {
		http.Error(w, "traffic scope is not authorized", http.StatusNotFound)
		return
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].ID < identities[j].ID })
	result := WebTrafficHistory{Schema: 3, Scope: kind + ":" + value, From: now.UTC().Truncate(time.Hour).Add(-23 * time.Hour).UnixMilli(), Until: now.UnixMilli(), Devices: []WebDeviceTraffic{}}
	for _, id := range identities {
		history, err := server.Runtime.Reports.deviceTrafficHistory(r.Context(), p.NetworkID, id, scopes[id.ID], now)
		if err != nil {
			http.Error(w, "original traffic history unavailable", http.StatusServiceUnavailable)
			return
		}
		result.Devices = append(result.Devices, history)
	}
	writeJSON(w, http.StatusOK, result)
}
