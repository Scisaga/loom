package control

import (
	"bytes"
	"errors"
	"net/netip"
	"sort"
	"time"
)

const (
	wgPortRecoveryWindow        = 2 * time.Minute
	wgPortRecoveryCooldown      = 3 * time.Minute
	wgPortRecoveryAttemptWindow = time.Hour
	wgPortRecoverySampleGap     = 45 * time.Second
)

// These inputs are disposable projections of existing report originals,
// resource facts and their protected local first-reception annotations. They
// are not another persisted recovery state or a source of authorization.
type WGPortRecoveryReports struct {
	DeviceID string
	Highest  U64
	Reports  []DeviceReport
	// Forked identifies an ambiguous position inside the requested time window;
	// Highest can instead lie after a historical window being reconstructed.
	Forked bool
}

type WGPortRecoveryChange struct {
	MaterialID string
	ReceivedAt time.Time
	Automatic  bool
}

type WGPortRecoveryResource struct {
	ResourceID string
	// Ports preserves the order of executable, already supplied ingress
	// mappings. The caller excludes other services and occupied listeners.
	Ports   []int
	Changes []WGPortRecoveryChange
}

type WGPortRecoverySuggestion struct {
	ResourceID   string
	FromPort     int
	ToPort       int
	LinkID       string
	SourceNodeID string
	FailureSince int64
}

type wgPortRecoveryReport struct {
	report DeviceReport
	valid  bool
}

// WGPortRecovery only proposes a new port for an existing authenticated WG
// resource. The caller must recheck current facts, listener ownership and the
// supplied mapping before submitting an ordinary resource.put. No time, random
// value, external state or network operation is read here.
func WGPortRecovery(projection Projection, histories []WGPortRecoveryReports, inputs []WGPortRecoveryResource, now time.Time, releases ...ReleaseSet) ([]WGPortRecoverySuggestion, error) {
	if now.IsZero() || now.UnixMilli() <= 0 {
		return nil, errors.New("WG port recovery requires an explicit current time")
	}
	links, err := DerivedNetworkLinks(projection)
	if err != nil {
		return nil, err
	}
	linkSpecs, err := projectionLinkSpecs(projection)
	if err != nil {
		return nil, err
	}
	views := map[string]DeviceView{}
	viewFor := func(id string) (DeviceView, error) {
		if value, ok := views[id]; ok {
			return value, nil
		}
		value, err := ProjectDeviceView(projection, id, releases...)
		if err == nil {
			views[id] = value
		}
		return value, err
	}
	reports := map[string][]wgPortRecoveryReport{}
	latest := map[string]DeviceReport{}
	for _, history := range histories {
		if ValidateID(history.DeviceID) != nil {
			return nil, errors.New("WG port recovery report scope is invalid")
		}
		if _, exists := reports[history.DeviceID]; exists {
			return nil, errors.New("WG port recovery report scope is duplicated")
		}
		values, err := wgPortRecoveryReportHistory(projection, history, now, viewFor)
		if err != nil {
			return nil, err
		}
		reports[history.DeviceID] = values
		if len(values) != 0 {
			value := values[len(values)-1]
			_, until := webReportTime(value.report, now)
			if value.valid && value.report.ReportSequence == history.Highest && until != 0 {
				latest[history.DeviceID] = value.report
			}
		}
	}
	resources := map[string]TransportResource{}
	for _, resource := range projection.NetworkIntent.Resources {
		resources[resource.ID] = resource
	}
	ordered := append([]WGPortRecoveryResource{}, inputs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ResourceID < ordered[j].ResourceID })
	result := []WGPortRecoverySuggestion{}
	for index, input := range ordered {
		if ValidateID(input.ResourceID) != nil || index > 0 && ordered[index-1].ResourceID == input.ResourceID {
			return nil, errors.New("WG port recovery resource scope is invalid or duplicated")
		}
		resource, exists := resources[input.ResourceID]
		if !exists || resource.Kind != "wireguard" {
			return nil, errors.New("WG port recovery requires an existing WireGuard resource")
		}
		port := 0
		for _, candidate := range input.Ports {
			if candidate < 1 || candidate > 65535 {
				return nil, errors.New("WG port recovery candidate port is invalid")
			}
			if port == 0 && candidate != resource.DialPort {
				port = candidate
			}
		}
		if port == 0 || !wgPortRecoveryChangeAllowed(projection, input, now) {
			continue
		}
		receiver, exists := latest[resource.OwnerNodeID]
		if !exists || !wgPortRecoveryListener(receiver, resource) {
			continue
		}
		for _, link := range links {
			if link.ResourceID != resource.ID {
				continue
			}
			source, exists := latest[link.FromNodeID]
			if !exists {
				continue
			}
			spec := linkSpecs[link.ID]
			if spec == "" {
				continue
			}
			if since := wgPortRecoveryFailure(reports[link.FromNodeID], source, link, spec, now); since != 0 {
				result = append(result, WGPortRecoverySuggestion{ResourceID: resource.ID, FromPort: resource.DialPort, ToPort: port, LinkID: link.ID, SourceNodeID: link.FromNodeID, FailureSince: since})
				break
			}
		}
	}
	return result, nil
}

func wgPortRecoveryReportHistory(projection Projection, history WGPortRecoveryReports, now time.Time, viewFor func(string) (DeviceView, error)) ([]wgPortRecoveryReport, error) {
	positions := map[U64][]DeviceReport{}
	for _, report := range history.Reports {
		if report.ReportSequence == 0 || report.ReportSequence > history.Highest {
			return nil, errors.New("WG port recovery report exceeds its pinned highest position")
		}
		positions[report.ReportSequence] = append(positions[report.ReportSequence], report)
	}
	sequences := make([]U64, 0, len(positions))
	for sequence := range positions {
		sequences = append(sequences, sequence)
	}
	sort.Slice(sequences, func(i, j int) bool { return sequences[i] < sequences[j] })
	result := make([]wgPortRecoveryReport, 0, len(sequences))
	for _, sequence := range sequences {
		values := positions[sequence]
		report := values[0]
		valid := true
		original, err := CanonicalEncode(report)
		if err != nil {
			valid = false
		}
		for _, other := range values[1:] {
			body, err := CanonicalEncode(other)
			if err != nil || !bytes.Equal(body, original) {
				valid = false
			}
		}
		valid = valid && report.DeviceID == history.DeviceID && report.ReportedAt <= now.Add(webClockTolerance).UnixMilli() &&
			verifyCurrentReportUsing(report, projection, viewFor) == nil && report.Runtime.State == "running" && report.Runtime.AppliedViewDigest == report.ViewDigest
		result = append(result, wgPortRecoveryReport{report: report, valid: valid})
	}
	return result, nil
}

func wgPortRecoveryChangeAllowed(projection Projection, input WGPortRecoveryResource, now time.Time) bool {
	target, exists := projection.CurrentTarget("resource", input.ResourceID)
	if !exists || target.Deleted || target.Conflicted || len(target.MaterialIDs) == 0 {
		return false
	}
	changes := map[string]WGPortRecoveryChange{}
	attempts := 0
	for _, change := range input.Changes {
		if ValidateDigest(change.MaterialID) != nil || change.ReceivedAt.IsZero() || change.ReceivedAt.After(now) {
			return false
		}
		if previous, exists := changes[change.MaterialID]; exists {
			if !previous.ReceivedAt.Equal(change.ReceivedAt) || previous.Automatic != change.Automatic {
				return false
			}
			continue
		}
		changes[change.MaterialID] = change
		if change.Automatic && !change.ReceivedAt.Before(now.Add(-wgPortRecoveryAttemptWindow)) {
			attempts++
		}
	}
	if attempts >= 3 {
		return false
	}
	for _, id := range target.MaterialIDs {
		change, exists := changes[id]
		if !exists || now.Sub(change.ReceivedAt) < wgPortRecoveryCooldown {
			return false
		}
	}
	return true
}

func wgPortRecoveryListener(report DeviceReport, resource TransportResource, mapped ...netip.AddrPort) bool {
	if report.Runtime.Resources == nil {
		return false
	}
	for _, listener := range *report.Runtime.Resources {
		if listener.ResourceID != resource.ID || listener.ListenerID != resource.ListenerID || listener.PublicKey != *resource.Authentication.PublicKey {
			continue
		}
		// A resource authenticates the peer's public dial coordinate. The
		// receiver reports its actual, independently configured local socket.
		if listener.Validate() == nil {
			if len(mapped) == 0 {
				return true
			}
			if len(mapped) != 1 {
				return false
			}
			actual, err := netip.ParseAddrPort(listener.Listen)
			return err == nil && actual.Port() == mapped[0].Port() && actual.Addr().IsUnspecified()
		}
	}
	return false
}

func wgPortRecoveryFailure(history []wgPortRecoveryReport, latest DeviceReport, link NetworkLink, spec string, now time.Time) int64 {
	var previous U64
	var since, last int64
	var count int
	var generation string
	for _, value := range history {
		report := value.report
		if previous != 0 && report.ReportSequence != previous+1 {
			since, last, count, generation = 0, 0, 0, ""
		}
		previous = report.ReportSequence
		var sample *Observation
		for i := range report.Observations {
			if matchesNativeLinkObservation(report.Observations[i], link, spec) {
				sample = &report.Observations[i]
				break
			}
		}
		_, reportUntil := webReportTime(report, time.UnixMilli(report.ReportedAt))
		if !value.valid || sample == nil || sample.Result != "unavailable" || sample.ObservedAt < now.Add(-wgPortRecoveryWindow).UnixMilli() ||
			webObservationUntil(report, *sample, reportUntil, time.UnixMilli(report.ReportedAt)) == 0 {
			since, last, count, generation = 0, 0, 0, ""
			continue
		}
		if generation != report.NetworkGeneration || last != 0 && (sample.ObservedAt < last || sample.ObservedAt-last > wgPortRecoverySampleGap.Milliseconds()) {
			since, last, count = 0, 0, 0
		}
		generation = report.NetworkGeneration
		if sample.ObservedAt != last {
			if count == 0 {
				since = sample.ObservedAt
			}
			last = sample.ObservedAt
			count++
		}
		if report.ReportSequence == latest.ReportSequence {
			_, until := webReportTime(report, now)
			if count >= 3 && last-since >= (30*time.Second).Milliseconds() && webObservationUntil(report, *sample, until, now) != 0 {
				return since
			}
		}
	}
	return 0
}
