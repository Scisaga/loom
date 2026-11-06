package control

import (
	"bytes"
	"context"
	"errors"
	"log"
	"reflect"
	"slices"
	"sort"
	"time"

	"loom/internal/localconfig"
)

func (server *Server) wgPortRecoveryPrior(head Material) (TransportResource, error) {
	var prior TransportResource
	for _, id := range head.Dependencies {
		body, err := server.Runtime.Authority.Material(id)
		if err != nil {
			return prior, err
		}
		material, err := DecodeMaterial(body)
		if err != nil {
			return prior, err
		}
		resource, ok := wgPortRecoveryResourceValue(material, head.TargetID)
		if !ok {
			continue
		}
		if prior.ID != "" {
			return prior, errors.New("WG recovery prior resource is ambiguous")
		}
		prior = resource
	}
	current, ok := effectiveMaterial(head).Payload.(TransportResource)
	if !ok || prior.ID == "" || current.DialPort == prior.DialPort {
		return prior, errors.New("WG recovery does not have one prior port")
	}
	comparison := current
	comparison.DialPort = prior.DialPort
	a, err := CanonicalEncode(prior)
	if err != nil {
		return prior, err
	}
	b, err := CanonicalEncode(comparison)
	if err != nil || string(a) != string(b) {
		return prior, errors.New("WG recovery changed more than the port")
	}
	return prior, nil
}

// A baseline is rebuilt from immutable pre-change samples, including after a
// control restart. It is a comparison scope, never an authorization or health
// store. Historical observations retain their own signed View and time.
func (server *Server) wgPortRecoveryBaseline(ctx context.Context, p Projection, resource TransportResource, head Material, at time.Time) (map[string]bool, error) {
	if at.IsZero() || at.After(server.now()) {
		return nil, errors.New("WG recovery acceptance time is unavailable")
	}
	prior, err := server.wgPortRecoveryPrior(head)
	if err != nil {
		return nil, err
	}
	before := p
	before.NetworkIntent.Resources = slices.Clone(p.NetworkIntent.Resources)
	for index := range before.NetworkIntent.Resources {
		if before.NetworkIntent.Resources[index].ID == resource.ID {
			before.NetworkIntent.Resources[index] = prior
		}
	}
	histories, err := server.wgPortRecoveryReports(ctx, before, at.Add(-time.Millisecond))
	if err != nil {
		return nil, err
	}
	links, err := DerivedNetworkLinks(before)
	if err != nil {
		return nil, err
	}
	required := map[string]bool{}
	failed := false
	for _, link := range links {
		if link.ResourceID != resource.ID && link.FromResourceID != resource.ID {
			continue
		}
		for _, history := range histories {
			if history.DeviceID != link.FromNodeID {
				continue
			}
			if history.Forked {
				return nil, errors.New("WG recovery baseline report is ambiguous")
			}
			var latest DeviceReport
			for _, report := range history.Reports {
				if report.ReportSequence > latest.ReportSequence {
					latest = report
				}
			}
			result := wgPortRecoveryHistoricalSample(before, latest, link, at)
			if result == "available" {
				required[link.ID] = true
			} else if result == "unavailable" && link.ResourceID == resource.ID {
				required[link.ID] = false
				failed = true
			}
		}
	}
	if !failed {
		return nil, errors.New("WG recovery original failed direction cannot be reconstructed")
	}
	return required, nil
}

func wgPortRecoveryHistoricalSample(p Projection, report DeviceReport, link NetworkLink, now time.Time) string {
	identity, exists := identityFor(p, link.FromNodeID)
	if !exists || report.DeviceID != link.FromNodeID || report.NetworkID != p.NetworkID || report.Verify(identity.DevicePublicKey) != nil {
		return ""
	}
	specs, err := projectionLinkSpecs(p)
	if err != nil {
		return ""
	}
	spec := specs[link.ID]
	if spec == "" {
		return ""
	}
	_, until := webReportTime(report, now)
	for _, sample := range report.Observations {
		if sample.Level == "link" && matchesNativeLinkObservation(sample, link, spec) && webObservationUntil(report, sample, until, now) != 0 {
			return sample.Result
		}
	}
	return ""
}

// Completion is derived from the first verification window's original native
// probe results. This allows a later, separate carrier failure to trigger a new
// bounded attempt, without persisting a recovery-complete flag.
func (server *Server) wgPortRecoveryPreviouslyVerified(ctx context.Context, p Projection, resource TransportResource, head Material, at time.Time) (bool, error) {
	required, err := server.wgPortRecoveryBaseline(ctx, p, resource, head, at)
	if err != nil {
		return false, err
	}
	histories, err := server.wgPortRecoveryReports(ctx, p, at.Add(wgPortRecoveryVerification))
	if err != nil {
		return false, err
	}
	until := at.Add(wgPortRecoveryVerification)
	if current := server.now().Add(webClockTolerance); current.Before(until) {
		until = current
	}
	return wgPortRecoveryHistoricalComplete(p, resource, required, histories, at, until)
}

// Replay the original comparison scope, rather than today's complete Views:
// later Service or Policy changes cannot undo an already verified recovery.
// Every participant and required direction must have been valid at one common
// cut. Separate successes whose lifetimes never overlap are not completion.
func wgPortRecoveryHistoricalComplete(p Projection, resource TransportResource, required map[string]bool, histories []WGPortRecoveryReports, from, until time.Time) (bool, error) {
	links, err := DerivedNetworkLinks(p)
	if err != nil {
		return false, err
	}
	participants := map[string]bool{resource.OwnerNodeID: true}
	comparison := []NetworkLink{}
	for _, link := range links {
		if _, exists := required[link.ID]; exists {
			participants[link.FromNodeID], participants[link.ToNodeID] = true, true
			comparison = append(comparison, link)
		}
	}
	if len(required) == 0 || len(comparison) != len(required) {
		return false, errors.New("WG recovery original comparison scope is unavailable")
	}
	for id := range participants {
		if _, exists := identityFor(p, id); !exists {
			return false, errors.New("WG recovery comparison identity is no longer authorized")
		}
	}
	events := []DeviceReport{}
	for _, history := range histories {
		if !participants[history.DeviceID] {
			continue
		}
		if history.Forked {
			return false, errors.New("WG recovery comparison report is ambiguous")
		}
		positions := map[U64][]byte{}
		times := map[int64]U64{}
		for _, report := range history.Reports {
			if report.ReportedAt < from.UnixMilli() || report.ReportedAt > until.UnixMilli() {
				continue
			}
			body, err := CanonicalEncode(report)
			if err != nil {
				return false, err
			}
			if previous, exists := positions[report.ReportSequence]; exists {
				if !bytes.Equal(previous, body) {
					return false, errors.New("WG recovery comparison report position is ambiguous")
				}
				continue
			}
			if sequence, exists := times[report.ReportedAt]; exists && sequence != report.ReportSequence {
				return false, errors.New("WG recovery comparison report time is ambiguous")
			}
			if report.DeviceID != history.DeviceID || report.ReportSequence == 0 || report.ReportSequence > history.Highest {
				return false, errors.New("WG recovery comparison report scope is invalid")
			}
			positions[report.ReportSequence], times[report.ReportedAt] = body, report.ReportSequence
			events = append(events, report)
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].ReportedAt != events[j].ReportedAt {
			return events[i].ReportedAt < events[j].ReportedAt
		}
		return events[i].DeviceID < events[j].DeviceID
	})
	latest := map[string]DeviceReport{}
	for index := 0; index < len(events); {
		cut := time.UnixMilli(events[index].ReportedAt)
		for index < len(events) && events[index].ReportedAt == cut.UnixMilli() {
			report := events[index]
			if previous, exists := latest[report.DeviceID]; !exists || report.ReportSequence > previous.ReportSequence {
				latest[report.DeviceID] = report
			}
			index++
		}
		ready := true
		for id := range participants {
			report, exists := latest[id]
			identity, _ := identityFor(p, id)
			_, reportUntil := webReportTime(report, cut)
			if !exists || report.NetworkID != p.NetworkID || report.Verify(identity.DevicePublicKey) != nil || reportUntil == 0 ||
				report.Runtime.State != "running" || report.Runtime.AppliedViewDigest != report.ViewDigest {
				ready = false
				break
			}
		}
		if !ready || !wgPortRecoveryListener(latest[resource.OwnerNodeID], resource) {
			continue
		}
		for _, link := range comparison {
			if wgPortRecoveryHistoricalSample(p, latest[link.FromNodeID], link, cut) != "available" {
				ready = false
				break
			}
		}
		if ready {
			return true, nil
		}
	}
	return false, nil
}

func (server *Server) wgPortRecoveryCurrent(ctx context.Context, p Projection, resource TransportResource, required map[string]bool) (bool, error) {
	reports, err := server.Runtime.Reports.Latest(ctx)
	if err != nil {
		return false, err
	}
	views, err := server.wgPortRecoveryViews(p, resource.ID)
	if err != nil {
		return false, err
	}
	latest := map[string]DeviceReport{}
	now := server.now()
	for _, report := range reports {
		_, until := webReportTime(report, now)
		if until != 0 && verifyCurrentReport(report, p, server.expectedReleaseSets(p)...) == nil &&
			report.Runtime.State == "running" && report.Runtime.AppliedViewDigest == report.ViewDigest {
			latest[report.DeviceID] = report
		}
	}
	for _, view := range views {
		if _, exists := latest[view.DeviceID]; !exists {
			return false, nil
		}
	}
	if !wgPortRecoveryListener(latest[resource.OwnerNodeID], resource) {
		return false, nil
	}
	if executor, ok := server.SSH.(WGPortRecoveryExecutor); ok {
		nodes, _, err := executor.WGPortMappings()
		if err != nil {
			return false, err
		}
		mapped, err := localconfig.IngressAddress(nodes, resource.OwnerNodeID, "udp", resource.DialHost, resource.DialPort)
		if err != nil {
			return false, err
		}
		if !wgPortRecoveryListener(latest[resource.OwnerNodeID], resource, mapped) {
			return false, nil
		}
	}
	links, err := DerivedNetworkLinks(p)
	if err != nil {
		return false, err
	}
	remaining := len(required)
	for _, link := range links {
		if _, exists := required[link.ID]; exists {
			if wgPortRecoveryHistoricalSample(p, latest[link.FromNodeID], link, now) != "available" {
				return false, nil
			}
			remaining--
		}
	}
	return remaining == 0, nil
}

func (server *Server) wgPortRecoveryDeliver(ctx context.Context, executor WGPortRecoveryExecutor, p Projection, resource TransportResource) error {
	views, err := server.wgPortRecoveryViews(p, resource.ID)
	if err != nil {
		return err
	}
	return wgPortRecoveryParallel(ctx, views, func(ctx context.Context, view DeviceView) error {
		envelope, err := server.deviceEnvelope(view.DeviceID)
		if err != nil {
			return err
		}
		for _, current := range envelope.View.Resources {
			if current.ID == resource.ID {
				a, _ := CanonicalEncode(current)
				b, _ := CanonicalEncode(resource)
				if string(a) == string(b) {
					return executor.WGPortDeliver(ctx, view.DeviceID, envelope, resource.ID)
				}
			}
		}
		return errors.New("WG recovery resource changed during delivery")
	})
}

func (server *Server) wgPortRecoveryWait(ctx context.Context, p Projection, resource TransportResource, head Material, required map[string]bool, deadline time.Time) (bool, error) {
	id, _ := MaterialID(head)
	for {
		current := server.Runtime.Authority.Snapshot()
		target, exists := current.CurrentTarget("resource", resource.ID)
		if !exists || target.Deleted || target.Conflicted || len(target.MaterialIDs) != 1 || target.MaterialIDs[0] != id {
			return false, errors.New("WG recovery was superseded")
		}
		owner, ownerExists := p.CurrentTarget("device", resource.OwnerNodeID)
		currentOwner, currentOwnerExists := current.CurrentTarget("device", resource.OwnerNodeID)
		if !ownerExists || !currentOwnerExists || !reflect.DeepEqual(owner, currentOwner) {
			return false, errors.New("WG recovery owner was superseded")
		}
		ok, err := server.wgPortRecoveryCurrent(ctx, current, resource, required)
		if err != nil || ok {
			return ok, err
		}
		if !server.now().Before(deadline) {
			return false, nil
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

func (server *Server) finishWGPortRecovery(ctx context.Context, executor WGPortRecoveryExecutor, p Projection, resource TransportResource, head Material, at time.Time) error {
	owner, active := p.CurrentTarget("device", resource.OwnerNodeID)
	if !active || owner.Deleted || owner.Conflicted || len(owner.MaterialIDs) == 0 {
		return errors.New("WG recovery owner is no longer active")
	}
	for _, id := range owner.MaterialIDs {
		if !slices.Contains(head.Dependencies, id) {
			return errors.New("WG recovery owner was superseded before restart")
		}
	}
	required, err := server.wgPortRecoveryBaseline(ctx, p, resource, head, at)
	if err != nil {
		return err
	}
	if server.now().Before(at.Add(wgPortRecoveryVerification)) {
		if err := server.wgPortRecoveryDeliver(ctx, executor, p, resource); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		ok, err := server.wgPortRecoveryWait(ctx, p, resource, head, required, at.Add(wgPortRecoveryVerification))
		if err != nil {
			return err
		}
		if ok {
			log.Print("control: shared WG port recovery verified by current native probe reports and all consumers")
			return nil
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current := server.Runtime.Authority.Snapshot()
	actual, err := server.wgPortRecoveryHead(current, resource.ID)
	if err != nil {
		return err
	}
	expectedID, _ := MaterialID(head)
	actualID, _ := MaterialID(actual)
	if actualID != expectedID {
		return errors.New("WG recovery changed before restoration")
	}
	prior, err := server.wgPortRecoveryPrior(head)
	if err != nil {
		return err
	}
	restored := wgPortRecoveryResource(current, resource.ID)
	restored.DialPort = prior.DialPort
	result, err := server.wgPortRecoveryPut(ctx, current, restored, true)
	if err != nil {
		return err
	}
	if err := server.wgPortRecoveryDeliver(ctx, executor, result.Projection, restored); err != nil {
		return err
	}
	for id, wasAvailable := range required {
		if !wasAvailable {
			delete(required, id)
		}
	}
	restoredHead, err := server.wgPortRecoveryHead(result.Projection, resource.ID)
	if err != nil {
		return err
	}
	verified, err := server.wgPortRecoveryWait(ctx, result.Projection, restored, restoredHead, required, server.now().Add(wgPortRecoveryVerification))
	if err != nil {
		return err
	}
	if !verified {
		return errors.New("WG prior port fact restored but runtime remains unverified")
	}
	log.Print("control: WG recovery verification failed; previous shared port restored by a new authenticated resource fact")
	return errors.New("WG port recovery did not restore every required direction")
}
