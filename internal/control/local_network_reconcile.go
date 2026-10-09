package control

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

func reportedLocalNetworkConflicts(projection Projection, reports []DeviceReport, releases ...ReleaseSet) map[string]bool {
	conflicts := LocalNetworkConflicts(projection.NetworkIntent)
	for _, report := range latestLocalNetworkReports(projection, reports) {
		if verifyCurrentReport(report, projection, releases...) != nil {
			continue
		}
		view, err := ProjectDeviceView(projection, report.DeviceID, releases...)
		if err != nil {
			continue
		}
		for _, service := range projection.NetworkIntent.Services {
			if service.LocalNetwork == nil {
				continue
			}
			visible := service.LocalNetwork.GatewayNodeID == report.DeviceID
			for _, assigned := range view.Services {
				visible = visible || assigned.ID == service.ID
			}
			if !visible {
				continue
			}
			virtual, _ := netip.ParsePrefix(service.LocalNetwork.VirtualPrefix)
			for _, text := range *report.LocalNetworks {
				prefix, _ := netip.ParsePrefix(text.Prefix)
				if virtual.Overlaps(prefix) {
					conflicts[service.ID] = true
				}
			}
		}
	}
	return conflicts
}

// Follow up only this control's single latest Service fact. No lease or
// coordinator is introduced; another control can take over by an explicit
// administrator write. Concurrent edits retain the existing conflict rules.
func (server *Server) reconcileLocalNetworks(ctx context.Context) error {
	projection := server.Runtime.Authority.Snapshot()
	hasMapping := false
	for _, service := range projection.NetworkIntent.Services {
		if service.LocalNetwork != nil && service.LocalNetwork.Enabled {
			hasMapping = true
			break
		}
	}
	if !hasMapping {
		return nil
	}
	reports, err := server.Runtime.Reports.Latest(ctx)
	if err != nil {
		return err
	}
	releases := server.expectedReleaseSets(projection)
	conflicts := reportedLocalNetworkConflicts(projection, reports, releases...)
	for _, service := range projection.NetworkIntent.Services {
		mapping := service.LocalNetwork
		if mapping == nil || !mapping.Enabled || !conflicts[service.ID] {
			continue
		}
		target, found := projection.CurrentTarget("service", service.ID)
		if !found || target.Deleted || target.Conflicted || len(target.MaterialIDs) != 1 {
			continue
		}
		body, err := server.Runtime.Authority.Material(target.MaterialIDs[0])
		if err != nil {
			return err
		}
		fact, err := DecodeMaterial(body)
		if err != nil {
			return err
		}
		if fact.IssuerControlID != server.Config.ControlID {
			continue
		}
		digest, err := digestContractValue("loom-local-network-retry-v3\x00", map[string]any{"service_id": service.ID, "material_ids": target.MaterialIDs})
		if err != nil {
			return err
		}
		requestID := "lan-reallocate-" + strings.TrimPrefix(digest, "sha256:")
		var operation Operation
		if mapping.AllocationAttempt < 3 {
			operation, err = localNetworkAllocation(projection, reports, LocalNetworkAllocationRequest{Schema: 3, RequestID: requestID, ID: service.ID, Name: service.Name, GatewayNodeID: mapping.GatewayNodeID, LocalPrefix: mapping.LocalPrefix, AllocationAttempt: mapping.AllocationAttempt + 1}, releases...)
			if err != nil && !errors.Is(err, errNoLocalNetworkPrefix) {
				return err
			}
		}
		if mapping.AllocationAttempt == 3 || errors.Is(err, errNoLocalNetworkPrefix) {
			disabled := service
			disabled.LocalNetwork = new(*mapping)
			disabled.LocalNetwork.Enabled = false
			dependencies := append([]string{}, target.MaterialIDs...)
			gateway, active := projection.CurrentTarget("device", mapping.GatewayNodeID)
			if !active || gateway.Deleted || gateway.Conflicted {
				continue
			}
			dependencies = append(dependencies, gateway.MaterialIDs...)
			sort.Strings(dependencies)
			dependencies = slices.Compact(dependencies)
			operation = Operation{Schema: 3, RequestID: requestID, Operation: "service.put", TargetKind: "service", TargetID: service.ID, Dependencies: dependencies, Payload: disabled}
		}
		if _, _, err := server.HandleOperation(ctx, operation); err != nil {
			return err
		}
		// Other maps may depend on this exact prefix. Rebuild their inputs on
		// the next existing reconciliation tick rather than use this snapshot.
		return nil
	}
	return nil
}
