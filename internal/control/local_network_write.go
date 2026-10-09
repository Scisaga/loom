package control

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sort"
)

// This request only asks for a reviewable operation. It reserves no address and
// has no lifetime outside this call and the existing administrator form.
type LocalNetworkAllocationRequest struct {
	Schema            int    `json:"schema"`
	RequestID         string `json:"request_id"`
	ID                string `json:"id"`
	Name              string `json:"name"`
	GatewayNodeID     string `json:"gateway_node_id"`
	LocalPrefix       string `json:"local_prefix"`
	AllocationAttempt int    `json:"allocation_attempt"`
}

func (value LocalNetworkAllocationRequest) Validate() error {
	if value.Schema != 3 || ValidateID(value.RequestID) != nil || ValidateID(value.ID) != nil || ValidateText(value.Name) != nil || ValidateID(value.GatewayNodeID) != nil || value.GatewayNodeID == "direct" || value.AllocationAttempt < 0 || value.AllocationAttempt > 3 {
		return errors.New("local network allocation request is invalid")
	}
	_, err := localNetworkPrefix(value.LocalPrefix)
	return err
}

func latestLocalNetworkReports(projection Projection, reports []DeviceReport) map[string]DeviceReport {
	latest := map[string]DeviceReport{}
	forked := map[string]bool{}
	for _, report := range reports {
		identity, found := identityFor(projection, report.DeviceID)
		if !found || report.NetworkID != projection.NetworkID || report.Verify(identity.DevicePublicKey) != nil {
			continue
		}
		if previous, found := latest[report.DeviceID]; !found || report.ReportSequence > previous.ReportSequence {
			latest[report.DeviceID] = report
			forked[report.DeviceID] = false
		} else if previous.ReportSequence == report.ReportSequence && !sameContractValue(previous, report) {
			forked[report.DeviceID] = true
		}
	}
	for id, report := range latest {
		if forked[id] || report.LocalNetworks == nil {
			delete(latest, id)
		}
	}
	return latest
}

func reportedShareableLAN(report DeviceReport, prefix string) bool {
	if report.LocalNetworks == nil {
		return false
	}
	for _, value := range *report.LocalNetworks {
		if value.Prefix == prefix && value.LAN {
			return true
		}
	}
	return false
}

func localNetworkAllocation(projection Projection, reports []DeviceReport, request LocalNetworkAllocationRequest, releases ...ReleaseSet) (Operation, error) {
	if err := request.Validate(); err != nil {
		return Operation{}, err
	}
	gateway, found := authorizationFor(projection, request.GatewayNodeID)
	if !found || !containsString(gateway.Responsibilities, "forward") {
		return Operation{}, errors.New("LAN gateway is not an authorized forward node")
	}
	latest := latestLocalNetworkReports(projection, reports)
	report, found := latest[request.GatewayNodeID]
	if !found || verifyCurrentReport(report, projection, releases...) != nil || !reportedShareableLAN(report, request.LocalPrefix) {
		return Operation{}, errors.New("gateway has no current authenticated report of the selected local prefix")
	}
	dependencies := map[string]bool{}
	reference := func(kind, id string, required bool) error {
		target, exists := projection.CurrentTarget(kind, id)
		if required && (!exists || target.Conflicted || target.Deleted) || exists && target.Conflicted {
			return errors.New("allocation references an unavailable or conflicted object")
		}
		for _, id := range target.MaterialIDs {
			dependencies[id] = true
		}
		return nil
	}
	if err := reference("device", gateway.ID, true); err != nil {
		return Operation{}, err
	}
	if err := reference("service", request.ID, false); err != nil {
		return Operation{}, err
	}
	excluded := []netip.Prefix{}
	for _, current := range latest {
		for _, text := range *current.LocalNetworks {
			prefix, _ := netip.ParsePrefix(text.Prefix)
			excluded = append(excluded, prefix)
		}
	}
	for _, service := range projection.NetworkIntent.Services {
		if service.ID == request.ID && service.Kind != "local_network" {
			return Operation{}, errors.New("Service kind cannot change")
		}
		if service.LocalNetwork == nil {
			continue
		}
		if err := reference("service", service.ID, true); err != nil {
			return Operation{}, err
		}
		local, _ := netip.ParsePrefix(service.LocalNetwork.LocalPrefix)
		excluded = append(excluded, local)
		if service.ID != request.ID {
			virtual, _ := netip.ParsePrefix(service.LocalNetwork.VirtualPrefix)
			excluded = append(excluded, virtual)
		}
	}
	for _, resource := range projection.NetworkIntent.Resources {
		if resource.Authentication.LocalAddresses == nil {
			continue
		}
		if err := reference("resource", resource.ID, true); err != nil {
			return Operation{}, err
		}
		for _, text := range *resource.Authentication.LocalAddresses {
			if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Addr().Is4() {
				excluded = append(excluded, prefix.Masked())
			}
		}
	}
	virtual, err := AllocateLocalNetworkPrefix(projection.NetworkID, request.ID, request.AllocationAttempt, request.LocalPrefix, excluded)
	if err != nil {
		return Operation{}, err
	}
	value := Service{ID: request.ID, Name: request.Name, Kind: "local_network", LocalNetwork: &LocalNetwork{GatewayNodeID: gateway.ID, LocalPrefix: request.LocalPrefix, VirtualPrefix: virtual.String(), AllocationAttempt: request.AllocationAttempt, Enabled: true}}
	ids := make([]string, 0, len(dependencies))
	for id := range dependencies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return Operation{Schema: 3, RequestID: request.RequestID, Operation: "service.put", TargetKind: "service", TargetID: value.ID, Dependencies: ids, Payload: value}, nil
}

func checkLocalNetworkWrite(operation Operation, projection Projection, reports []DeviceReport, reportErr error, releases ...ReleaseSet) error {
	value, lan := operation.Payload.(Service)
	if !lan || value.LocalNetwork == nil {
		return nil
	}
	for _, prior := range projection.NetworkIntent.Services {
		if prior.ID != value.ID || prior.LocalNetwork == nil {
			continue
		}
		if *prior.LocalNetwork == *value.LocalNetwork {
			return nil
		}
		disabled := *prior.LocalNetwork
		disabled.Enabled = false
		if *value.LocalNetwork == disabled {
			return nil
		}
	}
	if !value.LocalNetwork.Enabled {
		return errors.New("disabling a LAN must retain its original mapping")
	}
	if reportErr != nil {
		return errors.New("LAN allocation report readback is unavailable")
	}
	want, err := localNetworkAllocation(projection, reports, LocalNetworkAllocationRequest{Schema: 3, RequestID: operation.RequestID, ID: value.ID, Name: value.Name, GatewayNodeID: value.LocalNetwork.GatewayNodeID, LocalPrefix: value.LocalNetwork.LocalPrefix, AllocationAttempt: value.LocalNetwork.AllocationAttempt}, releases...)
	if err != nil {
		return err
	}
	if !sameContractValue(want.Payload, value) {
		return errors.New("LAN allocation preview is stale; review a new allocation")
	}
	for _, id := range want.Dependencies {
		if !containsString(operation.Dependencies, id) {
			return errors.New("LAN allocation dependencies changed; review again")
		}
	}
	return nil
}

func (server *Server) localNetworkAllocation(w http.ResponseWriter, r *http.Request) {
	if !server.admin(r) {
		http.Error(w, "administrator certificate required", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); !localAdmin(r) && origin != "" && origin != "https://"+r.Host {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	body, err := boundedBody(w, r)
	var request LocalNetworkAllocationRequest
	if err != nil || DecodeCanonical(body, &request, materialDecodeLimits()) != nil {
		http.Error(w, "invalid allocation request", http.StatusBadRequest)
		return
	}
	projection := server.Runtime.Authority.Snapshot()
	reports, err := server.Runtime.Reports.Latest(r.Context())
	if err != nil {
		http.Error(w, "LAN report readback unavailable", http.StatusServiceUnavailable)
		return
	}
	operation, err := localNetworkAllocation(projection, reports, request, server.expectedReleaseSets(projection)...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeCanonical(w, http.StatusOK, operation)
}

func (server *Server) submitLocalNetworkOperation(ctx context.Context, operation Operation, body []byte) (Submission, error) {
	reports, reportErr := server.Runtime.Reports.Latest(ctx)
	releases := server.expectedReleaseSets(server.Runtime.Authority.Snapshot())
	return server.Runtime.submitChecked(ctx, body, func(projection Projection) error {
		return checkLocalNetworkWrite(operation, projection, reports, reportErr, releases...)
	})
}
