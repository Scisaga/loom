package control

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"loom/internal/localconfig"
)

const wgPortRecoveryPrefix = "wg-port-recovery-"
const wgPortRecoveryVerification = 2 * time.Minute

// This is the existing deployment adapter's bounded management capability.
// Mappings locate supplied infrastructure; signed resources remain authority.
type WGPortRecoveryExecutor interface {
	SSHExecutor
	WGPortMappings() ([]localconfig.NodeNetwork, string, error)
	WGPortOccupied(context.Context, string, TransportResource) ([]int, error)
	WGPortCheck(context.Context, string, DeviceView) error
	WGPortDeliver(context.Context, string, DeviceViewEnvelope, string) error
}

func (server *Server) startWGPortRecovery(parent context.Context) func() {
	if _, ok := server.SSH.(WGPortRecoveryExecutor); !ok {
		return func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		for {
			if server.Runtime.Writable() {
				if err := server.reconcileWGPorts(ctx); err != nil && ctx.Err() == nil {
					// Never log SSH output, execution inputs or device credentials.
					log.Print("control: WG port recovery remains unverified; authenticated originals retained")
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (server *Server) reconcileWGPorts(ctx context.Context) error {
	executor, ok := server.SSH.(WGPortRecoveryExecutor)
	if !ok {
		return nil
	}
	nodes, local, err := executor.WGPortMappings()
	if err != nil {
		return err
	}
	if local == "" || local != server.Config.NodeID {
		return errors.New("WG recovery requires this deployment workstation identity")
	}
	p := server.Runtime.Authority.Snapshot()
	now := server.now()
	histories, err := server.wgPortRecoveryReports(ctx, p, now)
	if err != nil {
		return err
	}
	inputs := []WGPortRecoveryResource{}
	var unavailable error
	for _, resource := range p.NetworkIntent.Resources {
		if resource.Kind != "wireguard" {
			continue
		}
		head, err := server.wgPortRecoveryHead(p, resource.ID)
		if err != nil {
			continue
		}
		changes, err := server.Runtime.Authority.wgPortRecoveryChanges(resource.ID, now)
		if err != nil {
			unavailable = errors.Join(unavailable, err)
			continue
		}
		if strings.HasPrefix(head.RequestID, wgPortRecoveryPrefix) && !strings.HasPrefix(head.RequestID, wgPortRecoveryPrefix+"restore-") {
			at := time.Time{}
			id, _ := MaterialID(head)
			for _, change := range changes {
				if change.MaterialID == id {
					at = change.ReceivedAt
				}
			}
			verified, err := server.wgPortRecoveryPreviouslyVerified(ctx, p, resource, head, at)
			if err != nil {
				return err
			}
			if !verified {
				return server.finishWGPortRecovery(ctx, executor, p, resource, head, at)
			}
		}
		avoided, err := server.Runtime.Authority.wgPortRecoveryAvoidedPorts(resource.ID, now)
		if err != nil {
			unavailable = errors.Join(unavailable, err)
			continue
		}
		ports := wgPortRecoveryPorts(nodes, p, resource, avoided)
		inputs = append(inputs, WGPortRecoveryResource{ResourceID: resource.ID, Ports: ports, Changes: changes})
	}
	suggestions, err := WGPortRecovery(p, histories, inputs, now, server.expectedReleaseSets(p)...)
	if err != nil || len(suggestions) == 0 {
		return errors.Join(unavailable, err)
	}
	// One shared listener at a time; independent management reads/deliveries
	// within this attempt remain bounded and parallel.
	suggestion := suggestions[0]
	resource := wgPortRecoveryResource(p, suggestion.ResourceID)
	currentSocket, err := localconfig.IngressAddress(nodes, resource.OwnerNodeID, "udp", resource.DialHost, resource.DialPort)
	if err != nil {
		return err
	}
	occupied, err := executor.WGPortOccupied(ctx, resource.OwnerNodeID, resource)
	if err != nil {
		return err
	}
	selected := false
	for _, input := range inputs {
		if input.ResourceID != resource.ID {
			continue
		}
		for _, candidate := range input.Ports {
			mapped, err := localconfig.IngressAddress(nodes, resource.OwnerNodeID, "udp", resource.DialHost, candidate)
			if err != nil {
				continue
			}
			if mapped.Port() == currentSocket.Port() || !slices.Contains(occupied, int(mapped.Port())) {
				suggestion.ToPort = candidate
				selected = true
				break
			}
		}
	}
	if !selected {
		return errors.New("no unoccupied mapped local WG port is available for the same receiving address")
	}
	views, err := server.wgPortRecoveryViews(p, resource.ID)
	if err != nil {
		return err
	}
	if err := wgPortRecoveryParallel(ctx, views, func(ctx context.Context, view DeviceView) error {
		return executor.WGPortCheck(ctx, view.DeviceID, view)
	}); err != nil {
		return err
	}
	// SSH may outlive a probe's thirty-second validity. Requalify the actual
	// trigger immediately before the authenticated write instead of acting on
	// the preflight's old sample.
	if !reflect.DeepEqual(p, server.Runtime.Authority.Snapshot()) {
		return errors.New("WG recovery authorization changed during preflight")
	}
	fresh, err := server.wgPortRecoveryReports(ctx, p, server.now())
	if err != nil {
		return err
	}
	for index := range inputs {
		if inputs[index].ResourceID == resource.ID {
			inputs = []WGPortRecoveryResource{{ResourceID: resource.ID, Ports: []int{suggestion.ToPort}, Changes: inputs[index].Changes}}
			break
		}
	}
	qualified, err := WGPortRecovery(p, fresh, inputs, server.now(), server.expectedReleaseSets(p)...)
	if err != nil || len(qualified) != 1 || qualified[0].ResourceID != resource.ID {
		return err
	}
	replacement := resource
	replacement.DialPort = suggestion.ToPort
	result, err := server.wgPortRecoveryPut(ctx, p, replacement, false)
	if err != nil {
		return err
	}
	head, err := server.wgPortRecoveryHead(result.Projection, resource.ID)
	if err != nil {
		return err
	}
	log.Print("control: authenticated shared WG port recovery submitted; awaiting native probe reports")
	changes, err := server.Runtime.Authority.wgPortRecoveryChanges(resource.ID, server.now())
	if err != nil {
		return err
	}
	for _, change := range changes {
		if change.MaterialID == result.MaterialID {
			return server.finishWGPortRecovery(ctx, executor, result.Projection, replacement, head, change.ReceivedAt)
		}
	}
	return errors.New("WG recovery acceptance time is missing")
}

// A previously failed port is only avoided for a week by the original-fact
// projection passed here. Ascending cyclic order gives each supplied port a
// turn, without random choices or a persistent allocation index.
func wgPortRecoveryPorts(nodes []localconfig.NodeNetwork, p Projection, resource TransportResource, avoided []int) []int {
	ports := []int{}
	for _, node := range nodes {
		if node.ID != resource.OwnerNodeID {
			continue
		}
		for _, mapping := range node.Ingress {
			if mapping.Protocol != "udp" || mapping.PublicHost != resource.DialHost {
				continue
			}
			for port := mapping.PublicPorts.First; port <= mapping.PublicPorts.Last; port++ {
				if port == resource.DialPort || slices.Contains(avoided, port) {
					continue
				}
				occupied := false
				for _, other := range p.NetworkIntent.Resources {
					if other.ID != resource.ID && (other.Kind == "wireguard" || other.Kind == "hysteria2") && other.DialPort == port &&
						other.DialHost == resource.DialHost {
						occupied = true
					}
				}
				if !occupied {
					ports = append(ports, port)
				}
			}
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		a, b := ports[i], ports[j]
		if (a > resource.DialPort) != (b > resource.DialPort) {
			return a > resource.DialPort
		}
		return a < b
	})
	return slices.Compact(ports)
}

func wgPortRecoveryResource(p Projection, id string) TransportResource {
	for _, resource := range p.NetworkIntent.Resources {
		if resource.ID == id {
			return resource
		}
	}
	return TransportResource{}
}

func (server *Server) wgPortRecoveryHead(p Projection, id string) (Material, error) {
	target, ok := p.CurrentTarget("resource", id)
	if !ok || target.Deleted || target.Conflicted || len(target.MaterialIDs) != 1 {
		return Material{}, errors.New("WG resource does not have one active fact")
	}
	body, err := server.Runtime.Authority.Material(target.MaterialIDs[0])
	if err != nil {
		return Material{}, err
	}
	return DecodeMaterial(body)
}

func (server *Server) wgPortRecoveryPut(ctx context.Context, p Projection, replacement TransportResource, restore bool) (Submission, error) {
	original := wgPortRecoveryResource(p, replacement.ID)
	comparison := replacement
	comparison.DialPort = original.DialPort
	if original.ID == "" || original.Kind != "wireguard" || original.DialPort == replacement.DialPort || !reflect.DeepEqual(original, comparison) {
		return Submission{}, errors.New("WG recovery may only change an existing resource port")
	}
	target, ok := p.CurrentTarget("resource", replacement.ID)
	owner, ownerOK := p.CurrentTarget("device", replacement.OwnerNodeID)
	if !ok || !ownerOK || target.Conflicted || target.Deleted || owner.Conflicted || owner.Deleted || len(target.MaterialIDs) != 1 {
		return Submission{}, errors.New("WG recovery resource or owner is no longer active")
	}
	dependencies := append(append([]string{}, target.MaterialIDs...), owner.MaterialIDs...)
	sort.Strings(dependencies)
	dependencies = slices.Compact(dependencies)
	digest, err := digestContractValue("loom-wg-port-recovery-v3\x00", map[string]any{"resource": replacement, "dependencies": dependencies})
	if err != nil {
		return Submission{}, err
	}
	prefix := wgPortRecoveryPrefix
	if restore {
		prefix += "restore-"
	}
	operation := Operation{Schema: 3, RequestID: prefix + strings.TrimPrefix(digest, "sha256:"), Operation: "resource.put", TargetKind: "resource", TargetID: replacement.ID, Dependencies: dependencies, Payload: replacement}
	body, err := EncodeOperation(operation)
	if err != nil {
		return Submission{}, err
	}
	// The ordinary authenticated submission entry and its target dependency
	// checks remain intact. This additional check rejects unrelated concurrent
	// authorization changes before signing the reviewed resource.
	return server.Runtime.submitChecked(ctx, body, func(current Projection) error {
		if !reflect.DeepEqual(p, current) {
			return errors.New("WG recovery review changed before signing")
		}
		return nil
	})
}

func (server *Server) wgPortRecoveryViews(p Projection, resourceID string) ([]DeviceView, error) {
	links, err := DerivedNetworkLinks(p)
	if err != nil {
		return nil, err
	}
	resource := wgPortRecoveryResource(p, resourceID)
	participants := map[string]bool{resource.OwnerNodeID: true}
	for _, link := range links {
		if link.ResourceID == resourceID || link.FromResourceID == resourceID {
			participants[link.FromNodeID], participants[link.ToNodeID] = true, true
		}
	}
	views := []DeviceView{}
	for _, device := range p.DeviceAuthorizations {
		if !participants[device.ID] {
			continue
		}
		view, err := ProjectDeviceView(p, device.ID, server.expectedReleaseSets(p)...)
		if err != nil {
			return nil, err
		}
		for _, resource := range view.Resources {
			if resource.ID == resourceID {
				views = append(views, view)
				break
			}
		}
	}
	if len(views) == 0 {
		return nil, errors.New("WG recovery has no authenticated consumers")
	}
	return views, nil
}

func wgPortRecoveryParallel(ctx context.Context, views []DeviceView, run func(context.Context, DeviceView) error) error {
	var workers sync.WaitGroup
	var mu sync.Mutex
	var joined error
	limit := make(chan struct{}, 4)
	for _, view := range views {
		workers.Add(1)
		go func() {
			defer workers.Done()
			select {
			case limit <- struct{}{}:
				defer func() { <-limit }()
			case <-ctx.Done():
				return
			}
			check, cancel := context.WithTimeout(ctx, 35*time.Second)
			defer cancel()
			if err := run(check, view); err != nil {
				mu.Lock()
				joined = errors.Join(joined, fmt.Errorf("WG management operation failed for %s", view.DeviceID))
				mu.Unlock()
			}
		}()
	}
	workers.Wait()
	return errors.Join(joined, ctx.Err())
}
