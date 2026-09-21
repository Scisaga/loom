package control

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"loom/internal/model"
	"loom/internal/validate"
)

// PrepareLegacyNetworkImport replays and authenticates the protected legacy
// control boundary, then performs the only permitted legacy-SSOT-to-
// NetworkIntent conversion.  The returned legacy State is evidence for the
// local admin socket; it is not a second authority or a daemon input.
func PrepareLegacyNetworkImport(input ImportInput, publicDataPlaneCA []byte) (State, NetworkImport, error) {
	state, lkg, err := importValidated(input)
	if err != nil {
		return State{}, NetworkImport{}, err
	}
	intent, err := NetworkIntentFromLegacySSOT(lkg, publicDataPlaneCA)
	if err != nil {
		return State{}, NetworkImport{}, err
	}
	recovery, err := canonical(state.Recovery)
	if err != nil {
		return State{}, NetworkImport{}, err
	}
	return state, NetworkImport{Intent: intent, RecoveryEvidenceHash: "sha256:" + SHA256(recovery)}, nil
}

// NetworkIntentFromLegacySSOT is deliberately strict.  A legacy value with no
// exact schema-2 meaning fails as a whole instead of being guessed from the
// current WebProjection.
func NetworkIntentFromLegacySSOT(body, publicDataPlaneCA []byte) (NetworkIntent, error) {
	legacy, err := model.Load(body)
	if err != nil {
		return NetworkIntent{}, err
	}
	if findings := validate.Validate(legacy); len(findings) != 0 {
		return NetworkIntent{}, fmt.Errorf("legacy LKG validation failed: %s", validate.Format(findings))
	}
	intent := NetworkIntent{Schema: networkIntentSchema, Nodes: []NetworkNode{}, Links: []NetworkLink{},
		Policies: []NetworkPolicy{}, Services: []Service{}, DNS: []string{}, Components: []ComponentExpectation{},
		PublicDataPlaneCA: string(publicDataPlaneCA)}
	if legacy.Defaults != nil {
		intent.DNS = sortedStrings(legacy.Defaults.DNS)
		intent.Components = legacyComponents(legacy.Defaults.Components)
	}
	for index := range legacy.Nodes {
		node := &legacy.Nodes[index]
		if node.Drain || node.Paused || node.Decommission {
			return NetworkIntent{}, fmt.Errorf("legacy node %s has lifecycle flags that NetworkIntent cannot silently reinterpret", node.ID)
		}
		platform := "linux"
		roles := []string{}
		if node.Access != nil {
			roles = append(roles, "access")
			switch node.Access.Platform {
			case model.Android:
				platform = "android"
			case model.WindowsDesktop:
				platform = "windows"
			case model.LinuxServer:
				platform = "linux"
			default:
				return NetworkIntent{}, fmt.Errorf("legacy node %s has unsupported platform %q", node.ID, node.Access.Platform)
			}
		}
		converted := NetworkNode{ID: node.ID, Name: node.Name, Platform: platform, Roles: roles,
			DNS: sortedStrings(node.DNS), Components: legacyComponents(node.Components),
			ProbeTargets: sortedStrings(node.ProbeTargets), DistributionURLs: sortedUniqueStrings(legacy.DistributionURLsFor(node))}
		if converted.Name == "" {
			converted.Name = converted.ID
		}
		if node.Server != nil {
			converted.Roles = append(converted.Roles, "server")
			converted.Server = &ServerIntent{Direction: string(node.Server.Direction), PublicDataIngress: node.Server.PublicDataIngress,
				PublicEndpoint: node.PublicEndpoint, InboundPort: node.Server.InboundPort,
				InboundProtocol: string(node.Server.InboundProtocol.Or()), EgressCapable: node.Server.EgressCapable,
				WGPublicKey: node.Server.WGPublicKey, Country: node.Country, City: node.City, Provider: node.Provider}
			if !validPublicHost(converted.Server.PublicEndpoint) {
				return NetworkIntent{}, fmt.Errorf("legacy server %s has no canonical public endpoint", node.ID)
			}
			if err := validateServerIntent(converted.Server); err != nil {
				return NetworkIntent{}, fmt.Errorf("legacy server %s cannot be represented: %w", node.ID, err)
			}
		}
		sort.Strings(converted.Roles)
		intent.Nodes = append(intent.Nodes, converted)
	}
	sort.Slice(intent.Nodes, func(i, j int) bool { return intent.Nodes[i].ID < intent.Nodes[j].ID })
	for _, tunnel := range legacy.Tunnels {
		if tunnel.Protocol != model.WG || tunnel.Obfuscation != "" {
			return NetworkIntent{}, fmt.Errorf("legacy tunnel %s uses unsupported transport or obfuscation", tunnel.Pair())
		}
		from, to, fromAddress, toAddress := tunnel.From, tunnel.To, tunnel.FromAddr, tunnel.ToAddr
		if from > to {
			from, to, fromAddress, toAddress = to, from, toAddress, fromAddress
		}
		fromTarget, toTarget := strings.Split(toAddress, "/")[0], strings.Split(fromAddress, "/")[0]
		link := NetworkLink{ID: "link-" + from + "-" + to, From: from, To: to, Transport: "wireguard",
			FromAddress: fromAddress, ToAddress: toAddress, ListenPort: tunnel.ListenPort,
			RetiredListenPorts: append([]int(nil), tunnel.RetiredPorts...),
			ProbeTargets:       []NetworkLinkProbeTarget{{Reporter: from, Target: fromTarget}, {Reporter: to, Target: toTarget}}}
		sort.Ints(link.RetiredListenPorts)
		intent.Links = append(intent.Links, link)
	}
	sort.Slice(intent.Links, func(i, j int) bool { return intent.Links[i].ID < intent.Links[j].ID })
	nodes := legacy.NodeByID()
	for _, declaration := range legacy.Declarations {
		if !declaration.AddressFromRequest() {
			return NetworkIntent{}, fmt.Errorf("legacy declaration %s uses an address axis that NetworkIntent cannot preserve", declaration.ID)
		}
		allowed := sortedStrings(declaration.AllowedServers)
		exits := []string{}
		localEgressDevices := []string{}
		pinned := declaration.PinnedEgress()
		if pinned != "" {
			for _, node := range legacy.Nodes {
				if node.ID == pinned && node.Access != nil && node.Server != nil {
					localEgressDevices = append(localEgressDevices, pinned)
				}
			}
		}
		for _, nodeID := range allowed {
			node := nodes[nodeID]
			if node != nil && node.Server != nil && node.Server.EgressCapable &&
				(pinned == "" || pinned == nodeID) {
				exits = append(exits, nodeID)
			}
		}
		name := declaration.Name
		if name == "" {
			name = declaration.ID
		}
		intent.Policies = append(intent.Policies, NetworkPolicy{ID: declaration.ID, Name: name,
			AllowedServers: allowed, AllowedExits: exits, LocalEgressDevices: localEgressDevices,
			AllowDirect: pinned == "", MaxHops: declaration.MaxHops})
	}
	sort.Slice(intent.Policies, func(i, j int) bool { return intent.Policies[i].ID < intent.Policies[j].ID })
	for _, service := range legacy.Services {
		name := service.Name
		if name == "" {
			name = service.ID
		}
		intent.Services = append(intent.Services, Service{ID: service.ID, Name: name,
			Matchers: sortedStrings(service.Addresses), Policy: service.Declaration})
	}
	sort.Slice(intent.Services, func(i, j int) bool { return intent.Services[i].ID < intent.Services[j].ID })
	if len(intent.Nodes) == 0 || len(intent.Policies) == 0 || len(intent.Services) == 0 {
		return NetworkIntent{}, errors.New("legacy LKG does not contain a complete network intent")
	}
	if err := intent.Validate(); err != nil {
		return NetworkIntent{}, fmt.Errorf("converted NetworkIntent is invalid: %w", err)
	}
	return intent, nil
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func sortedUniqueStrings(values []string) []string {
	result := sortedStrings(values)
	unique := result[:0]
	for _, value := range result {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func legacyComponents(versions *model.ComponentVersions) []ComponentExpectation {
	if versions == nil {
		return []ComponentExpectation{}
	}
	components := []ComponentExpectation{}
	for _, value := range []struct{ name, version string }{
		{"agent", versions.Agent}, {"sing-box", versions.SingBox}, {"tailscale", versions.Tailscale}, {"wireguard", versions.WireGuard},
	} {
		if value.version != "" {
			components = append(components, ComponentExpectation{Name: value.name, Version: value.version})
		}
	}
	return components
}
