package control

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

const networkIntentSchema = 2

// NetworkIntent is the canonical, secret-free network value certified by the
// control log. DeviceView and WebProjection are derived from it; neither is an
// input when the network is changed.
type NetworkIntent struct {
	Schema            int                    `json:"schema"`
	Nodes             []NetworkNode          `json:"nodes"`
	Links             []NetworkLink          `json:"links"`
	Policies          []NetworkPolicy        `json:"policies"`
	Services          []Service              `json:"services"`
	DNS               []string               `json:"dns"`
	Components        []ComponentExpectation `json:"components"`
	PublicDataPlaneCA string                 `json:"public_data_plane_ca"`
}

type NetworkNode struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Platform         string                 `json:"platform,omitempty"`
	Roles            []string               `json:"roles"`
	Server           *ServerIntent          `json:"server,omitempty"`
	DNS              []string               `json:"dns,omitempty"`
	Components       []ComponentExpectation `json:"components,omitempty"`
	ProbeTargets     []string               `json:"probe_targets,omitempty"`
	DistributionURLs []string               `json:"distribution_urls,omitempty"`
}

type ServerIntent struct {
	Direction         string `json:"direction"`
	PublicDataIngress bool   `json:"public_data_ingress"`
	PublicEndpoint    string `json:"public_endpoint"`
	InboundPort       int    `json:"inbound_port"`
	InboundProtocol   string `json:"inbound_protocol"`
	EgressCapable     bool   `json:"egress_capable"`
	WGPublicKey       string `json:"wg_public_key,omitempty"`
	Country           string `json:"country,omitempty"`
	City              string `json:"city,omitempty"`
	Provider          string `json:"provider,omitempty"`
}

type NetworkLink struct {
	ID                 string                   `json:"id"`
	From               string                   `json:"from"`
	To                 string                   `json:"to"`
	Transport          string                   `json:"transport"`
	FromAddress        string                   `json:"from_address"`
	ToAddress          string                   `json:"to_address"`
	ListenPort         int                      `json:"listen_port"`
	RetiredListenPorts []int                    `json:"retired_listen_ports,omitempty"`
	ProbeTargets       []NetworkLinkProbeTarget `json:"probe_targets"`
}

type NetworkLinkProbeTarget struct {
	Reporter string `json:"reporter"`
	Target   string `json:"target"`
}

type NetworkPolicy struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	AllowedServers     []string `json:"allowed_servers"`
	AllowedExits       []string `json:"allowed_exits"`
	LocalEgressDevices []string `json:"local_egress_devices,omitempty"`
	AllowDirect        bool     `json:"allow_direct"`
	MaxHops            int      `json:"max_hops"`
}

type ComponentExpectation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
}

type LinkProbeTarget struct {
	LinkID          string `json:"link_id"`
	Peer            string `json:"peer"`
	Transport       string `json:"transport"`
	Target          string `json:"target"`
	PeerWGPublicKey string `json:"peer_wg_public_key,omitempty"`
}

type NetworkImport struct {
	Intent               NetworkIntent `json:"intent"`
	RecoveryEvidenceHash string        `json:"recovery_evidence_hash"`
}

func validateSortedNames(values []string, field string) error {
	for index, value := range values {
		if !validName(value) || index > 0 && values[index-1] >= value {
			return fmt.Errorf("%s are not uniquely sorted", field)
		}
	}
	return nil
}

func validateComponents(values []ComponentExpectation) error {
	for index, component := range values {
		if !validName(component.Name) || !validName(component.Version) ||
			index > 0 && values[index-1].Name >= component.Name {
			return errors.New("component expectations are not uniquely sorted")
		}
		if component.Digest != "" && !validDigest(component.Digest) {
			return errors.New("component expectation digest is invalid")
		}
	}
	return nil
}

func validatePublicDataPlaneCA(value string) error {
	if len(value) == 0 || len(value) > 1<<20 {
		return errors.New("public data-plane CA is invalid")
	}
	rest := []byte(value)
	previous := []byte(nil)
	seen := map[string]bool{}
	count := 0
	for len(rest) > 0 {
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("public data-plane CA is not a canonical certificate bundle")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return errors.New("public data-plane CA certificate is invalid")
		}
		if seen[string(block.Bytes)] || previous != nil && bytes.Compare(previous, block.Bytes) >= 0 {
			return errors.New("public data-plane CA certificates are not uniquely sorted")
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
		consumed := len(rest) - len(remainder)
		if !bytes.Equal(rest[:consumed], encoded) {
			return errors.New("public data-plane CA is not canonically encoded")
		}
		seen[string(block.Bytes)] = true
		previous = block.Bytes
		count++
		rest = remainder
	}
	if count == 0 {
		return errors.New("public data-plane CA is empty")
	}
	return nil
}

func validIPList(values []string, field string) error {
	for index, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || address.String() != value || index > 0 && values[index-1] >= value {
			return fmt.Errorf("%s are not canonical and uniquely sorted", field)
		}
	}
	return nil
}

func validateProbeTargets(values []string) error {
	for index, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.String() != value || parsed.User != nil || parsed.Fragment != "" ||
			(parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Hostname() == "" ||
			index > 0 && values[index-1] >= value {
			return errors.New("network node probe targets are not canonical and uniquely sorted")
		}
	}
	return nil
}

func validateDistributionURLs(values []string) error {
	for index, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.String() != value || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Host == "" ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || index > 0 && values[index-1] >= value {
			return errors.New("network distribution URLs are invalid or not uniquely sorted")
		}
	}
	return nil
}

func validServiceMatcher(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, " /@:") {
		return false
	}
	if strings.HasPrefix(value, ".") {
		value = value[1:]
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.String() == value
	}
	if len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			letter := character >= 'a' && character <= 'z'
			digit := character >= '0' && character <= '9'
			if !letter && !digit && character != '-' {
				return false
			}
		}
	}
	return true
}

func validateServiceMatchers(values []string) error {
	for index, value := range values {
		if !validServiceMatcher(value) || index > 0 && values[index-1] >= value {
			return errors.New("service matchers are not canonical and uniquely sorted")
		}
	}
	return nil
}

func validPublicHost(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, " /@") {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.String() == value
	}
	return !strings.Contains(value, ":") && net.ParseIP(value) == nil && validName(value) && strings.Contains(value, ".")
}

func canonicalTunnelPrefix(value string) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.String() != value || prefix.Addr().Is4() && prefix.Bits() != 32 || prefix.Addr().Is6() && prefix.Bits() != 128 {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// resolveLinkDirection converts the two certified per-node directions into
// one deterministic initiator and acceptor. It contains no reachability
// fallback: temporary transport failure remains an Observation.
func resolveLinkDirection(from, to NetworkNode) (initiator, acceptor string, err error) {
	if from.Server == nil || to.Server == nil {
		return "", "", errors.New("wireguard link endpoints must be servers")
	}
	left, right := from.Server.Direction, to.Server.Direction
	if left == "reverse_only" && right == "reverse_only" || left == "direct_only" && right == "direct_only" {
		return "", "", errors.New("wireguard link directions cannot establish a connection")
	}
	switch {
	case left == "reverse_only":
		return from.ID, to.ID, nil
	case right == "reverse_only":
		return to.ID, from.ID, nil
	case left == "direct_only":
		return to.ID, from.ID, nil
	case right == "direct_only":
		return from.ID, to.ID, nil
	case left == "bidirectional" && right == "bidirectional":
		if from.ID < to.ID {
			return from.ID, to.ID, nil
		}
		return to.ID, from.ID, nil
	default:
		return "", "", errors.New("wireguard link direction is invalid")
	}
}

func (intent NetworkIntent) Validate() error {
	if intent.Schema != networkIntentSchema || validatePublicDataPlaneCA(intent.PublicDataPlaneCA) != nil {
		return errors.New("network intent is incomplete")
	}
	if err := validIPList(intent.DNS, "network DNS servers"); err != nil {
		return err
	}
	if err := validateComponents(intent.Components); err != nil {
		return err
	}
	nodes := map[string]NetworkNode{}
	for index, node := range intent.Nodes {
		if !validName(node.ID) || !validName(node.Name) || index > 0 && intent.Nodes[index-1].ID >= node.ID {
			return errors.New("network nodes are not uniquely sorted")
		}
		if node.Platform != "" && node.Platform != "android" && node.Platform != "linux" && node.Platform != "windows" {
			return errors.New("network node platform is invalid")
		}
		if err := validateSortedNames(node.Roles, "network node roles"); err != nil {
			return err
		}
		if err := validIPList(node.DNS, "network node DNS servers"); err != nil {
			return err
		}
		if err := validateProbeTargets(node.ProbeTargets); err != nil {
			return err
		}
		if err := validateDistributionURLs(node.DistributionURLs); err != nil {
			return err
		}
		if err := validateComponents(node.Components); err != nil {
			return err
		}
		hasServer := false
		for _, role := range node.Roles {
			switch role {
			case "access":
			case "server":
				hasServer = true
			default:
				return errors.New("network node role is invalid")
			}
		}
		if hasServer != (node.Server != nil) {
			return errors.New("network node server role and attributes disagree")
		}
		if hasServer && node.Platform != "linux" || !hasServer && node.Server != nil ||
			(node.Platform == "android" || node.Platform == "windows") && hasServer {
			return errors.New("network node platform cannot provide the declared server role")
		}
		if node.Server != nil {
			server := node.Server
			if !validName(server.Direction) || !validPublicHost(server.PublicEndpoint) || server.InboundPort < 1 || server.InboundPort > 65535 ||
				!validName(server.InboundProtocol) || validateServerIntent(server) != nil {
				return errors.New("network server attributes are incomplete")
			}
		}
		nodes[node.ID] = node
	}
	addresses := map[netip.Addr]bool{}
	for index, link := range intent.Links {
		from, fromOK := nodes[link.From]
		to, toOK := nodes[link.To]
		fromPrefix, fromAddressOK := canonicalTunnelPrefix(link.FromAddress)
		toPrefix, toAddressOK := canonicalTunnelPrefix(link.ToAddress)
		if !validName(link.ID) || !validName(link.From) || !validName(link.To) || link.From >= link.To ||
			link.Transport != "wireguard" || index > 0 && intent.Links[index-1].ID >= link.ID ||
			!fromOK || !toOK || from.Server == nil || to.Server == nil ||
			!fromAddressOK || !toAddressOK || fromPrefix.Addr() == toPrefix.Addr() ||
			addresses[fromPrefix.Addr()] || addresses[toPrefix.Addr()] || link.ListenPort < 1 || link.ListenPort > 65535 ||
			len("wg-"+link.From) > 15 || len("wg-"+link.To) > 15 {
			return errors.New("network links are not uniquely sorted")
		}
		if _, _, err := resolveLinkDirection(from, to); err != nil {
			return err
		}
		previousPort := 0
		for _, port := range link.RetiredListenPorts {
			if port < 1 || port > 65535 || port == link.ListenPort || previousPort >= port {
				return errors.New("network link retired ports are invalid")
			}
			previousPort = port
		}
		if len(link.ProbeTargets) != 2 || link.ProbeTargets[0].Reporter != link.From ||
			link.ProbeTargets[0].Target != toPrefix.Addr().String() || link.ProbeTargets[1].Reporter != link.To ||
			link.ProbeTargets[1].Target != fromPrefix.Addr().String() {
			return errors.New("network link probe targets do not match tunnel endpoints")
		}
		addresses[fromPrefix.Addr()] = true
		addresses[toPrefix.Addr()] = true
	}
	policies := map[string]bool{}
	for index, policy := range intent.Policies {
		if !validName(policy.ID) || !validName(policy.Name) || policy.MaxHops < 0 || policy.MaxHops > 2 ||
			index > 0 && intent.Policies[index-1].ID >= policy.ID {
			return errors.New("network policies are not uniquely sorted")
		}
		if err := validateSortedNames(policy.AllowedServers, "policy servers"); err != nil {
			return err
		}
		if err := validateSortedNames(policy.AllowedExits, "policy exits"); err != nil {
			return err
		}
		if err := validateSortedNames(policy.LocalEgressDevices, "policy local egress devices"); err != nil {
			return err
		}
		if !policy.AllowDirect && len(policy.AllowedExits) == 0 && len(policy.LocalEgressDevices) == 0 {
			return errors.New("network policy has no allowed route")
		}
		for _, serverID := range policy.AllowedServers {
			node, ok := nodes[serverID]
			if !ok || node.Server == nil {
				return errors.New("network policy server is not a server node")
			}
		}
		for _, exit := range policy.AllowedExits {
			node, ok := nodes[exit]
			if !ok || node.Server == nil || !node.Server.EgressCapable || !contains(policy.AllowedServers, exit) {
				return errors.New("network policy exit is not egress capable")
			}
		}
		for _, deviceID := range policy.LocalEgressDevices {
			node, ok := nodes[deviceID]
			if !ok || node.Server == nil || !node.Server.EgressCapable || !contains(node.Roles, "access") ||
				!contains(node.Roles, "server") || !contains(policy.AllowedServers, deviceID) ||
				!contains(policy.AllowedExits, deviceID) {
				return errors.New("network policy local egress device is not an allowed hybrid exit")
			}
		}
		policies[policy.ID] = true
	}
	for index, service := range intent.Services {
		if !validName(service.ID) || !validName(service.Name) || !policies[service.Policy] ||
			index > 0 && intent.Services[index-1].ID >= service.ID {
			return errors.New("network services are invalid or not uniquely sorted")
		}
		if err := validateServiceMatchers(service.Matchers); err != nil {
			return err
		}
	}
	return nil
}

func (value NetworkImport) Validate() error {
	if !validDigest(value.RecoveryEvidenceHash) || value.Intent.Validate() != nil {
		return errors.New("network import is invalid")
	}
	return nil
}

func projectNetworkWeb(projection *Projection) {
	if projection.NetworkIntent == nil {
		return
	}
	intent := projection.NetworkIntent
	devices := make([]Device, 0, len(intent.Nodes))
	for _, node := range intent.Nodes {
		device := Device{ID: node.ID, Name: node.Name, Platform: node.Platform,
			Roles: append([]string(nil), node.Roles...), Authorized: false, Availability: "unknown",
			ExpectedComponents: append([]ComponentExpectation(nil), intent.Components...)}
		for _, override := range node.Components {
			index := sort.Search(len(device.ExpectedComponents), func(index int) bool {
				return device.ExpectedComponents[index].Name >= override.Name
			})
			if index < len(device.ExpectedComponents) && device.ExpectedComponents[index].Name == override.Name {
				device.ExpectedComponents[index] = override
			} else {
				device.ExpectedComponents = append(device.ExpectedComponents, ComponentExpectation{})
				copy(device.ExpectedComponents[index+1:], device.ExpectedComponents[index:])
				device.ExpectedComponents[index] = override
			}
		}
		if node.Server != nil {
			device.Direction = node.Server.Direction
			device.EgressCapable = node.Server.EgressCapable
			device.Endpoint = node.Server.PublicEndpoint
			device.Location = node.Server.Country
			if node.Server.City != "" {
				device.Location += " " + node.Server.City
			}
		}
		devices = append(devices, device)
	}
	links := make([]Link, 0, len(intent.Links))
	for _, link := range intent.Links {
		links = append(links, Link{ID: link.ID, From: link.From, To: link.To, Transport: link.Transport,
			Authorized: true, Availability: "unknown"})
	}
	projection.Web.Devices = devices
	projection.Web.Links = links
	projection.Web.Services = append([]Service(nil), intent.Services...)
	projection.Web.Paths = nil
	for _, authorization := range projection.DeviceAuthorizations {
		routes, _, err := projectAuthorizationRuntime(*projection, authorization)
		if err != nil {
			continue
		}
		for _, route := range routes {
			projection.Web.Paths = append(projection.Web.Paths, Path{CandidateID: route.ID, Device: authorization.DeviceID,
				Scope: route.Scope, FinalExit: route.FinalExit, Chain: append([]string(nil), route.Chain...), Availability: "unknown"})
		}
	}
	sort.Slice(projection.Web.Paths, func(i, j int) bool {
		return projection.Web.Paths[i].Device+"\x00"+projection.Web.Paths[i].CandidateID <
			projection.Web.Paths[j].Device+"\x00"+projection.Web.Paths[j].CandidateID
	})
}
