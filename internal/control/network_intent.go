package control

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Service struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Kind     string           `json:"kind"`
	Matchers []ServiceMatcher `json:"matchers"`
}

// NetworkIntent is reconstructed from signed facts. Empty unsupported
// collections mean unconfigured; every non-empty unsupported input is rejected.
type NetworkIntent struct {
	Schema               int                     `json:"schema"`
	Services             []Service               `json:"services"`
	Policies             []NetworkPolicy         `json:"policies"`
	Resources            []TransportResource     `json:"resources"`
	Links                []NetworkLink           `json:"links"`
	BusinessProbeTargets []BusinessProbeTarget   `json:"business_probe_targets"`
	DNSRecords           []undefinedNetworkValue `json:"dns_records"`
	PublicTrust          []undefinedNetworkValue `json:"public_trust"`
	ExpectedComponents   []undefinedNetworkValue `json:"expected_components"`
}

// No non-empty value of this type is valid. It preserves the already defined
// empty-array bytes without inventing fields for an undefined sub-contract.
type undefinedNetworkValue struct{}

func (undefinedNetworkValue) Validate() error {
	return errors.New("network sub-value contract is undefined")
}

type TransportResource struct {
	ID             string                 `json:"id"`
	Kind           string                 `json:"kind"`
	OwnerNodeID    string                 `json:"owner_node_id"`
	ListenerID     string                 `json:"listener_id"`
	DialHost       string                 `json:"dial_host"`
	DialPort       int                    `json:"dial_port"`
	Authentication ResourceAuthentication `json:"authentication"`
	LinkOnly       bool                   `json:"link_only,omitempty"`
}

// The containing resource kind selects one complete authentication shape.
type ResourceAuthentication struct {
	PublicKey      *string   `json:"public_key,omitempty"`
	LocalAddresses *[]string `json:"local_addresses,omitempty"`
	SPKISHA256     *string   `json:"spki_sha256,omitempty"`
	ALPN           *string   `json:"alpn,omitempty"`
	ServerName     *string   `json:"server_name,omitempty"`
	CACertificates *[]string `json:"ca_certificates,omitempty"`
}

type NetworkLink struct {
	ID              string          `json:"id"`
	FromNodeID      string          `json:"from_node_id"`
	ToNodeID        string          `json:"to_node_id"`
	ResourceID      string          `json:"resource_id"`
	FromResourceID  string          `json:"from_resource_id"`
	InitiatorNodeID string          `json:"initiator_node_id"`
	Purpose         string          `json:"purpose"`
	ProbeTarget     LinkProbeTarget `json:"probe_target"`
}

type LinkProbeTarget struct {
	ResourceID string `json:"resource_id"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Action     string `json:"action"`
}

func (resource TransportResource) Validate() error {
	for _, id := range []string{resource.ID, resource.OwnerNodeID, resource.ListenerID} {
		if ValidateID(id) != nil {
			return errors.New("transport resource identity is invalid")
		}
	}
	if resource.OwnerNodeID == "direct" || !contractHost(resource.DialHost) || resource.DialPort < 1 || resource.DialPort > 65535 {
		return errors.New("transport resource destination is invalid")
	}
	auth := resource.Authentication
	if resource.LinkOnly && resource.Kind != "hysteria2" {
		return errors.New("link_only is only defined for Hy2 listeners")
	}
	switch resource.Kind {
	case "wireguard":
		if auth.PublicKey == nil || auth.LocalAddresses == nil || *auth.LocalAddresses == nil || ValidatePublicKey(*auth.PublicKey) != nil ||
			auth.SPKISHA256 != nil || auth.ALPN != nil || auth.ServerName != nil || auth.CACertificates != nil {
			return errors.New("WireGuard authentication shape is invalid")
		}
		var previous netip.Prefix
		for index, text := range *auth.LocalAddresses {
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix.String() != text || index > 0 && (previous.Addr().Compare(prefix.Addr()) > 0 || previous.Addr() == prefix.Addr() && previous.Bits() >= prefix.Bits()) {
				return errors.New("WireGuard interface addresses are not canonical or uniquely sorted")
			}
			previous = prefix
		}
	case "tls_tunnel":
		if auth.PublicKey != nil || auth.LocalAddresses != nil || auth.CACertificates != nil || auth.SPKISHA256 == nil || auth.ALPN == nil ||
			ValidateDigest(*auth.SPKISHA256) != nil || ValidateID(*auth.ALPN) != nil || auth.ServerName != nil && !contractHost(*auth.ServerName) {
			return errors.New("TLS resource authentication shape is invalid")
		}
	case "hysteria2":
		if auth.PublicKey != nil || auth.LocalAddresses != nil || auth.SPKISHA256 != nil || auth.ALPN != nil || auth.ServerName == nil || !contractHost(*auth.ServerName) || auth.CACertificates == nil || len(*auth.CACertificates) == 0 {
			return errors.New("Hy2 authentication shape is invalid")
		}
		for index, encoded := range *auth.CACertificates {
			der, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil || base64.RawURLEncoding.EncodeToString(der) != encoded || index > 0 && (*auth.CACertificates)[index-1] >= encoded {
				return errors.New("Hy2 CA certificates are not canonical or uniquely sorted")
			}
			certificate, err := x509.ParseCertificate(der)
			if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
				return errors.New("Hy2 trust requires CA certificates with signing usage")
			}
		}
	default:
		return errors.New("transport resource kind is unsupported")
	}
	return nil
}

func (link NetworkLink) Validate() error {
	for _, id := range []string{link.ID, link.FromNodeID, link.ToNodeID, link.ResourceID, link.FromResourceID, link.InitiatorNodeID} {
		if ValidateID(id) != nil || id == "direct" {
			return errors.New("Link identity is invalid")
		}
	}
	if link.FromNodeID == link.ToNodeID || link.ResourceID == link.FromResourceID ||
		link.InitiatorNodeID != link.FromNodeID && link.InitiatorNodeID != link.ToNodeID || link.Purpose != "relay" {
		return errors.New("Link endpoints, initiator or purpose are invalid")
	}
	address, err := netip.ParseAddr(link.ProbeTarget.Host)
	if err != nil || address.Zone() != "" || address.String() != link.ProbeTarget.Host || ValidateID(link.ProbeTarget.ResourceID) != nil || link.ProbeTarget.Port < 1 || link.ProbeTarget.Port > 65535 || link.ProbeTarget.Action != "hysteria2_tls" {
		return errors.New("Link requires an exact authenticated Hy2 TLS probe through its WireGuard peer")
	}
	return nil
}

func contractHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && address.String() == host
	}
	return contractDNSName(host)
}

type NetworkPolicy struct {
	ID                 string      `json:"id"`
	Name               string      `json:"name"`
	ServiceID          string      `json:"service_id"`
	Action             string      `json:"action"`
	EntryScope         PolicyScope `json:"entry_scope"`
	RelayScope         PolicyScope `json:"relay_scope"`
	ExitScope          PolicyScope `json:"exit_scope"`
	AllowDirect        bool        `json:"allow_direct"`
	LocalEgressDevices []string    `json:"local_egress_devices"`
	MaxHops            int         `json:"max_hops,omitempty"`
}

type BusinessProbeTarget struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

func (service Service) Validate() error {
	if ValidateID(service.ID) != nil || ValidateText(service.Name) != nil || service.Kind != "internet" || len(service.Matchers) == 0 {
		return errors.New("internet Service is incomplete; other kinds require their complete contract")
	}
	for index, matcher := range service.Matchers {
		if matcher.Validate() != nil || index > 0 && !serviceMatcherLess(service.Matchers[index-1], matcher) {
			return errors.New("Service matchers are invalid or not uniquely sorted")
		}
	}
	return nil
}

func serviceMatcherLess(left, right ServiceMatcher) bool {
	return left.Kind < right.Kind || left.Kind == right.Kind && left.Value < right.Value
}

func (policy NetworkPolicy) Validate() error {
	if ValidateID(policy.ID) != nil || ValidateText(policy.Name) != nil || ValidateID(policy.ServiceID) != nil ||
		policy.Action != "allow" && policy.Action != "deny" || policy.EntryScope.Validate() != nil ||
		policy.RelayScope.Validate() != nil || policy.ExitScope.Validate() != nil || policy.MaxHops < 0 {
		return errors.New("internet Policy is invalid")
	}
	return validateContractIDs(policy.LocalEgressDevices, true)
}

func validateContractIDs(ids []string, nodes bool) error {
	if ids == nil {
		return errors.New("ID collection must be explicit")
	}
	for index, id := range ids {
		if ValidateID(id) != nil || nodes && id == "direct" || index > 0 && ids[index-1] >= id {
			return errors.New("IDs are invalid or not uniquely sorted")
		}
	}
	return nil
}

func (target BusinessProbeTarget) Validate() error {
	if ValidateID(target.ID) != nil {
		return errors.New("business probe target ID is invalid")
	}
	return ValidateHTTPSURL(target.URL)
}

// ValidateHTTPSURL verifies original authority bytes, without normalization.
func ValidateHTTPSURL(value string) error {
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == '\\' {
			return errors.New("HTTPS target must be an ASCII URL")
		}
		if value[index] == '%' && (index+2 >= len(value) || !contractUpperHex(value[index+1]) || !contractUpperHex(value[index+2])) {
			return errors.New("HTTPS target escapes are not canonical")
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Fragment != "" || strings.Contains(value, "#") || parsed.Host == "" || parsed.Path == "" || parsed.String() != value {
		return errors.New("HTTPS target is not canonical")
	}
	host := parsed.Hostname()
	address, addressErr := netip.ParseAddr(host)
	if addressErr == nil {
		if address.Zone() != "" || address.String() != host {
			return errors.New("HTTPS target IP is not canonical")
		}
	} else if !contractDNSName(host) {
		return errors.New("HTTPS target DNS name is not canonical")
	}
	port := parsed.Port()
	wantHost := host
	if addressErr == nil && address.Is6() {
		wantHost = "[" + host + "]"
	}
	if port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 || number == 443 || strconv.FormatUint(number, 10) != port {
			return errors.New("HTTPS target port is not canonical")
		}
		wantHost = net.JoinHostPort(host, port)
	}
	if parsed.Host != wantHost {
		return errors.New("HTTPS target authority is not canonical")
	}
	return nil
}

func contractUpperHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'F'
}

func EmptyNetworkIntent() NetworkIntent {
	return NetworkIntent{Schema: 3, Services: []Service{}, Policies: []NetworkPolicy{}, Resources: []TransportResource{}, Links: []NetworkLink{},
		BusinessProbeTargets: []BusinessProbeTarget{}, DNSRecords: []undefinedNetworkValue{}, PublicTrust: []undefinedNetworkValue{}, ExpectedComponents: []undefinedNetworkValue{}}
}

func (intent NetworkIntent) Validate() error {
	if intent.Schema != 3 || intent.Services == nil || intent.Policies == nil || intent.Resources == nil || intent.Links == nil ||
		intent.BusinessProbeTargets == nil || intent.DNSRecords == nil || intent.PublicTrust == nil || intent.ExpectedComponents == nil {
		return errors.New("NetworkIntent schema or explicit collections are invalid")
	}
	if len(intent.Resources)+len(intent.Links)+len(intent.DNSRecords)+len(intent.PublicTrust)+len(intent.ExpectedComponents) != 0 {
		return errors.New("non-empty resources, links, DNS, trust or component expectations require their complete contracts")
	}
	services := map[string]Service{}
	for index, service := range intent.Services {
		if service.Validate() != nil || index > 0 && intent.Services[index-1].ID >= service.ID {
			return errors.New("initial Services are invalid or not uniquely sorted")
		}
		services[service.ID] = service
	}
	for index, policy := range intent.Policies {
		service, found := services[policy.ServiceID]
		if policy.Validate() != nil || index > 0 && intent.Policies[index-1].ID >= policy.ID || !found || service.Kind != "internet" {
			return errors.New("initial Policies are invalid, unsorted or have no Service")
		}
		if policy.EntryScope.Mode == "only" || policy.RelayScope.Mode == "only" || policy.ExitScope.Mode == "only" || len(policy.LocalEgressDevices) != 0 {
			return errors.New("initial Policy references a node without ordinary responsibilities")
		}
	}
	for index, target := range intent.BusinessProbeTargets {
		if target.Validate() != nil || index > 0 && intent.BusinessProbeTargets[index-1].ID >= target.ID {
			return errors.New("initial business targets are invalid or not uniquely sorted")
		}
	}
	return nil
}
