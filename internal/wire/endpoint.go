package wire

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	DomainLinkIntent              = "loom-link-intent-v1"
	DomainListenerGeneration      = "loom-listener-generation-v2"
	DomainListenerTombstone       = "loom-listener-generation-tombstone-v1"
	DomainDistributionEndpointSet = "loom-distribution-endpoint-set-v1"
	DomainBootstrapIngressSet     = "loom-bootstrap-ingress-endpoint-set-v1"
	DomainDataIngressSet          = "loom-data-ingress-endpoint-set-v2"
	DomainControlServiceDirectory = "loom-control-service-directory-v1"
	DomainPublicAccessProfile     = "loom-server-public-access-profile-v1"
	DomainForwardResources        = "loom-forward-server-listener-resources-v1"
	DomainPortMappingIntent       = "loom-port-mapping-intent-v1"
	DomainPublicAccessState       = "loom-server-public-access-state-v1"
)

type LinkIntentDestinationV1 struct {
	DeviceID  string `json:"device_id,omitempty"`
	ServiceID string `json:"service_id,omitempty"`
}

type LinkIntentV1 struct {
	Schema               int                     `json:"schema"`
	ClusterID            string                  `json:"cluster_id"`
	LinkID               string                  `json:"link_id"`
	FromDeviceID         string                  `json:"from_device_id"`
	To                   LinkIntentDestinationV1 `json:"to"`
	Purpose              string                  `json:"purpose"`
	AllowedTransports    []string                `json:"allowed_transports"`
	Initiator            string                  `json:"initiator"`
	ListenerResourceRefs []string                `json:"listener_resource_refs"`
	CredentialRefs       []string                `json:"credential_refs"`
	RouteScope           string                  `json:"route_scope"`
	Generation           int64                   `json:"generation"`
	ParentHeadHash       string                  `json:"parent_head_hash"`
}

type ListenerGenerationV2 struct {
	Schema                  int      `json:"schema"`
	ListenerGeneration      int64    `json:"listener_generation"`
	PublishedState          string   `json:"published_state"`
	DialTargetFQDN          string   `json:"dial_target_fqdn"`
	PublicPort              int64    `json:"public_port"`
	AddressFamilies         []string `json:"address_families"`
	TransportIdentityRefs   []string `json:"transport_identity_refs"`
	CredentialGeneration    int64    `json:"credential_generation"`
	CertificateIntentHash   string   `json:"certificate_intent_hash,omitempty"`
	PublicProfileGeneration int64    `json:"public_profile_generation"`
	IntroducedRevision      int64    `json:"introduced_revision"`
	ValidFrom               string   `json:"valid_from"`
	ValidUntil              string   `json:"valid_until"`
	RetireNotBefore         string   `json:"retire_not_before,omitempty"`
	RotationOperationHash   string   `json:"rotation_operation_hash"`
}

type ListenerGenerationTombstoneV1 struct {
	Schema                     int    `json:"schema"`
	ListenerGeneration         int64  `json:"listener_generation"`
	TerminalState              string `json:"terminal_state"`
	TerminalAt                 string `json:"terminal_at"`
	Reason                     string `json:"reason"`
	RotationOperationHash      string `json:"rotation_operation_hash"`
	LastListenerGenerationHash string `json:"last_listener_generation_hash"`
}

type DistributionEndpointV1 struct {
	EndpointID             string                          `json:"endpoint_id"`
	LogicalServerID        string                          `json:"logical_server_id"`
	Transport              string                          `json:"transport"`
	DistributionPathPrefix string                          `json:"distribution_path_prefix"`
	ListenerGenerations    []ListenerGenerationV2          `json:"listener_generations"`
	ListenerTombstones     []ListenerGenerationTombstoneV1 `json:"listener_tombstones"`
}

type DistributionEndpointSetV1 struct {
	Schema         int                      `json:"schema"`
	ClusterID      string                   `json:"cluster_id"`
	EndpointSetID  string                   `json:"endpoint_set_id"`
	Generation     int64                    `json:"generation"`
	ValidFrom      string                   `json:"valid_from"`
	ValidUntil     string                   `json:"valid_until"`
	Endpoints      []DistributionEndpointV1 `json:"endpoints"`
	ParentHeadHash string                   `json:"parent_head_hash"`
	ConfigQC       json.RawMessage          `json:"config_qc"`
}

type BootstrapIngressEndpointV1 struct {
	EndpointID          string                          `json:"endpoint_id"`
	LogicalServerID     string                          `json:"logical_server_id"`
	Transport           string                          `json:"transport"`
	HintRank            int64                           `json:"hint_rank"`
	ListenerGenerations []ListenerGenerationV2          `json:"listener_generations"`
	ListenerTombstones  []ListenerGenerationTombstoneV1 `json:"listener_tombstones"`
}

type BootstrapIngressEndpointSetV1 struct {
	Schema         int                          `json:"schema"`
	ClusterID      string                       `json:"cluster_id"`
	EndpointSetID  string                       `json:"endpoint_set_id"`
	Generation     int64                        `json:"generation"`
	ValidFrom      string                       `json:"valid_from"`
	ValidUntil     string                       `json:"valid_until"`
	Endpoints      []BootstrapIngressEndpointV1 `json:"endpoints"`
	ParentHeadHash string                       `json:"parent_head_hash"`
	ConfigQC       json.RawMessage              `json:"config_qc"`
}

type DataIngressEndpointV2 struct {
	EndpointID          string                          `json:"endpoint_id"`
	LogicalServerID     string                          `json:"logical_server_id"`
	Transport           string                          `json:"transport"`
	ListenerGenerations []ListenerGenerationV2          `json:"listener_generations"`
	ListenerTombstones  []ListenerGenerationTombstoneV1 `json:"listener_tombstones"`
	PathCapabilities    []string                        `json:"path_capabilities"`
}

type DataIngressEndpointSetV2 struct {
	Schema         int                     `json:"schema"`
	ClusterID      string                  `json:"cluster_id"`
	EndpointSetID  string                  `json:"endpoint_set_id"`
	Generation     int64                   `json:"generation"`
	ValidFrom      string                  `json:"valid_from"`
	ValidUntil     string                  `json:"valid_until"`
	Endpoints      []DataIngressEndpointV2 `json:"endpoints"`
	GrantsRoot     string                  `json:"grants_root"`
	ParentHeadHash string                  `json:"parent_head_hash"`
	ConfigQC       json.RawMessage         `json:"config_qc"`
}

type PrivateControlServiceV1 struct {
	ServiceID                 string   `json:"service_id"`
	Role                      string   `json:"role"`
	OverlayIP                 string   `json:"overlay_ip"`
	Port                      int64    `json:"port"`
	CertificateProfileRef     string   `json:"certificate_profile_ref"`
	SPKIPins                  []string `json:"spki_pins"`
	AuthorizedSubjectProfiles []string `json:"authorized_subject_profiles"`
}

type ControlServiceDirectoryV1 struct {
	Schema                int                       `json:"schema"`
	ClusterID             string                    `json:"cluster_id"`
	Generation            int64                     `json:"generation"`
	Services              []PrivateControlServiceV1 `json:"services"`
	ControlSetHash        string                    `json:"control_set_hash"`
	PreviousDirectoryHash string                    `json:"previous_directory_hash,omitempty"`
	ParentHeadHash        string                    `json:"parent_head_hash"`
	ConfigQC              json.RawMessage           `json:"config_qc"`
}

type ServerPublicAccessProfileV1 struct {
	Schema                       int      `json:"schema"`
	ClusterID                    string   `json:"cluster_id"`
	ServerID                     string   `json:"server_id"`
	Generation                   int64    `json:"generation"`
	FQDN                         string   `json:"fqdn"`
	DNSZoneRef                   string   `json:"dns_zone_ref"`
	AddressFamilyPolicy          string   `json:"address_family_policy"`
	HTTPSPublicPort              int64    `json:"https_public_port"`
	DeploymentKind               string   `json:"deployment_kind"`
	PublicFrontendAddresses      []string `json:"public_frontend_addresses"`
	CertificateProfileRef        string   `json:"certificate_profile_ref"`
	ForwardListenerResourcesHash string   `json:"forward_listener_resources_hash"`
}

type PortMappingIntentV1 struct {
	Schema            int    `json:"schema"`
	MappingID         string `json:"mapping_id"`
	Transport         string `json:"transport"`
	PublicAddress     string `json:"public_address"`
	PublicPortStart   int64  `json:"public_port_start"`
	PublicPortEnd     int64  `json:"public_port_end"`
	LocalAddress      string `json:"local_address"`
	LocalPortStart    int64  `json:"local_port_start"`
	LocalPortEnd      int64  `json:"local_port_end"`
	MappingGeneration int64  `json:"mapping_generation"`
}

type ForwardServerListenerResourcesV1 struct {
	Schema                 int                   `json:"schema"`
	ClusterID              string                `json:"cluster_id"`
	ServerID               string                `json:"server_id"`
	Generation             int64                 `json:"generation"`
	NginxLocalTCPPort      int64                 `json:"nginx_local_tcp_port"`
	HY2LocalUDPPortPool    []int64               `json:"hy2_local_udp_port_pool"`
	WireGuardLocalUDPPorts []int64               `json:"wireguard_local_udp_ports"`
	TrojanLocalTCPPortPool []int64               `json:"trojan_local_tcp_port_pool"`
	Mappings               []PortMappingIntentV1 `json:"mappings"`
}

// ServerPublicAccessStateV1 是 certified intent 与验证证据的派生投影；调用方不能
// 仅凭 DNS/provider readback 把 preparing 提升为 active（D103、D125）。
type ServerPublicAccessStateV1 struct {
	Schema                      int    `json:"schema"`
	ClusterID                   string `json:"cluster_id"`
	ServerID                    string `json:"server_id"`
	Generation                  int64  `json:"generation"`
	PublicAccessProfileHash     string `json:"public_access_profile_hash"`
	Status                      string `json:"status"`
	LastVerifiedObservationHash string `json:"last_verified_observation_hash,omitempty"`
	LastChangedHeadHash         string `json:"last_changed_head_hash"`
}

func ValidateLinkIntent(intent *LinkIntentV1) error {
	if intent == nil || intent.Schema != 1 || !validIdentifier(intent.ClusterID, 128) ||
		!validIdentifier(intent.LinkID, 128) || !validIdentifier(intent.FromDeviceID, 128) ||
		intent.Generation < 1 || !oneOf(intent.Purpose, "control_overlay", "data_forward", "bootstrap") ||
		!oneOf(intent.Initiator, "from", "to") {
		return errors.New("[D131 LinkIntent] schema/identity/purpose/initiator 无效")
	}
	if (intent.To.DeviceID == "") == (intent.To.ServiceID == "") {
		return errors.New("[D131 LinkIntent] to 必须且只能选择 device_id/service_id")
	}
	if !sortedEnum(intent.AllowedTransports, []string{"wireguard", "hysteria2", "trojan_tls"}, true) ||
		!sortedUnique(intent.ListenerResourceRefs) || !sortedUnique(intent.CredentialRefs) {
		return errors.New("[D131 LinkIntent] transports/refs 必须按规范稳定排序且不重复")
	}
	if intent.Purpose == "bootstrap" && contains(intent.AllowedTransports, "wireguard") {
		return errors.New("[D131 LinkIntent] 首版 bootstrap 明确不支持 WireGuard")
	}
	_, err := ParseHash(intent.ParentHeadHash)
	return err
}

func ValidateListenerGeneration(generation *ListenerGenerationV2, transport string) error {
	if generation == nil || generation.Schema != 2 || generation.ListenerGeneration < 1 ||
		!oneOf(generation.PublishedState, "advertised", "preferred", "draining") ||
		!ValidFQDN(generation.DialTargetFQDN) || generation.PublicPort < 1 || generation.PublicPort > 65535 ||
		generation.CredentialGeneration < 1 || generation.PublicProfileGeneration < 1 || generation.IntroducedRevision < 1 ||
		!sortedEnum(generation.AddressFamilies, []string{"ipv4", "ipv6"}, true) ||
		!sortedUnique(generation.TransportIdentityRefs) || len(generation.TransportIdentityRefs) == 0 {
		return errors.New("[D107 EndpointSet] listener generation 字段无效")
	}
	from, err := ParseTimeZ(generation.ValidFrom)
	if err != nil {
		return err
	}
	until, err := ParseTimeZ(generation.ValidUntil)
	if err != nil || !from.Before(until) {
		return errors.New("[D107 EndpointSet] listener validity 无效")
	}
	if generation.RetireNotBefore != "" {
		retire, err := ParseTimeZ(generation.RetireNotBefore)
		if err != nil || retire.Before(from) {
			return errors.New("[D120 rotation] retire_not_before 无效")
		}
	}
	if oneOf(transport, "https", "hysteria2", "trojan_tls") {
		if _, err := ParseHash(generation.CertificateIntentHash); err != nil {
			return errors.New("[D122 TLS] TLS transport 必须绑定 certificate intent hash")
		}
	} else if transport == "wireguard" {
		if generation.CertificateIntentHash != "" {
			return errors.New("[D107 EndpointSet] WireGuard listener 禁止 certificate_intent_hash")
		}
	} else {
		return errors.New("[D107 EndpointSet] transport 无效")
	}
	_, err = ParseHash(generation.RotationOperationHash)
	return err
}

func validateGenerations(transport string, generations []ListenerGenerationV2, tombstones []ListenerGenerationTombstoneV1) error {
	preferred := 0
	seen := make(map[int64]struct{}, len(generations)+len(tombstones))
	for i := range generations {
		if err := ValidateListenerGeneration(&generations[i], transport); err != nil {
			return err
		}
		if i > 0 && generations[i-1].ListenerGeneration >= generations[i].ListenerGeneration {
			return errors.New("[D120 rotation] listener generations 必须严格递增")
		}
		seen[generations[i].ListenerGeneration] = struct{}{}
		if generations[i].PublishedState == "preferred" {
			preferred++
		}
	}
	for i := range tombstones {
		tombstone := &tombstones[i]
		if tombstone.Schema != 1 || tombstone.ListenerGeneration < 1 ||
			!oneOf(tombstone.TerminalState, "retired", "revoked", "abandoned") || tombstone.Reason == "" {
			return errors.New("[D120 rotation] listener tombstone 无效")
		}
		if _, err := ParseTimeZ(tombstone.TerminalAt); err != nil {
			return err
		}
		if _, err := ParseHash(tombstone.RotationOperationHash); err != nil {
			return err
		}
		if _, err := ParseHash(tombstone.LastListenerGenerationHash); err != nil {
			return err
		}
		if i > 0 && tombstones[i-1].ListenerGeneration >= tombstone.ListenerGeneration {
			return errors.New("[D120 rotation] listener tombstones 必须严格递增")
		}
		if _, duplicate := seen[tombstone.ListenerGeneration]; duplicate {
			return errors.New("[D120 rotation] 同一 listener generation 不能同时可拨和 tombstone")
		}
		seen[tombstone.ListenerGeneration] = struct{}{}
	}
	if len(generations) > 0 && preferred != 1 {
		return errors.New("[D120 rotation] 可拨 logical endpoint 必须恰有一个 preferred generation")
	}
	return nil
}

func ValidateDistributionEndpointSet(set *DistributionEndpointSetV1) error {
	if set == nil || set.Schema != 1 || len(set.Endpoints) == 0 ||
		!validateSetHeader(set.ClusterID, set.EndpointSetID, set.Generation, set.ValidFrom, set.ValidUntil, set.ParentHeadHash) {
		return errors.New("[D107 EndpointSet] distribution set header 无效")
	}
	if err := validateConfigQCShape(set.ConfigQC); err != nil {
		return err
	}
	for i := range set.Endpoints {
		endpoint := &set.Endpoints[i]
		if !orderedEndpoint(i, endpoint.EndpointID, set.Endpoints, func(item DistributionEndpointV1) string { return item.EndpointID }) ||
			endpoint.Transport != "https" || endpoint.DistributionPathPrefix != "/distribution/sha256/" ||
			!validIdentifier(endpoint.LogicalServerID, 128) {
			return errors.New("[D131 public surface] distribution endpoint 无效/未排序")
		}
		if err := validateGenerations(endpoint.Transport, endpoint.ListenerGenerations, endpoint.ListenerTombstones); err != nil {
			return err
		}
	}
	return nil
}

func ValidateBootstrapIngressSet(set *BootstrapIngressEndpointSetV1) error {
	if set == nil || set.Schema != 1 || len(set.Endpoints) == 0 ||
		!validateSetHeader(set.ClusterID, set.EndpointSetID, set.Generation, set.ValidFrom, set.ValidUntil, set.ParentHeadHash) {
		return errors.New("[D107 EndpointSet] bootstrap set header 无效")
	}
	if err := validateConfigQCShape(set.ConfigQC); err != nil {
		return err
	}
	for i := range set.Endpoints {
		endpoint := &set.Endpoints[i]
		if !orderedEndpoint(i, endpoint.EndpointID, set.Endpoints, func(item BootstrapIngressEndpointV1) string { return item.EndpointID }) ||
			!oneOf(endpoint.Transport, "hysteria2", "trojan_tls") || endpoint.HintRank < 0 ||
			!validIdentifier(endpoint.LogicalServerID, 128) {
			return errors.New("[D131 bootstrap] bootstrap endpoint 无效/未排序")
		}
		if err := validateGenerations(endpoint.Transport, endpoint.ListenerGenerations, endpoint.ListenerTombstones); err != nil {
			return err
		}
	}
	return nil
}

func ValidateDataIngressSet(set *DataIngressEndpointSetV2) error {
	if set == nil || set.Schema != 2 || len(set.Endpoints) == 0 ||
		!validateSetHeader(set.ClusterID, set.EndpointSetID, set.Generation, set.ValidFrom, set.ValidUntil, set.ParentHeadHash) {
		return errors.New("[D107 EndpointSet] data set header 无效")
	}
	if err := validateConfigQCShape(set.ConfigQC); err != nil {
		return err
	}
	if _, err := ParseHash(set.GrantsRoot); err != nil {
		return err
	}
	for i := range set.Endpoints {
		endpoint := &set.Endpoints[i]
		if !orderedEndpoint(i, endpoint.EndpointID, set.Endpoints, func(item DataIngressEndpointV2) string { return item.EndpointID }) ||
			!oneOf(endpoint.Transport, "hysteria2", "trojan_tls", "wireguard") ||
			!validIdentifier(endpoint.LogicalServerID, 128) || !sortedUnique(endpoint.PathCapabilities) {
			return errors.New("[D107 EndpointSet] data endpoint 无效/未排序")
		}
		if err := validateGenerations(endpoint.Transport, endpoint.ListenerGenerations, endpoint.ListenerTombstones); err != nil {
			return err
		}
	}
	return nil
}

func ValidateControlServiceDirectory(directory *ControlServiceDirectoryV1) error {
	if directory == nil || directory.Schema != 1 || !validIdentifier(directory.ClusterID, 128) ||
		directory.Generation < 1 || len(directory.Services) == 0 {
		return errors.New("[D131 private control] directory header 无效")
	}
	if err := validateConfigQCShape(directory.ConfigQC); err != nil {
		return err
	}
	for _, hash := range []string{directory.ControlSetHash, directory.ParentHeadHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	if directory.PreviousDirectoryHash != "" {
		if _, err := ParseHash(directory.PreviousDirectoryHash); err != nil {
			return err
		}
	}
	for i, service := range directory.Services {
		if i > 0 && directory.Services[i-1].ServiceID >= service.ServiceID {
			return errors.New("[D131 private control] services 必须严格排序且不重复")
		}
		address, err := netip.ParseAddr(service.OverlayIP)
		if err != nil || address.String() != service.OverlayIP || !address.IsPrivate() ||
			service.Port < 1 || service.Port > 65535 ||
			!oneOf(service.Role, "control_api", "enroll", "device_config", "device_report") ||
			!validIdentifier(service.ServiceID, 128) || !sortedUnique(service.SPKIPins) || len(service.SPKIPins) == 0 ||
			!sortedUnique(service.AuthorizedSubjectProfiles) || len(service.AuthorizedSubjectProfiles) == 0 {
			return errors.New("[D131 private control] service 必须使用私有 overlay tuple 和用途隔离 profile")
		}
	}
	return nil
}

func ValidatePublicAccess(profile *ServerPublicAccessProfileV1, resources *ForwardServerListenerResourcesV1) error {
	if profile == nil || resources == nil || profile.Schema != 1 || resources.Schema != 1 ||
		profile.ClusterID != resources.ClusterID || profile.ServerID != resources.ServerID || profile.Generation != resources.Generation ||
		!validIdentifier(profile.ClusterID, 128) || !validIdentifier(profile.ServerID, 128) || profile.Generation < 1 ||
		!ValidFQDN(profile.FQDN) || profile.HTTPSPublicPort < 1 || profile.HTTPSPublicPort > 65535 ||
		!validIdentifier(profile.DNSZoneRef, 128) || !validIdentifier(profile.CertificateProfileRef, 128) ||
		!oneOf(profile.AddressFamilyPolicy, "ipv4_only", "ipv6_only", "dual_stack") ||
		!oneOf(profile.DeploymentKind, "direct_standard", "direct_alternate", "nat_mapped") ||
		resources.NginxLocalTCPPort < 1 || resources.NginxLocalTCPPort > 65535 {
		return errors.New("[D103 public profile] profile/resources 字段或绑定无效")
	}
	if profile.DeploymentKind == "direct_standard" && profile.HTTPSPublicPort != 443 {
		return errors.New("[D103 public profile] direct_standard 必须使用 HTTPS 443")
	}
	if profile.DeploymentKind == "direct_alternate" && profile.HTTPSPublicPort == 443 {
		return errors.New("[D103 public profile] direct_alternate 必须显式使用替代端口")
	}
	if !sortedUnique(profile.PublicFrontendAddresses) || len(profile.PublicFrontendAddresses) == 0 {
		return errors.New("[D103 public profile] public frontend addresses 缺失/未排序")
	}
	hasIPv4, hasIPv6 := false, false
	for _, raw := range profile.PublicFrontendAddresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.String() != raw || !address.IsGlobalUnicast() {
			return errors.New("[D103 public profile] public frontend address 无效")
		}
		hasIPv4 = hasIPv4 || address.Is4()
		hasIPv6 = hasIPv6 || address.Is6()
	}
	if profile.AddressFamilyPolicy == "ipv4_only" && (!hasIPv4 || hasIPv6) ||
		profile.AddressFamilyPolicy == "ipv6_only" && (!hasIPv6 || hasIPv4) ||
		profile.AddressFamilyPolicy == "dual_stack" && (!hasIPv4 || !hasIPv6) {
		return errors.New("[D103 public profile] address family policy 与 frontend addresses 不一致")
	}
	if err := ValidateForwardServerListenerResources(resources); err != nil {
		return err
	}
	if profile.DeploymentKind == "nat_mapped" && len(resources.Mappings) == 0 {
		return errors.New("[D103 public profile] nat_mapped 必须声明映射")
	}
	if profile.DeploymentKind != "nat_mapped" && len(resources.Mappings) != 0 {
		return errors.New("[D103 public profile] direct profile 禁止伪造 NAT mapping")
	}
	if profile.DeploymentKind == "nat_mapped" {
		if !mappingContains(resources.Mappings, "tcp", profile.HTTPSPublicPort, resources.NginxLocalTCPPort) {
			return errors.New("[D103 NAT] HTTPS public/local tuple 缺 exact mapping")
		}
		for _, port := range resources.HY2LocalUDPPortPool {
			if !mappingContainsLocal(resources.Mappings, "udp", port) {
				return errors.New("[D103 NAT] HY2 local listener 缺 UDP mapping")
			}
		}
		for _, port := range resources.WireGuardLocalUDPPorts {
			if !mappingContainsLocal(resources.Mappings, "udp", port) {
				return errors.New("[D103 NAT] WireGuard local listener 缺 UDP mapping")
			}
		}
		for _, port := range resources.TrojanLocalTCPPortPool {
			if !mappingContainsLocal(resources.Mappings, "tcp", port) {
				return errors.New("[D103 NAT] Trojan local listener 缺 TCP mapping")
			}
		}
	}
	resourcesHash, err := HashObject(DomainForwardResources, resources)
	if err != nil || resourcesHash != profile.ForwardListenerResourcesHash {
		return errors.New("[D125 dependency] forward listener resources hash 不匹配")
	}
	return nil
}

func ValidateForwardServerListenerResources(resources *ForwardServerListenerResourcesV1) error {
	if resources == nil || resources.Schema != 1 || !validIdentifier(resources.ClusterID, 128) ||
		!validIdentifier(resources.ServerID, 128) || resources.Generation < 1 ||
		resources.NginxLocalTCPPort < 1 || resources.NginxLocalTCPPort > 65535 {
		return errors.New("[D103 public profile] private listener resources header 无效")
	}
	if err := validatePorts(resources.HY2LocalUDPPortPool, "HY2"); err != nil {
		return err
	}
	if err := validatePorts(resources.WireGuardLocalUDPPorts, "WireGuard"); err != nil {
		return err
	}
	if err := validatePorts(resources.TrojanLocalTCPPortPool, "Trojan"); err != nil {
		return err
	}
	if len(resources.HY2LocalUDPPortPool) == 0 || len(resources.WireGuardLocalUDPPorts) == 0 || len(resources.TrojanLocalTCPPortPool) == 0 {
		return errors.New("[D103 public profile] active forward 缺少 HY2/WG/Trojan listener 资源")
	}
	if overlap(resources.HY2LocalUDPPortPool, resources.WireGuardLocalUDPPorts) {
		return errors.New("[D103 tuple] HY2 与 WireGuard 不能占用同一 UDP tuple")
	}
	if containsPort(resources.TrojanLocalTCPPortPool, resources.NginxLocalTCPPort) {
		return errors.New("[D103 tuple] Nginx 与 Trojan 不能占用同一 TCP tuple（未声明 L4 SNI dispatcher）")
	}
	for i := range resources.Mappings {
		if i > 0 && resources.Mappings[i-1].MappingID >= resources.Mappings[i].MappingID {
			return errors.New("[D103 public profile] mappings 必须按 ID 严格排序")
		}
		if err := ValidatePortMapping(&resources.Mappings[i]); err != nil {
			return err
		}
		for j := 0; j < i; j++ {
			if mappingsOverlap(resources.Mappings[j], resources.Mappings[i]) {
				return errors.New("[D103 NAT] mapping public/local range 重叠")
			}
		}
	}
	return nil
}

func ValidateServerPublicAccessState(state *ServerPublicAccessStateV1) error {
	if state == nil || state.Schema != 1 || !validIdentifier(state.ClusterID, 128) ||
		!validIdentifier(state.ServerID, 128) || state.Generation < 1 ||
		!oneOf(state.Status, "preparing", "active", "draining", "disabled") {
		return errors.New("[D103 public profile] public access state header/status 无效")
	}
	for _, hash := range []string{state.PublicAccessProfileHash, state.LastChangedHeadHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	if state.Status == "active" && state.LastVerifiedObservationHash == "" {
		return errors.New("[D125 reconcile] active public access 缺 external verification evidence")
	}
	if state.LastVerifiedObservationHash != "" {
		if _, err := ParseHash(state.LastVerifiedObservationHash); err != nil {
			return err
		}
	}
	return nil
}

func ServerPublicAccessProfileHash(value *ServerPublicAccessProfileV1, resources *ForwardServerListenerResourcesV1) (string, error) {
	if err := ValidatePublicAccess(value, resources); err != nil {
		return "", err
	}
	return HashObject(DomainPublicAccessProfile, value)
}

func ForwardServerListenerResourcesHash(value *ForwardServerListenerResourcesV1) (string, error) {
	if err := ValidateForwardServerListenerResources(value); err != nil {
		return "", err
	}
	return HashObject(DomainForwardResources, value)
}

func PortMappingIntentHash(value *PortMappingIntentV1) (string, error) {
	if err := ValidatePortMapping(value); err != nil {
		return "", err
	}
	return HashObject(DomainPortMappingIntent, value)
}

func ServerPublicAccessStateHash(value *ServerPublicAccessStateV1) (string, error) {
	if err := ValidateServerPublicAccessState(value); err != nil {
		return "", err
	}
	return HashObject(DomainPublicAccessState, value)
}

func ValidatePortMapping(mapping *PortMappingIntentV1) error {
	if mapping == nil || mapping.Schema != 1 || !validIdentifier(mapping.MappingID, 128) ||
		!oneOf(mapping.Transport, "tcp", "udp") || mapping.MappingGeneration < 1 ||
		mapping.PublicPortStart < 1 || mapping.PublicPortEnd > 65535 || mapping.PublicPortStart > mapping.PublicPortEnd ||
		mapping.LocalPortStart < 1 || mapping.LocalPortEnd > 65535 || mapping.LocalPortStart > mapping.LocalPortEnd ||
		mapping.PublicPortEnd-mapping.PublicPortStart != mapping.LocalPortEnd-mapping.LocalPortStart {
		return errors.New("[D103 NAT] mapping transport/range/generation 无效")
	}
	public, err := netip.ParseAddr(mapping.PublicAddress)
	if err != nil || public.String() != mapping.PublicAddress || !public.IsGlobalUnicast() {
		return errors.New("[D103 NAT] public address 无效")
	}
	local, err := netip.ParseAddr(mapping.LocalAddress)
	if err != nil || local.String() != mapping.LocalAddress || !local.IsPrivate() {
		return errors.New("[D103 NAT] local address 必须是规范私有地址")
	}
	return nil
}

func ValidFQDN(value string) bool {
	if len(value) < 3 || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil && address.IsValid() {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func ListenerGenerationHash(value *ListenerGenerationV2, transport string) (string, error) {
	if err := ValidateListenerGeneration(value, transport); err != nil {
		return "", err
	}
	return HashObject(DomainListenerGeneration, value)
}

func DistributionEndpointSetHash(value *DistributionEndpointSetV1) (string, error) {
	if err := ValidateDistributionEndpointSet(value); err != nil {
		return "", err
	}
	return HashObject(DomainDistributionEndpointSet, value)
}

func BootstrapIngressSetHash(value *BootstrapIngressEndpointSetV1) (string, error) {
	if err := ValidateBootstrapIngressSet(value); err != nil {
		return "", err
	}
	return HashObject(DomainBootstrapIngressSet, value)
}

func DataIngressSetHash(value *DataIngressEndpointSetV2) (string, error) {
	if err := ValidateDataIngressSet(value); err != nil {
		return "", err
	}
	return HashObject(DomainDataIngressSet, value)
}

func ControlServiceDirectoryHash(value *ControlServiceDirectoryV1) (string, error) {
	if err := ValidateControlServiceDirectory(value); err != nil {
		return "", err
	}
	return HashObject(DomainControlServiceDirectory, value)
}

// VerifyConfigQCAuthority 验证 EndpointSet/private directory 所携 parent-head QC。
// previousSet 仅在 joint QC 时允许且必需，不能把两侧 signer 合并计数（D112）。
func VerifyConfigQCAuthority(parentHeadHash string, raw json.RawMessage, head *HeadEntryV2, currentSet, previousSet *ControlSetV1) error {
	if head == nil || head.HeadHash != parentHeadHash {
		return errors.New("[D107 EndpointSet] config QC 未绑定 exact parent head")
	}
	qcType, err := configQCType(raw)
	if err != nil {
		return err
	}
	switch qcType {
	case "stable_head":
		if previousSet != nil {
			return errors.New("[D112 joint] stable QC 禁止附带 previous ControlSet")
		}
		var qc StableHeadReplicationQCV1
		if _, err := DecodeStrict(raw, 4<<20, &qc); err != nil {
			return err
		}
		return VerifyStableHeadQC(head, currentSet, &qc)
	case "joint_head":
		if previousSet == nil {
			return errors.New("[D112 joint] joint QC 缺 previous ControlSet")
		}
		var qc JointHeadReplicationQCV1
		if _, err := DecodeStrict(raw, 4<<20, &qc); err != nil {
			return err
		}
		return VerifyJointHeadQC(head, previousSet, currentSet, &qc)
	default:
		return errors.New("[D107 EndpointSet] config QC type 未获协议授权")
	}
}

func validateConfigQCShape(raw json.RawMessage) error {
	qcType, err := configQCType(raw)
	if err != nil {
		return errors.New("[D107 EndpointSet] config_qc 缺失或 wire 无效")
	}
	switch qcType {
	case "stable_head":
		var qc StableHeadReplicationQCV1
		if _, err := DecodeStrict(raw, 4<<20, &qc); err != nil {
			return errors.New("[D107 EndpointSet] stable config_qc wire 无效")
		}
	case "joint_head":
		var qc JointHeadReplicationQCV1
		if _, err := DecodeStrict(raw, 4<<20, &qc); err != nil {
			return errors.New("[D107 EndpointSet] joint config_qc wire 无效")
		}
	default:
		return errors.New("[D107 EndpointSet] config_qc schema/type 无效")
	}
	return nil
}

func configQCType(raw json.RawMessage) (string, error) {
	canonical, err := CanonicalizeStrict(raw)
	if err != nil || len(canonical) > 4<<20 {
		return "", errors.New("[D107 EndpointSet] config_qc JSON 无效")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &object); err != nil {
		return "", errors.New("[D107 EndpointSet] config_qc 必须是 object")
	}
	var schema int
	var qcType string
	if err := json.Unmarshal(object["schema"], &schema); err != nil || schema != 1 {
		return "", errors.New("[D107 EndpointSet] config_qc schema 无效")
	}
	if err := json.Unmarshal(object["qc_type"], &qcType); err != nil {
		return "", errors.New("[D107 EndpointSet] config_qc type 无效")
	}
	return qcType, nil
}

func validateSetHeader(cluster, setID string, generation int64, fromRaw, untilRaw, parentHash string) bool {
	if !validIdentifier(cluster, 128) || !validIdentifier(setID, 128) || generation < 1 {
		return false
	}
	from, err := ParseTimeZ(fromRaw)
	if err != nil {
		return false
	}
	until, err := ParseTimeZ(untilRaw)
	if err != nil || !from.Before(until) {
		return false
	}
	_, err = ParseHash(parentHash)
	return err == nil
}

func sortedUnique(values []string) bool {
	for i, value := range values {
		if value == "" || (i > 0 && values[i-1] >= value) {
			return false
		}
	}
	return true
}

func sortedEnum(values, order []string, nonempty bool) bool {
	if nonempty && len(values) == 0 {
		return false
	}
	position := make(map[string]int, len(order))
	for i, value := range order {
		position[value] = i
	}
	previous := -1
	for _, value := range values {
		current, ok := position[value]
		if !ok || current <= previous {
			return false
		}
		previous = current
	}
	return true
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func orderedEndpoint[T any](index int, current string, values []T, id func(T) string) bool {
	return validIdentifier(current, 128) && (index == 0 || id(values[index-1]) < current)
}

func validatePorts(ports []int64, name string) error {
	for i, port := range ports {
		if port < 1 || port > 65535 || (i > 0 && ports[i-1] >= port) {
			return fmt.Errorf("[D103 tuple] %s ports 无效/未排序", name)
		}
	}
	return nil
}

func overlap(left, right []int64) bool {
	seen := make(map[int64]struct{}, len(left))
	for _, value := range left {
		seen[value] = struct{}{}
	}
	for _, value := range right {
		if _, found := seen[value]; found {
			return true
		}
	}
	return false
}

func containsPort(values []int64, port int64) bool {
	for _, value := range values {
		if value == port {
			return true
		}
	}
	return false
}

func mappingsOverlap(left, right PortMappingIntentV1) bool {
	publicOverlap := left.Transport == right.Transport && left.PublicAddress == right.PublicAddress &&
		rangesOverlap(left.PublicPortStart, left.PublicPortEnd, right.PublicPortStart, right.PublicPortEnd)
	localOverlap := left.Transport == right.Transport && left.LocalAddress == right.LocalAddress &&
		rangesOverlap(left.LocalPortStart, left.LocalPortEnd, right.LocalPortStart, right.LocalPortEnd)
	return publicOverlap || localOverlap
}

func rangesOverlap(leftStart, leftEnd, rightStart, rightEnd int64) bool {
	return leftStart <= rightEnd && rightStart <= leftEnd
}

func mappingContains(mappings []PortMappingIntentV1, transport string, publicPort, localPort int64) bool {
	for _, mapping := range mappings {
		if mapping.Transport == transport && publicPort >= mapping.PublicPortStart && publicPort <= mapping.PublicPortEnd &&
			localPort == mapping.LocalPortStart+publicPort-mapping.PublicPortStart {
			return true
		}
	}
	return false
}

func mappingContainsLocal(mappings []PortMappingIntentV1, transport string, localPort int64) bool {
	for _, mapping := range mappings {
		if mapping.Transport == transport && localPort >= mapping.LocalPortStart && localPort <= mapping.LocalPortEnd {
			return true
		}
	}
	return false
}
