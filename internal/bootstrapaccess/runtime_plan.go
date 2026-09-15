package bootstrapaccess

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"loom/internal/rotation"
	"loom/internal/wire"
)

const domainBootstrapListenerRuntimeBinding = "loom-bootstrap-listener-runtime-binding-v1"

type bootstrapListenerRuntimeProjectionV1 struct {
	Schema             int              `json:"schema"`
	ClusterID          string           `json:"cluster_id"`
	IngressSetHash     string           `json:"ingress_set_hash"`
	EndpointSetID      string           `json:"endpoint_set_id"`
	EndpointID         string           `json:"endpoint_id"`
	LogicalServerID    string           `json:"logical_server_id"`
	Transport          string           `json:"transport"`
	ListenerGeneration int64            `json:"listener_generation"`
	ListenerState      string           `json:"listener_state"`
	ServerName         string           `json:"server_name"`
	PublicPort         int64            `json:"public_port"`
	BindTuple          rotation.Tuple   `json:"bind_tuple"`
	PublicTuples       []rotation.Tuple `json:"public_tuples"`
	SPKIPins           []string         `json:"spki_pins"`
	ValidFrom          string           `json:"valid_from"`
	ValidUntil         string           `json:"valid_until"`
}

// VerifiedBootstrapListenerV1 只由 BuildBootstrapIngressRuntimePlan 从
// certified catalog、QC、PublicAccessProfile 与 durable rotation ownership
// 联合产生。字段保持私有，transport server 不能接受手写 listen/name/pin。
type VerifiedBootstrapListenerV1 struct {
	projection  bootstrapListenerRuntimeProjectionV1
	bindingHash string
}

type BootstrapIngressRuntimePlanV1 struct {
	bindings []VerifiedBootstrapListenerV1
}

// Bindings 返回每个必须创建的本地 socket capability。值本身不可由包外构造，
// 因此选择其中一个不会扩大 frozen execution plan 的 tuple 集合。
func (plan BootstrapIngressRuntimePlanV1) Bindings() []VerifiedBootstrapListenerV1 {
	return append([]VerifiedBootstrapListenerV1(nil), plan.bindings...)
}

func (verified VerifiedBootstrapListenerV1) Transport() string {
	return verified.projection.Transport
}

func (verified VerifiedBootstrapListenerV1) ServerName() string {
	return verified.projection.ServerName
}

func (verified VerifiedBootstrapListenerV1) Tuple() rotation.Tuple {
	return verified.projection.BindTuple
}

// PublicTuples 返回该本地 socket 经 direct/NAT binding 实际服务的 certified
// public tuple；外部 verifier 只探测这些精确地址，不做 DNS 扩张或邻近端口扫描。
func (verified VerifiedBootstrapListenerV1) PublicTuples() []rotation.Tuple {
	return append([]rotation.Tuple(nil), verified.projection.PublicTuples...)
}

func (verified VerifiedBootstrapListenerV1) ListenerGeneration() int64 {
	return verified.projection.ListenerGeneration
}

func (verified VerifiedBootstrapListenerV1) IngressSetHash() string {
	return verified.projection.IngressSetHash
}

// BuildBootstrapIngressRuntimePlan 不自行分配端口，也不相信本机 listen 配置。
// expected EndpointSet hash 来自已重放的 rotation intent；catalog 的 parent Head/QC
// 证明其 authority lineage；最终本地 tuple 必须已在 durable frozen plan 中拥有。
func BuildBootstrapIngressRuntimePlan(catalog *wire.BootstrapEndpointCatalogV1,
	parentHead *wire.HeadEntryV2, currentSet, previousSet *wire.ControlSetV1,
	authorized rotation.AuthorizedRuntimePlanV1, profile *wire.ServerPublicAccessProfileV1,
	resources *wire.ForwardServerListenerResourcesV1, endpointID string,
	listenerGeneration int64, trustedTime time.Time, serverProtocol int64) (BootstrapIngressRuntimePlanV1, error) {
	if catalog == nil || parentHead == nil || currentSet == nil || profile == nil || resources == nil ||
		endpointID == "" || listenerGeneration < 1 || trustedTime.IsZero() || serverProtocol < 2 {
		return BootstrapIngressRuntimePlanV1{}, errors.New("[bootstrap runtime] authority/identity/可信时间输入不完整")
	}
	if err := wire.ValidateBootstrapEndpointCatalog(catalog); err != nil {
		return BootstrapIngressRuntimePlanV1{}, err
	}
	if serverProtocol < catalog.RequiredClientProtocol {
		return BootstrapIngressRuntimePlanV1{}, errors.New("[bootstrap runtime] server protocol 低于 catalog reader contract")
	}
	if err := wire.VerifyConfigQCAuthority(catalog.ParentHeadHash, catalog.BootstrapIngressSet.ConfigQC,
		parentHead, currentSet, previousSet); err != nil {
		return BootstrapIngressRuntimePlanV1{}, err
	}
	intent := authorized.Intent()
	dependency := intent.FrozenDependencies
	if intent.Schema != 1 || dependency.Schema != 1 || dependency.EndpointKind != "bootstrap" ||
		intent.ExpectedEndpointSetHash != catalog.BootstrapIngressSetHash ||
		dependency.EndpointSetID != catalog.BootstrapIngressSet.EndpointSetID ||
		dependency.EndpointID != endpointID || dependency.TargetListenerGeneration < 1 ||
		dependency.ClusterID != catalog.ClusterID || intent.ClusterID != catalog.ClusterID {
		return BootstrapIngressRuntimePlanV1{}, errors.New("[bootstrap runtime] catalog 未绑定 exact certified rotation intent")
	}
	profileHash, err := wire.ServerPublicAccessProfileHash(profile, resources)
	if err != nil {
		return BootstrapIngressRuntimePlanV1{}, err
	}
	resourcesHash, err := wire.ForwardServerListenerResourcesHash(resources)
	if err != nil || profileHash != dependency.PublicAccessProfileHash ||
		resourcesHash != dependency.ForwardListenerResourceGenerationHash {
		return BootstrapIngressRuntimePlanV1{}, errors.New("[bootstrap runtime] public profile/resources 未绑定 frozen dependencies")
	}
	endpoint, listener, err := findBootstrapListener(catalog, endpointID, listenerGeneration)
	if err != nil {
		return BootstrapIngressRuntimePlanV1{}, err
	}
	if endpoint.LogicalServerID != dependency.LogicalServerID || endpoint.Transport != dependency.Transport ||
		profile.ClusterID != catalog.ClusterID || profile.ServerID != endpoint.LogicalServerID ||
		resources.ClusterID != catalog.ClusterID || resources.ServerID != endpoint.LogicalServerID ||
		listener.PublicProfileGeneration != profile.Generation || listener.DialTargetFQDN != profile.FQDN {
		return BootstrapIngressRuntimePlanV1{}, errors.New("[bootstrap runtime] endpoint/listener/profile identity 不完全相等")
	}
	listenerState, tuples, ok := authorized.GenerationTuples(listenerGeneration)
	if !ok || !listenerStateCompatible(listenerState, listener.PublishedState,
		dependency.SourceListenerGeneration == nil) {
		return BootstrapIngressRuntimePlanV1{}, errors.New("[bootstrap runtime] listener generation 当前不拥有可服务 tuple")
	}
	spkiPins, err := bootstrapIdentityPins(listener.TransportIdentityRefs, profile.CertificateProfileRef)
	if err != nil {
		return BootstrapIngressRuntimePlanV1{}, err
	}
	bindings, err := deriveRuntimeBindings(catalog, endpoint, listener, listenerState, profile, resources,
		tuples, spkiPins, dependency.PortMappingIntentHash)
	if err != nil {
		return BootstrapIngressRuntimePlanV1{}, err
	}
	return BootstrapIngressRuntimePlanV1{bindings: bindings}, nil
}

func findBootstrapListener(catalog *wire.BootstrapEndpointCatalogV1, endpointID string,
	generation int64) (*wire.BootstrapIngressEndpointV1, *wire.ListenerGenerationV2, error) {
	for endpointIndex := range catalog.BootstrapIngressSet.Endpoints {
		endpoint := &catalog.BootstrapIngressSet.Endpoints[endpointIndex]
		if endpoint.EndpointID != endpointID {
			continue
		}
		for generationIndex := range endpoint.ListenerGenerations {
			listener := &endpoint.ListenerGenerations[generationIndex]
			if listener.ListenerGeneration == generation {
				return endpoint, listener, nil
			}
		}
		return nil, nil, errors.New("[bootstrap runtime] endpoint 缺 exact listener generation")
	}
	return nil, nil, errors.New("[bootstrap runtime] certified catalog 缺 exact endpoint")
}

func listenerStateCompatible(runtimeState, publishedState string, initialProvision bool) bool {
	if initialProvision && (runtimeState == "prepared" || runtimeState == "advertised") {
		// 首代没有可保留的旧 preferred；expected set 必须仍满足公开 wire 的
		// 恰一 preferred 不变量，但在发布前只作为安装计划消费。
		return publishedState == "preferred"
	}
	if runtimeState == "prepared" {
		// expected set 可在公开 advertise 前作为精确安装计划，但 wire 中绝不发布 prepared。
		return publishedState == "advertised"
	}
	return runtimeState == publishedState
}

func bootstrapIdentityPins(refs []string, certificateProfile string) ([]string, error) {
	wantProfile := "profile:" + certificateProfile
	profileSeen := false
	pins := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref == wantProfile {
			profileSeen = true
			continue
		}
		if _, err := wire.ParseHash(ref); err != nil {
			return nil, errors.New("[bootstrap runtime] transport identity ref 未绑定 exact WebPKI profile/SPKI pin")
		}
		pins = append(pins, ref)
	}
	if !profileSeen || len(pins) == 0 {
		return nil, errors.New("[bootstrap runtime] listener 缺 exact WebPKI profile 或 SPKI pin")
	}
	return pins, nil
}

func deriveRuntimeBindings(catalog *wire.BootstrapEndpointCatalogV1,
	endpoint *wire.BootstrapIngressEndpointV1, listener *wire.ListenerGenerationV2,
	listenerState string, profile *wire.ServerPublicAccessProfileV1,
	resources *wire.ForwardServerListenerResourcesV1, tuples []rotation.Tuple,
	spkiPins []string, frozenMappingHash string) ([]VerifiedBootstrapListenerV1, error) {
	l4 := "tcp"
	pool := resources.TrojanLocalTCPPortPool
	if endpoint.Transport == "hysteria2" {
		l4 = "udp"
		pool = resources.HY2LocalUDPPortPool
	}
	if len(tuples) == 0 {
		return nil, errors.New("[bootstrap runtime] generation 没有 frozen bind tuple")
	}
	if profile.DeploymentKind == "nat_mapped" && frozenMappingHash == "" ||
		profile.DeploymentKind != "nat_mapped" && frozenMappingHash != "" {
		return nil, errors.New("[bootstrap runtime] deployment kind 与 frozen NAT mapping 不一致")
	}
	validFrom, validUntil, err := listenerCatalogValidity(catalog, listener)
	if err != nil {
		return nil, err
	}
	canonicalTuples := append([]rotation.Tuple(nil), tuples...)
	sort.Slice(canonicalTuples, func(left, right int) bool {
		if canonicalTuples[left].Address != canonicalTuples[right].Address {
			return canonicalTuples[left].Address < canonicalTuples[right].Address
		}
		return canonicalTuples[left].Port < canonicalTuples[right].Port
	})
	for index, tuple := range canonicalTuples {
		address, err := netip.ParseAddr(tuple.Address)
		if err != nil || address.String() != tuple.Address || tuple.Transport != l4 ||
			tuple.Port < 1 || tuple.Port > 65535 || index > 0 && tuple == canonicalTuples[index-1] {
			return nil, errors.New("[bootstrap runtime] frozen bind tuple 非规范或 transport 不匹配")
		}
	}

	publicByLocal := make(map[rotation.Tuple][]rotation.Tuple, len(canonicalTuples))
	for _, rawAddress := range profile.PublicFrontendAddresses {
		publicAddress, _ := netip.ParseAddr(rawAddress)
		if !listenerAllowsFamily(listener, publicAddress) {
			continue
		}
		matches := make([]rotation.Tuple, 0, 1)
		for _, tuple := range canonicalTuples {
			if profile.DeploymentKind == "nat_mapped" {
				if mappingServesTuple(resources.Mappings, l4, publicAddress.String(), listener.PublicPort,
					tuple, pool, frozenMappingHash) {
					matches = append(matches, tuple)
				}
			} else if directTupleServes(tuple, publicAddress, listener.PublicPort, pool) {
				matches = append(matches, tuple)
			}
		}
		if len(matches) != 1 {
			return nil, errors.New("[bootstrap runtime] certified public address/port 必须唯一命中 local listener/NAT mapping")
		}
		publicTuple := rotation.Tuple{Transport: l4, Address: publicAddress.String(), Port: listener.PublicPort}
		publicByLocal[matches[0]] = append(publicByLocal[matches[0]], publicTuple)
	}
	bindings := make([]VerifiedBootstrapListenerV1, 0, len(canonicalTuples))
	for _, tuple := range canonicalTuples {
		publicTuples := publicByLocal[tuple]
		if len(publicTuples) == 0 {
			return nil, errors.New("[bootstrap runtime] frozen tuple 不服务任何 certified public frontend")
		}
		projection := bootstrapListenerRuntimeProjectionV1{
			Schema: 1, ClusterID: catalog.ClusterID, IngressSetHash: catalog.BootstrapIngressSetHash,
			EndpointSetID: catalog.BootstrapIngressSet.EndpointSetID, EndpointID: endpoint.EndpointID,
			LogicalServerID: endpoint.LogicalServerID, Transport: endpoint.Transport,
			ListenerGeneration: listener.ListenerGeneration, ListenerState: listenerState,
			ServerName: listener.DialTargetFQDN, PublicPort: listener.PublicPort,
			BindTuple: tuple, PublicTuples: append([]rotation.Tuple(nil), publicTuples...),
			SPKIPins:  append([]string(nil), spkiPins...),
			ValidFrom: validFrom, ValidUntil: validUntil,
		}
		hash, err := wire.HashObject(domainBootstrapListenerRuntimeBinding, projection)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, VerifiedBootstrapListenerV1{projection: projection, bindingHash: hash})
	}
	return bindings, nil
}

func listenerAllowsFamily(listener *wire.ListenerGenerationV2, address netip.Addr) bool {
	want := "ipv6"
	if address.Is4() {
		want = "ipv4"
	}
	for _, family := range listener.AddressFamilies {
		if family == want {
			return true
		}
	}
	return false
}

func directTupleServes(tuple rotation.Tuple, publicAddress netip.Addr, publicPort int64, pool []int64) bool {
	if tuple.Port != publicPort || !containsPort(pool, tuple.Port) {
		return false
	}
	bindAddress, _ := netip.ParseAddr(tuple.Address)
	return bindAddress == publicAddress || bindAddress.IsUnspecified() && bindAddress.Is4() == publicAddress.Is4()
}

func mappingServesTuple(mappings []wire.PortMappingIntentV1, transport, publicAddress string,
	publicPort int64, tuple rotation.Tuple, pool []int64, frozenMappingHash string) bool {
	if !containsPort(pool, tuple.Port) {
		return false
	}
	for _, mapping := range mappings {
		if mapping.Transport != transport || mapping.PublicAddress != publicAddress ||
			publicPort < mapping.PublicPortStart || publicPort > mapping.PublicPortEnd {
			continue
		}
		localPort := mapping.LocalPortStart + publicPort - mapping.PublicPortStart
		mappingHash, err := wire.PortMappingIntentHash(&mapping)
		if err == nil && mappingHash == frozenMappingHash &&
			mapping.LocalAddress == tuple.Address && localPort == tuple.Port {
			return true
		}
	}
	return false
}

func listenerCatalogValidity(catalog *wire.BootstrapEndpointCatalogV1,
	listener *wire.ListenerGenerationV2) (string, string, error) {
	catalogFrom, _ := wire.ParseTimeZ(catalog.ValidFrom)
	catalogUntil, _ := wire.ParseTimeZ(catalog.ValidUntil)
	listenerFrom, _ := wire.ParseTimeZ(listener.ValidFrom)
	listenerUntil, _ := wire.ParseTimeZ(listener.ValidUntil)
	if listenerFrom.After(catalogFrom) {
		catalogFrom = listenerFrom
	}
	if listenerUntil.Before(catalogUntil) {
		catalogUntil = listenerUntil
	}
	if !catalogFrom.Before(catalogUntil) {
		return "", "", errors.New("[bootstrap runtime] catalog/listener validity 无交集")
	}
	return catalogFrom.UTC().Format(time.RFC3339), catalogUntil.UTC().Format(time.RFC3339), nil
}

func containsPort(values []int64, target int64) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (verified VerifiedBootstrapListenerV1) valid() bool {
	projection := verified.projection
	if projection.Schema != 1 || projection.ClusterID == "" || projection.EndpointSetID == "" ||
		projection.EndpointID == "" || projection.LogicalServerID == "" ||
		(projection.Transport != "hysteria2" && projection.Transport != "trojan_tls") ||
		(projection.ListenerState != "prepared" && projection.ListenerState != "advertised" &&
			projection.ListenerState != "preferred" && projection.ListenerState != "draining") ||
		projection.ListenerGeneration < 1 || !validCertifiedServerName(projection.ServerName) ||
		projection.PublicPort < 1 || projection.PublicPort > 65535 || len(projection.PublicTuples) == 0 ||
		len(projection.SPKIPins) == 0 {
		return false
	}
	if _, err := wire.ParseHash(projection.IngressSetHash); err != nil {
		return false
	}
	for _, pin := range projection.SPKIPins {
		if _, err := wire.ParseHash(pin); err != nil {
			return false
		}
	}
	from, err := wire.ParseTimeZ(projection.ValidFrom)
	if err != nil {
		return false
	}
	until, err := wire.ParseTimeZ(projection.ValidUntil)
	if err != nil || !from.Before(until) {
		return false
	}
	address, err := netip.ParseAddr(projection.BindTuple.Address)
	if err != nil || address.String() != projection.BindTuple.Address || projection.BindTuple.Port < 1 ||
		projection.BindTuple.Port > 65535 || projection.BindTuple.Transport != "tcp" &&
		projection.BindTuple.Transport != "udp" {
		return false
	}
	if projection.Transport == "hysteria2" && projection.BindTuple.Transport != "udp" ||
		projection.Transport == "trojan_tls" && projection.BindTuple.Transport != "tcp" {
		return false
	}
	for index, tuple := range projection.PublicTuples {
		address, err := netip.ParseAddr(tuple.Address)
		if err != nil || address.String() != tuple.Address || tuple.Transport != projection.BindTuple.Transport ||
			tuple.Port != projection.PublicPort || index > 0 && !runtimeTupleLess(projection.PublicTuples[index-1], tuple) {
			return false
		}
	}
	want, err := wire.HashObject(domainBootstrapListenerRuntimeBinding, projection)
	return err == nil && want == verified.bindingHash
}

func runtimeTupleLess(left, right rotation.Tuple) bool {
	if left.Transport != right.Transport {
		return left.Transport < right.Transport
	}
	if left.Address != right.Address {
		return left.Address < right.Address
	}
	return left.Port < right.Port
}

func (verified VerifiedBootstrapListenerV1) acceptsAt(now time.Time) bool {
	if !verified.valid() || now.IsZero() {
		return false
	}
	from, _ := wire.ParseTimeZ(verified.projection.ValidFrom)
	until, _ := wire.ParseTimeZ(verified.projection.ValidUntil)
	instant := now.UTC()
	return !instant.Before(from) && instant.Before(until)
}

func (verified VerifiedBootstrapListenerV1) matchesLocalAddr(address net.Addr, transport string) bool {
	if !verified.valid() || address == nil || verified.projection.Transport != transport {
		return false
	}
	wantNetwork := "tcp"
	if transport == "hysteria2" {
		wantNetwork = "udp"
	}
	if address.Network() != wantNetwork {
		return false
	}
	host, port, err := net.SplitHostPort(address.String())
	if err != nil {
		return false
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || parsed.String() != host || parsed.String() != verified.projection.BindTuple.Address {
		return false
	}
	return port == strconv.FormatInt(verified.projection.BindTuple.Port, 10)
}
