package bootstrapaccess

import (
	"errors"
	"math"
	"net/netip"
	"slices"
	"sort"
	"time"

	"loom/internal/certmanager"
	"loom/internal/rotation"
	"loom/internal/wire"
)

// 这些完整 preimage 先进入认证的迁移事务。catalog 在这里是私有安装计划，
// 只有运行中的 local/external 验证及 advertise 事务通过后才可公开分发。
type InitialBootstrapListenerInputV1 struct {
	EndpointID     string                                   `json:"endpoint_id"`
	Transport      string                                   `json:"transport"`
	PublicPort     int64                                    `json:"public_port"`
	Profile        wire.ServerPublicAccessProfileV1         `json:"profile"`
	Resources      wire.ForwardServerListenerResourcesV1    `json:"resources"`
	Certificate    certmanager.ExistingCertificateBindingV1 `json:"certificate"`
	EvidencePolicy BootstrapOuterEvidencePolicyV1           `json:"evidence_policy"`
}

type InitialBootstrapInstallationInputV1 struct {
	Schema      int                               `json:"schema"`
	ClusterID   string                            `json:"cluster_id"`
	OperationID string                            `json:"operation_id"`
	Parent      wire.HeadEntryV2                  `json:"parent"`
	ParentQC    wire.StableHeadReplicationQCV1    `json:"parent_qc"`
	ControlSet  wire.ControlSetV1                 `json:"control_set"`
	ValidFrom   string                            `json:"valid_from"`
	ValidUntil  string                            `json:"valid_until"`
	Listeners   []InitialBootstrapListenerInputV1 `json:"listeners"`
}

type InitialBootstrapListenerPlanV1 struct {
	EndpointID string                   `json:"endpoint_id"`
	Intent     rotation.IntentV1        `json:"intent"`
	Execution  rotation.ExecutionPlanV1 `json:"execution"`
}

type InitialBootstrapInstallationV1 struct {
	Schema  int                                 `json:"schema"`
	Input   InitialBootstrapInstallationInputV1 `json:"input"`
	Catalog wire.BootstrapEndpointCatalogV1     `json:"catalog"`
	Plans   []InitialBootstrapListenerPlanV1    `json:"plans"`
}

// 纯生成：所有时间、地址、端口、证书和 observer key 均由调用方提供。
// 不分配域名、不签证、不查询端口，也不把材料准备冒充公网可达。
func BuildInitialBootstrapInstallation(input InitialBootstrapInstallationInputV1) (InitialBootstrapInstallationV1, error) {
	var empty InitialBootstrapInstallationV1
	if input.Schema != 1 || input.ClusterID == "" || input.OperationID == "" || len(input.Listeners) == 0 || len(input.Listeners) > 32 ||
		input.Parent.Body.Payload.ClusterID != input.ClusterID || input.ControlSet.ClusterID != input.ClusterID || input.Parent.Body.Payload.ControlRevision == math.MaxInt64 {
		return empty, errors.New("[bootstrap 安装] 缺原网络、固定操作、认证 parent 或入口材料")
	}
	if err := wire.VerifyStableHeadQC(&input.Parent, &input.ControlSet, &input.ParentQC); err != nil {
		return empty, err
	}
	from, err := wire.ParseTimeZ(input.ValidFrom)
	until, endErr := wire.ParseTimeZ(input.ValidUntil)
	if err != nil || endErr != nil || !from.Before(until) {
		return empty, errors.New("[bootstrap 安装] 有效期无效")
	}
	qc, _ := wire.MarshalCanonical(input.ParentQC)
	set := wire.BootstrapIngressEndpointSetV1{Schema: 1, ClusterID: input.ClusterID, EndpointSetID: "bootstrap-ingress", Generation: 1,
		ValidFrom: input.ValidFrom, ValidUntil: input.ValidUntil, ParentHeadHash: input.Parent.HeadHash, ConfigQC: qc,
		Endpoints: make([]wire.BootstrapIngressEndpointV1, 0, len(input.Listeners))}
	var transports []string
	profiles := make(map[string]string)
	for i, listener := range input.Listeners {
		if i > 0 && input.Listeners[i-1].EndpointID >= listener.EndpointID {
			return empty, errors.New("[bootstrap 安装] 入口必须稳定排序且不重复")
		}
		if err := validateInitialListener(input.ClusterID, listener, from, until); err != nil {
			return empty, err
		}
		profileHash, _ := wire.ServerPublicAccessProfileHash(&listener.Profile, &listener.Resources)
		if prior, found := profiles[listener.Profile.ServerID]; found && prior != profileHash {
			return empty, errors.New("[bootstrap 安装] 同一节点不能声明冲突的 public profile/resources")
		}
		profiles[listener.Profile.ServerID] = profileHash
		operationHash, err := wire.HashObject("loom-initial-bootstrap-listener-input-v1", struct {
			OperationID    string                          `json:"operation_id"`
			ParentHeadHash string                          `json:"parent_head_hash"`
			Listener       InitialBootstrapListenerInputV1 `json:"listener"`
		}{input.OperationID, input.Parent.HeadHash, listener})
		if err != nil {
			return empty, err
		}
		families := []string{"ipv4"}
		if listener.Profile.AddressFamilyPolicy == "ipv6_only" {
			families = []string{"ipv6"}
		} else if listener.Profile.AddressFamilyPolicy == "dual_stack" {
			families = []string{"ipv4", "ipv6"}
		}
		generation := wire.ListenerGenerationV2{Schema: 2, ListenerGeneration: 1, PublishedState: "preferred", DialTargetFQDN: listener.Profile.FQDN,
			PublicPort: listener.PublicPort, AddressFamilies: families, TransportIdentityRefs: []string{"profile:" + listener.Profile.CertificateProfileRef, listener.Certificate.Identity.SPKIHash},
			CredentialGeneration: 1, CertificateIdentityProjectionHash: listener.Certificate.IdentityProjectionHash, PublicProfileGeneration: listener.Profile.Generation,
			IntroducedRevision: input.Parent.Body.Payload.ControlRevision + 1, ValidFrom: input.ValidFrom, ValidUntil: input.ValidUntil, RotationOperationHash: operationHash}
		set.Endpoints = append(set.Endpoints, wire.BootstrapIngressEndpointV1{EndpointID: listener.EndpointID, LogicalServerID: listener.Profile.ServerID, Transport: listener.Transport,
			HintRank: int64(i), ListenerGenerations: []wire.ListenerGenerationV2{generation}, ListenerTombstones: []wire.ListenerGenerationTombstoneV1{}})
		transports = append(transports, listener.Transport)
	}
	if !slices.Contains(transports, "hysteria2") || !slices.Contains(transports, "trojan_tls") {
		return empty, errors.New("[bootstrap 安装] 必须同时提供 HY2 与独立 Trojan/TLS TCP 入口")
	}
	setHash, err := wire.BootstrapIngressSetHash(&set)
	if err != nil {
		return empty, err
	}
	qcHash, _ := wire.ConfigQCHash(qc)
	catalog := wire.BootstrapEndpointCatalogV1{Schema: 1, ClusterID: input.ClusterID, CatalogGeneration: 1, ValidFrom: input.ValidFrom, ValidUntil: input.ValidUntil,
		BootstrapIngressSet: set, BootstrapIngressSetHash: setHash, RequiredClientProtocol: 2, ParentHeadHash: input.Parent.HeadHash, ConfigQCHash: qcHash}
	if err := wire.ValidateBootstrapEndpointCatalog(&catalog); err != nil {
		return empty, err
	}
	result := InitialBootstrapInstallationV1{Schema: 1, Input: input, Catalog: catalog, Plans: make([]InitialBootstrapListenerPlanV1, 0, len(input.Listeners))}
	for i, listener := range input.Listeners {
		plan, err := buildInitialListenerPlan(input, listener, catalog, set.Endpoints[i])
		if err != nil {
			return empty, err
		}
		for j, existing := range result.Plans {
			if input.Listeners[j].Profile.ServerID != listener.Profile.ServerID {
				continue
			}
			for _, left := range existing.Execution.TargetTuples {
				for _, right := range plan.Execution.TargetTuples {
					a, _ := netip.ParseAddr(left.Address)
					b, _ := netip.ParseAddr(right.Address)
					if left.Transport == right.Transport && left.Port == right.Port && a.Is4() == b.Is4() &&
						(a == b || a.IsUnspecified() || b.IsUnspecified()) {
						return empty, errors.New("[bootstrap 安装] 同一节点的监听 tuple 冲突")
					}
				}
			}
		}
		result.Plans = append(result.Plans, plan)
	}
	return result, nil
}

func ValidateInitialBootstrapInstallation(installation *InitialBootstrapInstallationV1) error {
	if installation == nil || installation.Schema != 1 {
		return errors.New("[bootstrap 安装] 安装计划 schema 无效")
	}
	want, err := BuildInitialBootstrapInstallation(installation.Input)
	if err != nil {
		return err
	}
	if !wire.EqualCanonical(want, *installation) {
		return errors.New("[bootstrap 安装] 计划不等于认证输入的确定性投影")
	}
	return nil
}

func validateInitialListener(cluster string, listener InitialBootstrapListenerInputV1, from, until time.Time) error {
	if listener.Transport != "hysteria2" && listener.Transport != "trojan_tls" || listener.Profile.ClusterID != cluster || listener.PublicPort < 1 || listener.PublicPort > 65535 {
		return errors.New("[bootstrap 安装] listener 网络、transport 或端口无效")
	}
	if err := wire.ValidatePublicAccess(&listener.Profile, &listener.Resources); err != nil {
		return err
	}
	if _, err := certmanager.ExistingCertificateBindingHash(&listener.Certificate); err != nil {
		return err
	}
	identity := listener.Certificate.Identity
	if identity.ClusterID != cluster || identity.KeyOwnerDeviceID != listener.Profile.ServerID || identity.IssuerProfileRef != listener.Profile.CertificateProfileRef ||
		!slices.Contains(identity.EndpointIDs, listener.EndpointID) || !slices.Contains(identity.DNSNames, listener.Profile.FQDN) {
		return errors.New("[bootstrap 安装] 证书不属于此节点、入口或域名")
	}
	certificateFrom, _ := wire.ParseTimeZ(listener.Certificate.NotBefore)
	certificateUntil, _ := wire.ParseTimeZ(listener.Certificate.NotAfter)
	if from.Before(certificateFrom) || until.After(certificateUntil) {
		return errors.New("[bootstrap 安装] 安装计划超出现有证书有效期")
	}
	if _, err := BootstrapOuterEvidencePolicyHash(&listener.EvidencePolicy); err != nil {
		return err
	}
	if listener.EvidencePolicy.ClusterID != cluster {
		return errors.New("[bootstrap 安装] 外部验证策略不属于当前网络")
	}
	for _, observer := range listener.EvidencePolicy.Observers {
		if observer.ObserverID == listener.Profile.ServerID {
			return errors.New("[bootstrap 安装] 入口节点不能把自身作为外部 observer")
		}
	}
	return nil
}

func buildInitialListenerPlan(input InitialBootstrapInstallationInputV1, listener InitialBootstrapListenerInputV1,
	catalog wire.BootstrapEndpointCatalogV1, endpoint wire.BootstrapIngressEndpointV1) (InitialBootstrapListenerPlanV1, error) {
	var empty InitialBootstrapListenerPlanV1
	profileHash, _ := wire.ServerPublicAccessProfileHash(&listener.Profile, &listener.Resources)
	resourcesHash, _ := wire.ForwardServerListenerResourcesHash(&listener.Resources)
	policyHash, _ := BootstrapOuterEvidencePolicyHash(&listener.EvidencePolicy)
	addressHash, err := wire.HashObject("loom-existing-public-address-binding-v1", struct {
		Schema    int      `json:"schema"`
		FQDN      string   `json:"fqdn"`
		Addresses []string `json:"addresses"`
	}{1, listener.Profile.FQDN, listener.Profile.PublicFrontendAddresses})
	if err != nil {
		return empty, err
	}
	contractHash, _ := wire.HashObject("loom-bootstrap-runtime-contract-v1", struct {
		Schema     int      `json:"schema"`
		Transports []string `json:"transports"`
		Inside     string   `json:"inside"`
	}{1, []string{"hysteria2", "trojan_tls"}, "capability-exact-enrollment-tcp"})
	poolHash, _ := wire.HashObject("loom-initial-bootstrap-pools-v1", listener.Resources)
	tuples, mappingHash, err := initialBootstrapTuples(listener)
	if err != nil {
		return empty, err
	}
	policyTuplesHash, _ := wire.HashObject("loom-bootstrap-listen-policy-v1", tuples)
	dependencies := rotation.FrozenDependenciesV1{Schema: 1, ClusterID: input.ClusterID, EndpointKind: "bootstrap", EndpointSetID: catalog.BootstrapIngressSet.EndpointSetID,
		EndpointID: listener.EndpointID, LogicalServerID: listener.Profile.ServerID, Transport: listener.Transport, TargetListenerGeneration: 1,
		LogicalPublicEndpointIntentHash: endpoint.ListenerGenerations[0].RotationOperationHash, PublicAccessProfileHash: profileHash, DNSAddressBindingHash: addressHash,
		CertificateIdentityProjectionHash: listener.Certificate.IdentityProjectionHash, CredentialArtifactRefsRoot: wire.EmptyHashV1, RenderContractHash: contractHash,
		EvidencePolicyHash: policyHash, PortPoolHash: poolHash, FirewallPolicyHash: policyTuplesHash, ForwardListenerResourceGenerationHash: resourcesHash,
		PortMappingIntentHash: mappingHash, LinkIntentHashes: []string{}}
	dependenciesHash, err := wire.HashObject(rotation.DomainFrozenDependencies, dependencies)
	if err != nil {
		return empty, err
	}
	intent := rotation.IntentV1{Schema: 1, ClusterID: input.ClusterID, RotationID: "initial-" + listener.EndpointID, OperationID: input.OperationID,
		BaseHeadHash: input.Parent.HeadHash, ExpectedEndpointSetHash: catalog.BootstrapIngressSetHash, FrozenDependencies: dependencies, FrozenDependenciesHash: dependenciesHash,
		AdvertiseNotBefore: input.ValidFrom, PreferNotBefore: input.ValidFrom, DrainNotBefore: input.ValidUntil, DrainNotAfter: input.ValidUntil, RetireNotBefore: input.ValidUntil,
		MinimumReaderFloor: input.Parent.Body.Payload.ControlRevision + 1}
	execution := rotation.ExecutionPlanV1{Schema: 1, ClusterID: input.ClusterID, RotationID: intent.RotationID, FrozenDependenciesHash: dependenciesHash,
		SourceTuples: []rotation.Tuple{}, TargetTuples: tuples}
	if err := rotation.ValidateIntent(&intent); err != nil {
		return empty, err
	}
	if err := rotation.ValidateExecutionPlan(&intent, &execution); err != nil {
		return empty, err
	}
	// 再使用与真实 adapter 相同的 public/local tuple 投影验证，避免生产者与消费者各自理解端口。
	if _, err := deriveRuntimeBindings(&catalog, &endpoint, &endpoint.ListenerGenerations[0], "prepared", &listener.Profile, &listener.Resources, tuples,
		[]string{listener.Certificate.Identity.SPKIHash}, mappingHash); err != nil {
		return empty, err
	}
	return InitialBootstrapListenerPlanV1{EndpointID: listener.EndpointID, Intent: intent, Execution: execution}, nil
}

func initialBootstrapTuples(listener InitialBootstrapListenerInputV1) ([]rotation.Tuple, string, error) {
	l4 := "udp"
	pool := listener.Resources.HY2LocalUDPPortPool
	if listener.Transport == "trojan_tls" {
		l4 = "tcp"
		pool = listener.Resources.TrojanLocalTCPPortPool
	}
	var tuples []rotation.Tuple
	mappingHash := ""
	if listener.Profile.DeploymentKind == "nat_mapped" {
		for _, mapping := range listener.Resources.Mappings {
			if mapping.Transport != l4 || !slices.Contains(listener.Profile.PublicFrontendAddresses, mapping.PublicAddress) || listener.PublicPort < mapping.PublicPortStart || listener.PublicPort > mapping.PublicPortEnd {
				continue
			}
			if mappingHash != "" {
				return nil, "", errors.New("[bootstrap 安装] 一个 listener 必须绑定唯一既有 NAT mapping")
			}
			mappingHash, _ = wire.PortMappingIntentHash(&mapping)
			tuples = append(tuples, rotation.Tuple{Transport: l4, Address: mapping.LocalAddress, Port: mapping.LocalPortStart + listener.PublicPort - mapping.PublicPortStart})
		}
		if mappingHash == "" {
			return nil, "", errors.New("[bootstrap 安装] 缺既有精确 NAT mapping")
		}
	} else {
		families := map[bool]bool{}
		for _, address := range listener.Profile.PublicFrontendAddresses {
			parsed, _ := netip.ParseAddr(address)
			families[parsed.Is4()] = true
		}
		if families[true] {
			tuples = append(tuples, rotation.Tuple{Transport: l4, Address: "0.0.0.0", Port: listener.PublicPort})
		}
		if families[false] {
			tuples = append(tuples, rotation.Tuple{Transport: l4, Address: "::", Port: listener.PublicPort})
		}
	}
	for _, tuple := range tuples {
		if !slices.Contains(pool, tuple.Port) {
			return nil, "", errors.New("[bootstrap 安装] 端口不属于已声明资源池")
		}
	}
	sort.Slice(tuples, func(i, j int) bool { return tuples[i].Address < tuples[j].Address })
	return tuples, mappingHash, nil
}
