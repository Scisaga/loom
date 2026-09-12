package bootstrapaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"

	"loom/internal/rotation"
	"loom/internal/wire"
)

const (
	domainBootstrapOuterProbePlan       = "loom-bootstrap-outer-probe-plan-v1"
	domainBootstrapOuterProbeSignature  = "loom-bootstrap-outer-probe-signature-v1"
	domainBootstrapOuterEvidencePolicy  = "loom-bootstrap-outer-evidence-policy-v1"
	domainBootstrapOuterReachability    = "loom-bootstrap-outer-reachability-evidence-v1"
	bootstrapOuterProbeMaximumObservers = 32
)

// BootstrapOuterProbePlanV1 是外部 observer 可接收的最小探测计划。它只含
// certified public tuple 与 TLS identity，不含 capability、Invite 或 Enrollment token。
type BootstrapOuterProbePlanV1 struct {
	Schema                 int              `json:"schema"`
	ClusterID              string           `json:"cluster_id"`
	RotationID             string           `json:"rotation_id"`
	FrozenDependenciesHash string           `json:"frozen_dependencies_hash"`
	EndpointSetHash        string           `json:"endpoint_set_hash"`
	EndpointID             string           `json:"endpoint_id"`
	LogicalServerID        string           `json:"logical_server_id"`
	Transport              string           `json:"transport"`
	ListenerGeneration     int64            `json:"listener_generation"`
	ServerName             string           `json:"server_name"`
	SPKIPins               []string         `json:"spki_pins"`
	Targets                []rotation.Tuple `json:"targets"`
	ValidFrom              string           `json:"valid_from"`
	ValidUntil             string           `json:"valid_until"`
}

type BootstrapOuterObserverV1 struct {
	ObserverID        string `json:"observer_id"`
	FailureDomain     string `json:"failure_domain"`
	ObserverKeyID     string `json:"observer_key_id"`
	ObserverPublicKey string `json:"observer_public_key"`
}

// BootstrapOuterEvidencePolicyV1 由 rotation frozen dependency 的
// evidence_policy_hash 固定；executor 不能临时把自身 key 添加成外部 observer。
type BootstrapOuterEvidencePolicyV1 struct {
	Schema                        int                        `json:"schema"`
	ClusterID                     string                     `json:"cluster_id"`
	PolicyID                      string                     `json:"policy_id"`
	MinimumExternalObservers      int64                      `json:"minimum_external_observers"`
	MinimumExternalFailureDomains int64                      `json:"minimum_external_failure_domains"`
	MaximumObservationAgeSeconds  int64                      `json:"maximum_observation_age_seconds"`
	Observers                     []BootstrapOuterObserverV1 `json:"observers"`
}

type BootstrapOuterProbeResultV1 struct {
	Target             rotation.Tuple `json:"target"`
	TLSVersion         int64          `json:"tls_version"`
	NegotiatedProtocol string         `json:"negotiated_protocol"`
	LeafSPKIHash       string         `json:"leaf_spki_hash"`
}

type BootstrapOuterProbeObservationV1 struct {
	Schema        int                           `json:"schema"`
	ClusterID     string                        `json:"cluster_id"`
	ObserverID    string                        `json:"observer_id"`
	ProbePlanHash string                        `json:"probe_plan_hash"`
	ObservedAt    string                        `json:"observed_at"`
	Results       []BootstrapOuterProbeResultV1 `json:"results"`
}

type BootstrapOuterProbeSignatureV1 struct {
	Algorithm     string `json:"algorithm"`
	ObserverKeyID string `json:"observer_key_id"`
	Signature     string `json:"signature"`
}

type SignedBootstrapOuterProbeObservationV1 struct {
	Body      BootstrapOuterProbeObservationV1 `json:"body"`
	Signature BootstrapOuterProbeSignatureV1   `json:"signature"`
}

type BootstrapOuterReachabilityEvidenceV1 struct {
	Schema             int                                      `json:"schema"`
	ClusterID          string                                   `json:"cluster_id"`
	RotationID         string                                   `json:"rotation_id"`
	EvidencePolicyHash string                                   `json:"evidence_policy_hash"`
	ProbePlanHash      string                                   `json:"probe_plan_hash"`
	VerifiedAt         string                                   `json:"verified_at"`
	ValidUntil         string                                   `json:"valid_until"`
	Observations       []SignedBootstrapOuterProbeObservationV1 `json:"observations"`
}

// VerifiedBootstrapOuterReachabilityV1 只能由完整 policy/signature/time/coverage
// 验证产生，供 certified advertise operation 绑定 exact external evidence hash。
type VerifiedBootstrapOuterReachabilityV1 struct {
	evidence BootstrapOuterReachabilityEvidenceV1
	hash     string
}

type BootstrapOuterProbeOptions struct {
	ObserverID string
	PrivateKey ed25519.PrivateKey
	TLSConfig  *tls.Config
	TCPDial    DialContext
	ListenUDP  UDPListenFunc
	Now        func() time.Time
	Timeout    time.Duration
}

// BuildBootstrapOuterProbePlan 把本机 opaque listener capability 投影为外部
// observer 的无 bearer 计划，并再次绑定完整 replay 后的 rotation authority。
func BuildBootstrapOuterProbePlan(runtimePlan BootstrapIngressRuntimePlanV1,
	authorized rotation.AuthorizedRuntimePlanV1) (BootstrapOuterProbePlanV1, error) {
	bindings := runtimePlan.Bindings()
	if len(bindings) == 0 {
		return BootstrapOuterProbePlanV1{}, errors.New("[D120 external verify] bootstrap runtime plan 为空")
	}
	intent := authorized.Intent()
	dependency := intent.FrozenDependencies
	first := bindings[0].projection
	if intent.Schema != 1 || dependency.Schema != 1 || intent.FrozenDependenciesHash == "" ||
		intent.ExpectedEndpointSetHash != first.IngressSetHash || dependency.EndpointKind != "bootstrap" ||
		dependency.EndpointSetID != first.EndpointSetID || dependency.EndpointID != first.EndpointID ||
		dependency.LogicalServerID != first.LogicalServerID || dependency.Transport != first.Transport ||
		dependency.TargetListenerGeneration != first.ListenerGeneration {
		return BootstrapOuterProbePlanV1{}, errors.New("[D120 external verify] runtime plan 与 certified rotation authority 不匹配")
	}
	ownedState, ownedTuples, ok := authorized.GenerationTuples(first.ListenerGeneration)
	if !ok || ownedState == "" {
		return BootstrapOuterProbePlanV1{}, errors.New("[D120 external verify] target generation 尚未获得 runtime ownership")
	}
	owned := make(map[rotation.Tuple]struct{}, len(ownedTuples))
	for _, tuple := range ownedTuples {
		owned[tuple] = struct{}{}
	}
	targets := make([]rotation.Tuple, 0, len(bindings))
	for _, binding := range bindings {
		projection := binding.projection
		if !binding.valid() || projection.ClusterID != first.ClusterID ||
			projection.IngressSetHash != first.IngressSetHash || projection.EndpointSetID != first.EndpointSetID ||
			projection.EndpointID != first.EndpointID || projection.LogicalServerID != first.LogicalServerID ||
			projection.Transport != first.Transport || projection.ListenerGeneration != first.ListenerGeneration ||
			projection.ServerName != first.ServerName || projection.ValidFrom != first.ValidFrom ||
			projection.ValidUntil != first.ValidUntil || !slices.Equal(projection.SPKIPins, first.SPKIPins) {
			return BootstrapOuterProbePlanV1{}, errors.New("[D120 external verify] runtime bindings 不属于同一 target generation")
		}
		if _, ok := owned[projection.BindTuple]; !ok {
			return BootstrapOuterProbePlanV1{}, errors.New("[D127 external verify] runtime binding 不在 durable frozen tuple 集合")
		}
		targets = append(targets, projection.PublicTuples...)
	}
	sort.Slice(targets, func(left, right int) bool { return runtimeTupleLess(targets[left], targets[right]) })
	for index := range targets {
		if index > 0 && targets[index] == targets[index-1] {
			return BootstrapOuterProbePlanV1{}, errors.New("[D103 external verify] public probe tuple 被多个 local binding 重复覆盖")
		}
	}
	plan := BootstrapOuterProbePlanV1{
		Schema: 1, ClusterID: first.ClusterID, RotationID: intent.RotationID,
		FrozenDependenciesHash: intent.FrozenDependenciesHash, EndpointSetHash: first.IngressSetHash,
		EndpointID: first.EndpointID, LogicalServerID: first.LogicalServerID,
		Transport: first.Transport, ListenerGeneration: first.ListenerGeneration,
		ServerName: first.ServerName, SPKIPins: append([]string(nil), first.SPKIPins...),
		Targets: targets, ValidFrom: first.ValidFrom, ValidUntil: first.ValidUntil,
	}
	if err := validateBootstrapOuterProbePlan(&plan); err != nil {
		return BootstrapOuterProbePlanV1{}, err
	}
	return plan, nil
}

func BootstrapOuterProbePlanHash(plan *BootstrapOuterProbePlanV1) (string, error) {
	if err := validateBootstrapOuterProbePlan(plan); err != nil {
		return "", err
	}
	return wire.HashObject(domainBootstrapOuterProbePlan, plan)
}

func BootstrapOuterEvidencePolicyHash(policy *BootstrapOuterEvidencePolicyV1) (string, error) {
	if err := validateBootstrapOuterEvidencePolicy(policy); err != nil {
		return "", err
	}
	return wire.HashObject(domainBootstrapOuterEvidencePolicy, policy)
}

// RunBootstrapOuterProbe 对计划中的每个 public IP:port 完成真实 TLS/QUIC
// outer handshake。它不解析 FQDN、不发送 auth header/password，也不测业务路径。
func RunBootstrapOuterProbe(ctx context.Context, plan *BootstrapOuterProbePlanV1,
	options BootstrapOuterProbeOptions) (SignedBootstrapOuterProbeObservationV1, error) {
	if ctx == nil || !validProbeIdentifier(options.ObserverID) || len(options.PrivateKey) != ed25519.PrivateKeySize ||
		options.TLSConfig == nil || options.Now == nil || options.Timeout < time.Second || options.Timeout > 30*time.Second {
		return SignedBootstrapOuterProbeObservationV1{}, errors.New("[D120 external verify] probe dependencies/timeout 无效")
	}
	if err := validateBootstrapOuterProbePlan(plan); err != nil {
		return SignedBootstrapOuterProbeObservationV1{}, err
	}
	if err := ctx.Err(); err != nil {
		return SignedBootstrapOuterProbeObservationV1{}, err
	}
	probePlanHash, err := BootstrapOuterProbePlanHash(plan)
	if err != nil {
		return SignedBootstrapOuterProbeObservationV1{}, err
	}
	startedAt := options.Now().UTC().Truncate(time.Second)
	validFrom, _ := wire.ParseTimeZ(plan.ValidFrom)
	validUntil, _ := wire.ParseTimeZ(plan.ValidUntil)
	if startedAt.Before(validFrom) || !startedAt.Before(validUntil) {
		return SignedBootstrapOuterProbeObservationV1{}, errors.New("[D120 external verify] probe plan 尚未生效或已过期")
	}
	tcpDial := options.TCPDial
	if tcpDial == nil {
		tcpDial = (&net.Dialer{}).DialContext
	}
	listenUDP := options.ListenUDP
	if listenUDP == nil {
		listenUDP = (&net.ListenConfig{}).ListenPacket
	}
	results := make([]BootstrapOuterProbeResultV1, 0, len(plan.Targets))
	for _, target := range plan.Targets {
		probeContext, cancel := context.WithTimeout(ctx, options.Timeout)
		state, err := probeBootstrapOuterTarget(probeContext, plan, target, options.TLSConfig,
			tcpDial, listenUDP, options.Timeout)
		cancel()
		if err != nil {
			return SignedBootstrapOuterProbeObservationV1{}, err
		}
		result, err := outerProbeResult(target, plan.Transport, state, plan.SPKIPins)
		if err != nil {
			return SignedBootstrapOuterProbeObservationV1{}, err
		}
		results = append(results, result)
	}
	observedAt := options.Now().UTC().Truncate(time.Second)
	if observedAt.Before(startedAt) || !observedAt.Before(validUntil) {
		return SignedBootstrapOuterProbeObservationV1{}, errors.New("[D120 external verify] probe 完成时间倒退或超出 listener validity")
	}
	publicKey := options.PrivateKey.Public().(ed25519.PublicKey)
	keyID, err := bootstrapOuterObserverKeyID(publicKey)
	if err != nil {
		return SignedBootstrapOuterProbeObservationV1{}, err
	}
	body := BootstrapOuterProbeObservationV1{
		Schema: 1, ClusterID: plan.ClusterID, ObserverID: options.ObserverID,
		ProbePlanHash: probePlanHash, ObservedAt: observedAt.Format(time.RFC3339), Results: results,
	}
	canonical, err := wire.MarshalCanonical(body)
	if err != nil {
		return SignedBootstrapOuterProbeObservationV1{}, err
	}
	message, err := wire.Frame(domainBootstrapOuterProbeSignature, canonical)
	if err != nil {
		return SignedBootstrapOuterProbeObservationV1{}, err
	}
	return SignedBootstrapOuterProbeObservationV1{Body: body, Signature: BootstrapOuterProbeSignatureV1{
		Algorithm: "ed25519", ObserverKeyID: keyID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(options.PrivateKey, message)),
	}}, nil
}

// VerifyBootstrapOuterReachability 要求 frozen policy 中足量且跨故障域的 observer
// 对 exact plan 全覆盖成功；单台 server 自报或只探到一个地址族都不能形成 evidence。
func VerifyBootstrapOuterReachability(policy *BootstrapOuterEvidencePolicyV1,
	authorized rotation.AuthorizedRuntimePlanV1, runtimePlan BootstrapIngressRuntimePlanV1,
	observations []SignedBootstrapOuterProbeObservationV1,
	trustedTime time.Time) (VerifiedBootstrapOuterReachabilityV1, error) {
	if trustedTime.IsZero() {
		return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 external verify] 可信验证时间缺失")
	}
	policyHash, err := BootstrapOuterEvidencePolicyHash(policy)
	if err != nil {
		return VerifiedBootstrapOuterReachabilityV1{}, err
	}
	intent := authorized.Intent()
	if policy.ClusterID != intent.ClusterID || policyHash != intent.FrozenDependencies.EvidencePolicyHash {
		return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D127 external verify] observer policy 未绑定 frozen rotation dependency")
	}
	plan, err := BuildBootstrapOuterProbePlan(runtimePlan, authorized)
	if err != nil {
		return VerifiedBootstrapOuterReachabilityV1{}, err
	}
	planHash, err := BootstrapOuterProbePlanHash(&plan)
	if err != nil {
		return VerifiedBootstrapOuterReachabilityV1{}, err
	}
	if len(observations) < int(policy.MinimumExternalObservers) ||
		len(observations) > len(policy.Observers) {
		return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 external verify] observer 数量未满足 frozen policy")
	}
	observerByID := make(map[string]BootstrapOuterObserverV1, len(policy.Observers))
	for _, observer := range policy.Observers {
		observerByID[observer.ObserverID] = observer
	}
	verifiedAt := trustedTime.UTC().Truncate(time.Second)
	planUntil, _ := wire.ParseTimeZ(plan.ValidUntil)
	evidenceUntil := planUntil
	failureDomains := make(map[string]struct{}, len(observations))
	cloned := make([]SignedBootstrapOuterProbeObservationV1, 0, len(observations))
	for index := range observations {
		signed := &observations[index]
		if index > 0 && observations[index-1].Body.ObserverID >= signed.Body.ObserverID {
			return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 external verify] observations 必须按 observer ID 严格排序")
		}
		observer, ok := observerByID[signed.Body.ObserverID]
		if !ok {
			return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 external verify] observation signer 不在 frozen policy")
		}
		observedAt, err := verifyBootstrapOuterObservation(signed, observer, &plan, planHash)
		if err != nil {
			return VerifiedBootstrapOuterReachabilityV1{}, err
		}
		observationUntil := observedAt.Add(time.Duration(policy.MaximumObservationAgeSeconds) * time.Second)
		if observedAt.After(verifiedAt) || !verifiedAt.Before(observationUntil) {
			return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 external verify] observation 来自未来或已过期")
		}
		if observationUntil.Before(evidenceUntil) {
			evidenceUntil = observationUntil
		}
		failureDomains[observer.FailureDomain] = struct{}{}
		cloned = append(cloned, cloneSignedBootstrapOuterObservation(*signed))
	}
	if int64(len(failureDomains)) < policy.MinimumExternalFailureDomains || !verifiedAt.Before(evidenceUntil) {
		return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 external verify] failure-domain 数量或 evidence 有效期不足")
	}
	evidence := BootstrapOuterReachabilityEvidenceV1{
		Schema: 1, ClusterID: plan.ClusterID, RotationID: plan.RotationID,
		EvidencePolicyHash: policyHash, ProbePlanHash: planHash,
		VerifiedAt: verifiedAt.Format(time.RFC3339), ValidUntil: evidenceUntil.UTC().Format(time.RFC3339),
		Observations: cloned,
	}
	hash, err := wire.HashObject(domainBootstrapOuterReachability, evidence)
	if err != nil {
		return VerifiedBootstrapOuterReachabilityV1{}, err
	}
	return VerifiedBootstrapOuterReachabilityV1{evidence: evidence, hash: hash}, nil
}

func (verified VerifiedBootstrapOuterReachabilityV1) EvidenceHash() string {
	return verified.hash
}

func (verified VerifiedBootstrapOuterReachabilityV1) Evidence() BootstrapOuterReachabilityEvidenceV1 {
	clone := verified.evidence
	clone.Observations = make([]SignedBootstrapOuterProbeObservationV1, 0, len(verified.evidence.Observations))
	for _, observation := range verified.evidence.Observations {
		clone.Observations = append(clone.Observations, cloneSignedBootstrapOuterObservation(observation))
	}
	return clone
}

// VerifyBootstrapOuterReachabilityEvidence 在 executor 重启或 control 接管后从
// 持久 artifact 重新验证全部签名；evidence 不能只凭已存 hash 恢复为可信对象。
func VerifyBootstrapOuterReachabilityEvidence(policy *BootstrapOuterEvidencePolicyV1,
	authorized rotation.AuthorizedRuntimePlanV1, runtimePlan BootstrapIngressRuntimePlanV1,
	evidence *BootstrapOuterReachabilityEvidenceV1) (VerifiedBootstrapOuterReachabilityV1, error) {
	if evidence == nil {
		return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 external verify] stored evidence 缺失")
	}
	verifiedAt, err := wire.ParseTimeZ(evidence.VerifiedAt)
	if err != nil {
		return VerifiedBootstrapOuterReachabilityV1{}, err
	}
	verified, err := VerifyBootstrapOuterReachability(policy, authorized, runtimePlan,
		evidence.Observations, verifiedAt)
	if err != nil {
		return VerifiedBootstrapOuterReachabilityV1{}, err
	}
	if !wire.EqualCanonical(verified.evidence, *evidence) {
		return VerifiedBootstrapOuterReachabilityV1{}, errors.New("[D120 external verify] stored evidence 与签名重算结果不一致")
	}
	return verified, nil
}

// validateAdvertiseTransition 防止已验外部证据被晚于有效期重放到另一次
// advertise；本地验证证据仍须由 node executor 独立产生并使用不同 hash。
func (verified VerifiedBootstrapOuterReachabilityV1) validateAdvertiseTransition(
	authorized rotation.AuthorizedRuntimePlanV1, transition *rotation.Transition) error {
	intent := authorized.Intent()
	if verified.hash == "" || verified.evidence.Schema != 1 || transition == nil ||
		transition.NextPhase != "advertised" || transition.ExternalVerificationEvidenceHash != verified.hash ||
		transition.LocalVerificationEvidenceHash == "" ||
		transition.LocalVerificationEvidenceHash == transition.ExternalVerificationEvidenceHash ||
		verified.evidence.ClusterID != intent.ClusterID || verified.evidence.RotationID != intent.RotationID ||
		verified.evidence.EvidencePolicyHash != intent.FrozenDependencies.EvidencePolicyHash {
		return errors.New("[D120 external verify] advertise transition 未绑定 verified external evidence")
	}
	certifiedAt, err := wire.ParseTimeZ(transition.CertifiedAt)
	if err != nil {
		return err
	}
	verifiedAt, _ := wire.ParseTimeZ(verified.evidence.VerifiedAt)
	validUntil, _ := wire.ParseTimeZ(verified.evidence.ValidUntil)
	if certifiedAt.Before(verifiedAt) || !certifiedAt.Before(validUntil) {
		return errors.New("[D120 external verify] advertise certification 不在 evidence 有效窗口")
	}
	return nil
}

func probeBootstrapOuterTarget(ctx context.Context, plan *BootstrapOuterProbePlanV1,
	target rotation.Tuple, roots *tls.Config, tcpDial DialContext, listenUDP UDPListenFunc,
	timeout time.Duration) (tls.ConnectionState, error) {
	config := roots.Clone()
	config.Certificates = nil
	config.GetClientCertificate = nil
	config.InsecureSkipVerify = false
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = nil
	config.ServerName = plan.ServerName
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	address := net.JoinHostPort(target.Address, fmt.Sprintf("%d", target.Port))
	if plan.Transport == "trojan_tls" {
		network := "tcp6"
		parsed, _ := netip.ParseAddr(target.Address)
		if parsed.Is4() {
			network = "tcp4"
		}
		raw, err := tcpDial(ctx, network, address)
		if err != nil || raw == nil {
			if err == nil {
				err = errors.New("拨号器返回 nil connection")
			}
			return tls.ConnectionState{}, fmt.Errorf("[D120 external verify] Trojan public tuple 不可达: %w", err)
		}
		connection := tls.Client(raw, config)
		err = connection.HandshakeContext(ctx)
		state := connection.ConnectionState()
		_ = connection.Close()
		if err != nil {
			return tls.ConnectionState{}, fmt.Errorf("[D120 external verify] Trojan outer TLS 失败: %w", err)
		}
		return state, nil
	}
	parsed, _ := netip.ParseAddr(target.Address)
	localAddress := "[::]:0"
	network := "udp6"
	if parsed.Is4() {
		localAddress = "0.0.0.0:0"
		network = "udp4"
	}
	packetConnection, err := listenUDP(ctx, network, localAddress)
	if err != nil || packetConnection == nil {
		if err == nil {
			err = errors.New("监听器返回 nil packet connection")
		}
		return tls.ConnectionState{}, fmt.Errorf("[D120 external verify] HY2 observer UDP socket 创建失败: %w", err)
	}
	defer packetConnection.Close()
	remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(parsed, uint16(target.Port)))
	config.NextProtos = []string{http3.NextProtoH3}
	connection, err := quic.Dial(ctx, packetConnection, remote, config, &quic.Config{
		HandshakeIdleTimeout: timeout, MaxIdleTimeout: timeout, EnableDatagrams: false, Allow0RTT: false,
	})
	if err != nil {
		return tls.ConnectionState{}, fmt.Errorf("[D120 external verify] Hysteria2 public tuple/QUIC TLS 不可达: %w", err)
	}
	state := connection.ConnectionState().TLS
	_ = connection.CloseWithError(0, "")
	return state, nil
}

func outerProbeResult(target rotation.Tuple, transport string, state tls.ConnectionState,
	pins []string) (BootstrapOuterProbeResultV1, error) {
	if state.Version != tls.VersionTLS13 || len(state.PeerCertificates) == 0 {
		return BootstrapOuterProbeResultV1{}, errors.New("[D122 external verify] outer transport 未使用 TLS 1.3/certificate")
	}
	digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	pin := "sha256:" + hex.EncodeToString(digest[:])
	if !slices.Contains(pins, pin) {
		return BootstrapOuterProbeResultV1{}, errors.New("[D122 external verify] leaf SPKI 不在 certified listener pin set")
	}
	wantProtocol := ""
	if transport == "hysteria2" {
		wantProtocol = http3.NextProtoH3
	}
	if state.NegotiatedProtocol != wantProtocol {
		return BootstrapOuterProbeResultV1{}, errors.New("[D122 external verify] outer transport ALPN 不匹配")
	}
	return BootstrapOuterProbeResultV1{Target: target, TLSVersion: int64(state.Version),
		NegotiatedProtocol: state.NegotiatedProtocol, LeafSPKIHash: pin}, nil
}

func verifyBootstrapOuterObservation(signed *SignedBootstrapOuterProbeObservationV1,
	observer BootstrapOuterObserverV1, plan *BootstrapOuterProbePlanV1,
	planHash string) (time.Time, error) {
	if signed == nil || signed.Body.Schema != 1 || signed.Body.ClusterID != plan.ClusterID ||
		signed.Body.ObserverID != observer.ObserverID || signed.Body.ProbePlanHash != planHash ||
		signed.Signature.Algorithm != "ed25519" || signed.Signature.ObserverKeyID != observer.ObserverKeyID ||
		len(signed.Body.Results) != len(plan.Targets) {
		return time.Time{}, errors.New("[D120 external verify] signed observation identity/coverage 无效")
	}
	observedAt, err := wire.ParseTimeZ(signed.Body.ObservedAt)
	if err != nil {
		return time.Time{}, err
	}
	validFrom, _ := wire.ParseTimeZ(plan.ValidFrom)
	validUntil, _ := wire.ParseTimeZ(plan.ValidUntil)
	if observedAt.Before(validFrom) || !observedAt.Before(validUntil) {
		return time.Time{}, errors.New("[D120 external verify] observation 不在 listener/catalog validity 内")
	}
	for index, result := range signed.Body.Results {
		if result.Target != plan.Targets[index] || result.TLSVersion != int64(tls.VersionTLS13) ||
			!slices.Contains(plan.SPKIPins, result.LeafSPKIHash) {
			return time.Time{}, errors.New("[D120 external verify] observation result 未覆盖 exact tuple/TLS identity")
		}
		wantProtocol := ""
		if plan.Transport == "hysteria2" {
			wantProtocol = http3.NextProtoH3
		}
		if result.NegotiatedProtocol != wantProtocol {
			return time.Time{}, errors.New("[D120 external verify] observation ALPN 与 transport 不匹配")
		}
	}
	publicKey, err := decodeObserverPublicKey(observer.ObserverPublicKey)
	if err != nil {
		return time.Time{}, err
	}
	rawSignature, err := base64.RawURLEncoding.DecodeString(signed.Signature.Signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(rawSignature) != signed.Signature.Signature {
		return time.Time{}, errors.New("[D120 external verify] observer signature encoding 无效")
	}
	canonical, err := wire.MarshalCanonical(signed.Body)
	if err != nil {
		return time.Time{}, err
	}
	message, err := wire.Frame(domainBootstrapOuterProbeSignature, canonical)
	if err != nil || !ed25519.Verify(publicKey, message, rawSignature) {
		return time.Time{}, errors.New("[D120 external verify] observer signature 无效")
	}
	return observedAt, nil
}

func validateBootstrapOuterProbePlan(plan *BootstrapOuterProbePlanV1) error {
	if plan == nil || plan.Schema != 1 || !validProbeIdentifier(plan.ClusterID) ||
		!validProbeIdentifier(plan.RotationID) || !validProbeIdentifier(plan.EndpointID) ||
		!validProbeIdentifier(plan.LogicalServerID) || plan.ListenerGeneration < 1 ||
		(plan.Transport != "hysteria2" && plan.Transport != "trojan_tls") ||
		!wire.ValidFQDN(plan.ServerName) || len(plan.SPKIPins) == 0 || len(plan.Targets) == 0 {
		return errors.New("[D120 external verify] probe plan header 无效")
	}
	for _, hash := range []string{plan.FrozenDependenciesHash, plan.EndpointSetHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	for index, pin := range plan.SPKIPins {
		if _, err := wire.ParseHash(pin); err != nil || index > 0 && plan.SPKIPins[index-1] >= pin {
			return errors.New("[D122 external verify] probe SPKI pins 非规范")
		}
	}
	validFrom, err := wire.ParseTimeZ(plan.ValidFrom)
	if err != nil {
		return err
	}
	validUntil, err := wire.ParseTimeZ(plan.ValidUntil)
	if err != nil || !validFrom.Before(validUntil) {
		return errors.New("[D120 external verify] probe validity 无效")
	}
	wantL4 := "tcp"
	if plan.Transport == "hysteria2" {
		wantL4 = "udp"
	}
	for index, target := range plan.Targets {
		address, err := netip.ParseAddr(target.Address)
		if err != nil || address.String() != target.Address || target.Transport != wantL4 ||
			target.Port < 1 || target.Port > 65535 || index > 0 && !runtimeTupleLess(plan.Targets[index-1], target) {
			return errors.New("[D103 external verify] public probe targets 非规范/错序/重复")
		}
	}
	return nil
}

func validateBootstrapOuterEvidencePolicy(policy *BootstrapOuterEvidencePolicyV1) error {
	if policy == nil || policy.Schema != 1 || !validProbeIdentifier(policy.ClusterID) ||
		!validProbeIdentifier(policy.PolicyID) || len(policy.Observers) == 0 ||
		len(policy.Observers) > bootstrapOuterProbeMaximumObservers || policy.MinimumExternalObservers < 1 ||
		policy.MinimumExternalObservers > int64(len(policy.Observers)) || policy.MinimumExternalFailureDomains < 1 ||
		policy.MinimumExternalFailureDomains > policy.MinimumExternalObservers ||
		policy.MaximumObservationAgeSeconds < 1 || policy.MaximumObservationAgeSeconds > 3600 {
		return errors.New("[D120 external verify] evidence policy header/threshold 无效")
	}
	seenKeys := make(map[string]struct{}, len(policy.Observers))
	domains := make(map[string]struct{}, len(policy.Observers))
	for index, observer := range policy.Observers {
		if !validProbeIdentifier(observer.ObserverID) || !validProbeIdentifier(observer.FailureDomain) ||
			index > 0 && policy.Observers[index-1].ObserverID >= observer.ObserverID {
			return errors.New("[D120 external verify] observers 必须按 ID 严格排序")
		}
		publicKey, err := decodeObserverPublicKey(observer.ObserverPublicKey)
		if err != nil {
			return err
		}
		keyID, err := bootstrapOuterObserverKeyID(publicKey)
		if err != nil || keyID != observer.ObserverKeyID {
			return errors.New("[D120 external verify] observer key ID/public key 不匹配")
		}
		if _, duplicate := seenKeys[keyID]; duplicate {
			return errors.New("[D120 external verify] observer public key 重复")
		}
		seenKeys[keyID] = struct{}{}
		domains[observer.FailureDomain] = struct{}{}
	}
	if int64(len(domains)) < policy.MinimumExternalFailureDomains {
		return errors.New("[D120 external verify] policy failure-domain 不足")
	}
	return nil
}

func decodeObserverPublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("[D120 external verify] observer public key encoding 无效")
	}
	return ed25519.PublicKey(raw), nil
}

func bootstrapOuterObserverKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("[D120 external verify] observer Ed25519 public key 长度无效")
	}
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validProbeIdentifier(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n\t")
}

func cloneSignedBootstrapOuterObservation(value SignedBootstrapOuterProbeObservationV1) SignedBootstrapOuterProbeObservationV1 {
	clone := value
	clone.Body.Results = append([]BootstrapOuterProbeResultV1(nil), value.Body.Results...)
	return clone
}
