package bootstrapaccess

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"loom/internal/rotation"
	"loom/internal/wire"
)

const (
	domainBootstrapLocalReadiness = "loom-bootstrap-local-readiness-evidence-v1"
	bootstrapLocalReadinessAge    = time.Minute
)

type BootstrapLocalReadinessResultV1 struct {
	BindingHash        string         `json:"binding_hash"`
	BindTuple          rotation.Tuple `json:"bind_tuple"`
	DialTuple          rotation.Tuple `json:"dial_tuple"`
	TLSVersion         int64          `json:"tls_version"`
	NegotiatedProtocol string         `json:"negotiated_protocol"`
	LeafSPKIHash       string         `json:"leaf_spki_hash"`
}

type BootstrapLocalReadinessEvidenceV1 struct {
	Schema                 int                               `json:"schema"`
	ClusterID              string                            `json:"cluster_id"`
	RotationID             string                            `json:"rotation_id"`
	FrozenDependenciesHash string                            `json:"frozen_dependencies_hash"`
	CertifiedStateHash     string                            `json:"certified_state_hash"`
	EndpointSetHash        string                            `json:"endpoint_set_hash"`
	EndpointID             string                            `json:"endpoint_id"`
	LogicalServerID        string                            `json:"logical_server_id"`
	Transport              string                            `json:"transport"`
	ListenerGeneration     int64                             `json:"listener_generation"`
	VerifiedAt             string                            `json:"verified_at"`
	ValidUntil             string                            `json:"valid_until"`
	Results                []BootstrapLocalReadinessResultV1 `json:"results"`
}

// VerifiedBootstrapLocalReadinessV1 只能由 exact opaque runtime plan 的真实
// local socket handshake 产生；调用方不能用一个格式合法的 hash 构造。
type VerifiedBootstrapLocalReadinessV1 struct {
	evidence BootstrapLocalReadinessEvidenceV1
	hash     string
}

type BootstrapLocalReadinessOptions struct {
	TLSConfig *tls.Config
	Now       func() time.Time
	Timeout   time.Duration
}

// VerifyBootstrapLocalReadiness 对 runtime.Start 已同步 bind 的每个本地 socket
// 完成无 bearer TLS/QUIC 握手。wildcard bind 只投影为同地址族 loopback，不扩大端口。
func VerifyBootstrapLocalReadiness(ctx context.Context, runtime *BootstrapIngressRuntime,
	authorized rotation.AuthorizedRuntimePlanV1,
	options BootstrapLocalReadinessOptions) (VerifiedBootstrapLocalReadinessV1, error) {
	if ctx == nil || options.TLSConfig == nil || options.Now == nil ||
		options.Timeout < time.Second || options.Timeout > 30*time.Second {
		return VerifiedBootstrapLocalReadinessV1{}, errors.New("[local verify] dependencies/timeout 无效")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedBootstrapLocalReadinessV1{}, err
	}
	runtimePlan, err := runtime.runningPlan()
	if err != nil {
		return VerifiedBootstrapLocalReadinessV1{}, err
	}
	outerPlan, err := BuildBootstrapOuterProbePlan(runtimePlan, authorized)
	if err != nil {
		return VerifiedBootstrapLocalReadinessV1{}, err
	}
	bindings := runtimePlan.Bindings()
	startedAt := options.Now().UTC().Truncate(time.Second)
	validFrom, _ := wire.ParseTimeZ(outerPlan.ValidFrom)
	listenerValidUntil, _ := wire.ParseTimeZ(outerPlan.ValidUntil)
	if startedAt.Before(validFrom) || !startedAt.Before(listenerValidUntil) {
		return VerifiedBootstrapLocalReadinessV1{}, errors.New("[local verify] listener 尚未生效或已过期")
	}
	tcpDial := (&net.Dialer{}).DialContext
	listenUDP := (&net.ListenConfig{}).ListenPacket
	probePlan := outerPlan
	results := make([]BootstrapLocalReadinessResultV1, 0, len(bindings))
	for _, binding := range bindings {
		dialTuple, err := bootstrapLocalDialTuple(binding.projection.BindTuple)
		if err != nil {
			return VerifiedBootstrapLocalReadinessV1{}, err
		}
		probeContext, cancel := context.WithTimeout(ctx, options.Timeout)
		state, err := probeBootstrapOuterTarget(probeContext, &probePlan, dialTuple,
			options.TLSConfig, tcpDial, listenUDP, options.Timeout)
		cancel()
		if err != nil {
			return VerifiedBootstrapLocalReadinessV1{}, fmt.Errorf("[local verify] local socket handshake 失败: %w", err)
		}
		verified, err := outerProbeResult(dialTuple, probePlan.Transport, state, probePlan.SPKIPins)
		if err != nil {
			return VerifiedBootstrapLocalReadinessV1{}, err
		}
		results = append(results, BootstrapLocalReadinessResultV1{
			BindingHash: binding.bindingHash, BindTuple: binding.projection.BindTuple, DialTuple: dialTuple,
			TLSVersion: verified.TLSVersion, NegotiatedProtocol: verified.NegotiatedProtocol,
			LeafSPKIHash: verified.LeafSPKIHash,
		})
	}
	verifiedAt := options.Now().UTC().Truncate(time.Second)
	if verifiedAt.Before(startedAt) || !verifiedAt.Before(listenerValidUntil) {
		return VerifiedBootstrapLocalReadinessV1{}, errors.New("[local verify] 完成时间倒退或超出 listener validity")
	}
	validUntil := verifiedAt.Add(bootstrapLocalReadinessAge)
	if listenerValidUntil.Before(validUntil) {
		validUntil = listenerValidUntil
	}
	state := authorized.State()
	stateHash, err := wire.HashObject(rotation.DomainState, state)
	if err != nil {
		return VerifiedBootstrapLocalReadinessV1{}, err
	}
	evidence := BootstrapLocalReadinessEvidenceV1{
		Schema: 1, ClusterID: outerPlan.ClusterID, RotationID: outerPlan.RotationID,
		FrozenDependenciesHash: outerPlan.FrozenDependenciesHash, CertifiedStateHash: stateHash,
		EndpointSetHash: outerPlan.EndpointSetHash, EndpointID: outerPlan.EndpointID,
		LogicalServerID: outerPlan.LogicalServerID, Transport: outerPlan.Transport,
		ListenerGeneration: outerPlan.ListenerGeneration, VerifiedAt: verifiedAt.Format(time.RFC3339),
		ValidUntil: validUntil.Format(time.RFC3339), Results: results,
	}
	hash, err := wire.HashObject(domainBootstrapLocalReadiness, evidence)
	if err != nil {
		return VerifiedBootstrapLocalReadinessV1{}, err
	}
	return VerifiedBootstrapLocalReadinessV1{evidence: evidence, hash: hash}, nil
}

func (verified VerifiedBootstrapLocalReadinessV1) EvidenceHash() string {
	return verified.hash
}

func (verified VerifiedBootstrapLocalReadinessV1) Evidence() BootstrapLocalReadinessEvidenceV1 {
	clone := verified.evidence
	clone.Results = append([]BootstrapLocalReadinessResultV1(nil), verified.evidence.Results...)
	return clone
}

// validateAdvertiseTransition 要求 advertise 精确引用刚从 prepared runtime
// 验出的 local evidence，并限制其只能用于同一 certified state 的短窗口。
func (verified VerifiedBootstrapLocalReadinessV1) validateAdvertiseTransition(
	authorized rotation.AuthorizedRuntimePlanV1, transition *rotation.Transition) error {
	intent := authorized.Intent()
	state := authorized.State()
	stateHash, err := wire.HashObject(rotation.DomainState, state)
	if err != nil {
		return err
	}
	if verified.hash == "" || verified.evidence.Schema != 1 || transition == nil ||
		state.Phase != "prepared" || transition.NextPhase != "advertised" ||
		transition.LocalVerificationEvidenceHash != verified.hash ||
		transition.ExternalVerificationEvidenceHash == "" ||
		transition.ExternalVerificationEvidenceHash == transition.LocalVerificationEvidenceHash ||
		verified.evidence.ClusterID != intent.ClusterID || verified.evidence.RotationID != intent.RotationID ||
		verified.evidence.FrozenDependenciesHash != intent.FrozenDependenciesHash ||
		verified.evidence.EndpointSetHash != intent.ExpectedEndpointSetHash ||
		verified.evidence.CertifiedStateHash != stateHash ||
		verified.evidence.EndpointID != intent.FrozenDependencies.EndpointID ||
		verified.evidence.LogicalServerID != intent.FrozenDependencies.LogicalServerID ||
		verified.evidence.Transport != intent.FrozenDependencies.Transport ||
		len(verified.evidence.Results) == 0 ||
		verified.evidence.ListenerGeneration != state.TargetListenerGeneration {
		return errors.New("[local verify] advertise transition 未绑定 verified local readiness")
	}
	wantHash, err := wire.HashObject(domainBootstrapLocalReadiness, verified.evidence)
	if err != nil || wantHash != verified.hash {
		return errors.New("[local verify] local readiness evidence/hash 不一致")
	}
	verifiedAt, err := wire.ParseTimeZ(verified.evidence.VerifiedAt)
	if err != nil {
		return err
	}
	validUntil, err := wire.ParseTimeZ(verified.evidence.ValidUntil)
	if err != nil {
		return err
	}
	certifiedAt, err := wire.ParseTimeZ(transition.CertifiedAt)
	if err != nil || certifiedAt.Before(verifiedAt) || !certifiedAt.Before(validUntil) {
		return errors.New("[local verify] advertise certification 不在 local readiness 有效窗口")
	}
	return nil
}

// ValidateBootstrapAdvertiseTransition 把 local 与 external 两份独立证据设为同一
// advertise 的必要条件；任何一侧的裸 hash 都不能代替 verified artifact。
func ValidateBootstrapAdvertiseTransition(authorized rotation.AuthorizedRuntimePlanV1,
	transition *rotation.Transition, local VerifiedBootstrapLocalReadinessV1,
	external VerifiedBootstrapOuterReachabilityV1) error {
	if err := local.validateAdvertiseTransition(authorized, transition); err != nil {
		return err
	}
	return external.validateAdvertiseTransition(authorized, transition)
}

func bootstrapLocalDialTuple(binding rotation.Tuple) (rotation.Tuple, error) {
	address, err := netip.ParseAddr(binding.Address)
	if err != nil || address.String() != binding.Address {
		return rotation.Tuple{}, errors.New("[local verify] bind tuple address 无效")
	}
	dial := binding
	if address.IsUnspecified() {
		if address.Is4() {
			dial.Address = netip.MustParseAddr("127.0.0.1").String()
		} else {
			dial.Address = netip.IPv6Loopback().String()
		}
	}
	return dial, nil
}
