package bootstrapaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"sync"

	"loom/internal/wire"
)

// credentialBinding 是 transport adapter 可见的最小认证投影。字段保持私有，
// 防止调用方把短期 bearer 整体格式化进日志或 diagnostics。
type credentialBinding struct {
	capabilityID string
	credential   string
	verified     wire.VerifiedBootstrapCapabilityV1
}

// CredentialRegistry 保存一个 certified ingress set 当前允许的 capability 集合。
// Replace 构造完整候选后一次换指针，避免 reconcile 中途出现半新半旧认证表。
type CredentialRegistry struct {
	mu             sync.RWMutex
	ingressSetHash string
	byCredential   map[string]credentialBinding
	byTrojanKey    map[[trojanKeyLength]byte]credentialBinding
	resolve        CapabilityResolver
}

// CapabilityResolver 只能返回 wire 完整验证产生的 opaque evidence。transport
// authentication 会在 registry 内再次精确匹配，避免私有服务响应替换 capability。
type CapabilityResolver func(context.Context, wire.BootstrapCapabilityLookupRequestV1) (wire.VerifiedBootstrapCapabilityV1, error)

const trojanKeyLength = sha256.Size224 * 2

func NewCredentialRegistry(ingressSetHash string,
	capabilities []wire.VerifiedBootstrapCapabilityV1) (*CredentialRegistry, error) {
	return NewCredentialRegistryWithResolver(ingressSetHash, capabilities, nil)
}

func NewCredentialRegistryWithResolver(ingressSetHash string,
	capabilities []wire.VerifiedBootstrapCapabilityV1, resolve CapabilityResolver) (*CredentialRegistry, error) {
	registry := &CredentialRegistry{resolve: resolve}
	if err := registry.replace(ingressSetHash, capabilities); err != nil {
		return nil, err
	}
	return registry, nil
}

// Replace 只接受 wire verifier 产生的 opaque evidence；zero value 或属于另一个
// ingress set 的 capability 会使整批更新失败，旧认证表保持不变。
func (registry *CredentialRegistry) Replace(ingressSetHash string,
	capabilities []wire.VerifiedBootstrapCapabilityV1) error {
	if registry == nil {
		return errors.New("[capability] credential registry 缺失")
	}
	return registry.replace(ingressSetHash, capabilities)
}

func (registry *CredentialRegistry) replace(ingressSetHash string,
	capabilities []wire.VerifiedBootstrapCapabilityV1) error {
	if _, err := wire.ParseHash(ingressSetHash); err != nil {
		return errors.New("[capability] credential registry ingress set hash 无效")
	}
	candidate := make(map[string]credentialBinding, len(capabilities))
	trojanCandidate := make(map[[trojanKeyLength]byte]credentialBinding, len(capabilities))
	seenIDs := make(map[string]struct{}, len(capabilities))
	for _, verified := range capabilities {
		body := verified.Body()
		capabilityID := verified.CapabilityID()
		credential := verified.TransportCredential()
		if _, err := wire.ParseHash(capabilityID); err != nil ||
			body.AllowedIngressSetHash != ingressSetHash || credential == "" {
			return errors.New("[capability] credential registry 收到未验证或跨 ingress capability")
		}
		if _, exists := seenIDs[capabilityID]; exists {
			return errors.New("[capability] credential registry capability ID 重复")
		}
		if _, exists := candidate[credential]; exists {
			return errors.New("[capability] credential registry transport credential 冲突")
		}
		seenIDs[capabilityID] = struct{}{}
		binding := credentialBinding{
			capabilityID: capabilityID, credential: credential, verified: verified,
		}
		key := trojanCredentialKey(credential)
		if _, exists := trojanCandidate[key]; exists {
			return errors.New("[capability] credential registry Trojan key 冲突")
		}
		candidate[credential] = binding
		trojanCandidate[key] = binding
	}
	registry.mu.Lock()
	registry.ingressSetHash = ingressSetHash
	registry.byCredential = candidate
	registry.byTrojanKey = trojanCandidate
	registry.mu.Unlock()
	return nil
}

// openTrojanSession 在同一个 registry read lock 下完成 key lookup 与 durable
// OpenSession。Replace 一旦返回，任何尚未落盘的新连接都不可能再使用旧表。
func (registry *CredentialRegistry) openTrojanSession(ctx context.Context, manager *Manager,
	key [trojanKeyLength]byte, sessionID string) (*Session, error) {
	if registry == nil || manager == nil {
		return nil, errors.New("[capability] Trojan credential/session manager 缺失")
	}
	registry.mu.RLock()
	binding, ok := registry.byTrojanKey[key]
	ingressSetHash, resolve := registry.ingressSetHash, registry.resolve
	if resolve == nil {
		if !ok {
			registry.mu.RUnlock()
			return nil, errors.New("[capability] Trojan transport credential 无效")
		}
		session, err := manager.OpenSession(binding.verified, sessionID, ingressSetHash)
		registry.mu.RUnlock()
		return session, err
	}
	registry.mu.RUnlock()
	verified, err := resolve(ctx, wire.BootstrapCapabilityLookupRequestV1{Schema: 1,
		IngressSetHash: ingressSetHash, Transport: "trojan_tls", Authentication: string(key[:])})
	if err != nil || verified.Body().AllowedIngressSetHash != ingressSetHash ||
		trojanCredentialKey(verified.TransportCredential()) != key {
		return nil, errors.New("[capability] Trojan transport credential 无效")
	}
	registry.mu.RLock()
	if registry.ingressSetHash != ingressSetHash {
		registry.mu.RUnlock()
		return nil, errors.New("[capability] Trojan ingress set 已变化")
	}
	session, err := manager.OpenSession(verified, sessionID, ingressSetHash)
	registry.mu.RUnlock()
	return session, err
}

// openHysteria2Session 与 Trojan 路径共享同一个撤销竞态边界，但 HY2 的认证
// header 能直接携带 transport credential，不需要协议 SHA-224 key。
func (registry *CredentialRegistry) openHysteria2Session(ctx context.Context, manager *Manager,
	credential, sessionID string) (*Session, error) {
	if registry == nil || manager == nil || credential == "" {
		return nil, errors.New("[capability] Hysteria2 credential/session manager 缺失")
	}
	registry.mu.RLock()
	binding, ok := registry.byCredential[credential]
	ingressSetHash, resolve := registry.ingressSetHash, registry.resolve
	if resolve == nil {
		if !ok {
			registry.mu.RUnlock()
			return nil, errors.New("[capability] Hysteria2 transport credential 无效")
		}
		session, err := manager.OpenSession(binding.verified, sessionID, ingressSetHash)
		registry.mu.RUnlock()
		return session, err
	}
	registry.mu.RUnlock()
	verified, err := resolve(ctx, wire.BootstrapCapabilityLookupRequestV1{Schema: 1,
		IngressSetHash: ingressSetHash, Transport: "hysteria2", Authentication: credential})
	if err != nil || verified.Body().AllowedIngressSetHash != ingressSetHash ||
		verified.TransportCredential() != credential {
		return nil, errors.New("[capability] Hysteria2 transport credential 无效")
	}
	registry.mu.RLock()
	if registry.ingressSetHash != ingressSetHash {
		registry.mu.RUnlock()
		return nil, errors.New("[capability] Hysteria2 ingress set 已变化")
	}
	session, err := manager.OpenSession(verified, sessionID, ingressSetHash)
	registry.mu.RUnlock()
	return session, err
}

func trojanCredentialKey(credential string) [trojanKeyLength]byte {
	digest := sha256.Sum224([]byte(credential))
	var key [trojanKeyLength]byte
	hex.Encode(key[:], digest[:])
	return key
}

// authenticate 的 bool 是唯一认证结果；调用方不得记录 credential 本身。
func (registry *CredentialRegistry) authenticate(credential string) (wire.VerifiedBootstrapCapabilityV1, bool) {
	if registry == nil || credential == "" {
		return wire.VerifiedBootstrapCapabilityV1{}, false
	}
	registry.mu.RLock()
	binding, ok := registry.byCredential[credential]
	registry.mu.RUnlock()
	return binding.verified, ok
}

func (registry *CredentialRegistry) IngressSetHash() string {
	if registry == nil {
		return ""
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.ingressSetHash
}

// snapshot 返回稳定排序的 adapter 输入；不得把返回值序列化或输出到 diagnostics。
func (registry *CredentialRegistry) snapshot() []credentialBinding {
	if registry == nil {
		return nil
	}
	registry.mu.RLock()
	values := make([]credentialBinding, 0, len(registry.byCredential))
	for _, binding := range registry.byCredential {
		values = append(values, binding)
	}
	registry.mu.RUnlock()
	sort.Slice(values, func(i, j int) bool { return values[i].capabilityID < values[j].capabilityID })
	return values
}
