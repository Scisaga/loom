package bootstrapaccess

import (
	"errors"
	"sort"
	"sync"

	"loom/internal/wire"
)

// CredentialBindingV1 是 transport adapter 可见的最小认证投影。Credential 只可
// 交给协议认证器，不得进入日志、状态文件或 diagnostics（D115、D131）。
type CredentialBindingV1 struct {
	CapabilityID string
	Credential   string
	Verified     wire.VerifiedBootstrapCapabilityV1
}

// CredentialRegistry 保存一个 certified ingress set 当前允许的 capability 集合。
// Replace 构造完整候选后一次换指针，避免 reconcile 中途出现半新半旧认证表（D127、D131）。
type CredentialRegistry struct {
	mu             sync.RWMutex
	ingressSetHash string
	byCredential   map[string]CredentialBindingV1
}

func NewCredentialRegistry(ingressSetHash string,
	capabilities []wire.VerifiedBootstrapCapabilityV1) (*CredentialRegistry, error) {
	registry := &CredentialRegistry{}
	if err := registry.replace(ingressSetHash, capabilities); err != nil {
		return nil, err
	}
	return registry, nil
}

// Replace 只接受 wire verifier 产生的 opaque evidence；zero value 或属于另一个
// ingress set 的 capability 会使整批更新失败，旧认证表保持不变（D131）。
func (registry *CredentialRegistry) Replace(ingressSetHash string,
	capabilities []wire.VerifiedBootstrapCapabilityV1) error {
	if registry == nil {
		return errors.New("[D131 capability] credential registry 缺失")
	}
	return registry.replace(ingressSetHash, capabilities)
}

func (registry *CredentialRegistry) replace(ingressSetHash string,
	capabilities []wire.VerifiedBootstrapCapabilityV1) error {
	if _, err := wire.ParseHash(ingressSetHash); err != nil {
		return errors.New("[D131 capability] credential registry ingress set hash 无效")
	}
	candidate := make(map[string]CredentialBindingV1, len(capabilities))
	seenIDs := make(map[string]struct{}, len(capabilities))
	for _, verified := range capabilities {
		body := verified.Body()
		capabilityID := verified.CapabilityID()
		credential := verified.TransportCredential()
		if _, err := wire.ParseHash(capabilityID); err != nil ||
			body.AllowedIngressSetHash != ingressSetHash || credential == "" {
			return errors.New("[D131 capability] credential registry 收到未验证或跨 ingress capability")
		}
		if _, exists := seenIDs[capabilityID]; exists {
			return errors.New("[D131 capability] credential registry capability ID 重复")
		}
		if _, exists := candidate[credential]; exists {
			return errors.New("[D131 capability] credential registry transport credential 冲突")
		}
		seenIDs[capabilityID] = struct{}{}
		candidate[credential] = CredentialBindingV1{
			CapabilityID: capabilityID, Credential: credential, Verified: verified,
		}
	}
	registry.mu.Lock()
	registry.ingressSetHash = ingressSetHash
	registry.byCredential = candidate
	registry.mu.Unlock()
	return nil
}

// Authenticate 的 bool 是唯一认证结果；调用方不得记录 credential 本身。
func (registry *CredentialRegistry) Authenticate(credential string) (CredentialBindingV1, bool) {
	if registry == nil || credential == "" {
		return CredentialBindingV1{}, false
	}
	registry.mu.RLock()
	binding, ok := registry.byCredential[credential]
	registry.mu.RUnlock()
	return binding, ok
}

func (registry *CredentialRegistry) IngressSetHash() string {
	if registry == nil {
		return ""
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.ingressSetHash
}

// Snapshot 返回稳定排序的 adapter 输入；不应把返回值序列化或输出到 diagnostics。
func (registry *CredentialRegistry) Snapshot() []CredentialBindingV1 {
	if registry == nil {
		return nil
	}
	registry.mu.RLock()
	values := make([]CredentialBindingV1, 0, len(registry.byCredential))
	for _, binding := range registry.byCredential {
		values = append(values, binding)
	}
	registry.mu.RUnlock()
	sort.Slice(values, func(i, j int) bool { return values[i].CapabilityID < values[j].CapabilityID })
	return values
}
