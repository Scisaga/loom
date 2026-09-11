package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"loom/internal/wire"
)

const (
	domainRRSetIntent       = "loom-dns-rrset-intent-v1"
	domainRRSet             = "loom-dns-rrset-v1"
	domainReconcileEvidence = "loom-dns-reconcile-evidence-v1"
)

// CertifiedRRSetIntentV1 只描述已经由调用方验证过的 certified desired state；
// provider readback 和解析结果都不能反向构造该 authority（D103、D125）。
type CertifiedRRSetIntentV1 struct {
	Schema                  int    `json:"schema"`
	ClusterID               string `json:"cluster_id"`
	OperationID             string `json:"operation_id"`
	CertifiedHeadHash       string `json:"certified_head_hash"`
	PublicAccessProfileHash string `json:"public_access_profile_hash"`
	RRSet                   RRSet  `json:"rrset"`
	RRSetHash               string `json:"rrset_hash"`
}

type ResolverObservationV1 struct {
	Schema     int    `json:"schema"`
	ResolverID string `json:"resolver_id"`
	RRSet      RRSet  `json:"rrset"`
	ObservedAt string `json:"observed_at"`
}

type ReconcileEvidenceV1 struct {
	Schema              int                     `json:"schema"`
	IntentHash          string                  `json:"intent_hash"`
	ProviderObservation ResolverObservationV1   `json:"provider_observation"`
	ExternalResolvers   []ResolverObservationV1 `json:"external_resolvers"`
}

type ReconcileStateV1 struct {
	Schema       int                     `json:"schema"`
	ActiveIntent *CertifiedRRSetIntentV1 `json:"active_intent,omitempty"`
	Evidence     *ReconcileEvidenceV1    `json:"evidence,omitempty"`
	EvidenceHash string                  `json:"evidence_hash,omitempty"`
}

// Resolver 必须代表一个独立递归/权威观察点；ID 用于阻止把同一观察重复计数。
type Resolver interface {
	ID() string
	Resolve(ctx context.Context, zone, name, rrType string) (Readback, error)
}

type AuthorityVerifier func(intent *CertifiedRRSetIntentV1) error

type Reconciler struct {
	mu        sync.Mutex
	path      string
	provider  Provider
	resolvers []Resolver
	verify    AuthorityVerifier
	state     ReconcileStateV1
}

func OpenReconciler(path string, provider Provider, resolvers []Resolver, verify AuthorityVerifier) (*Reconciler, error) {
	if path == "" || provider == nil || verify == nil || len(resolvers) < 2 {
		return nil, errors.New("[D125 DNS] reconciler path/provider/authority verifier/双 resolver 缺失")
	}
	resolverCopy := append([]Resolver(nil), resolvers...)
	sort.Slice(resolverCopy, func(i, j int) bool { return resolverCopy[i].ID() < resolverCopy[j].ID() })
	for i, resolver := range resolverCopy {
		if resolver == nil || !validAuditID(resolver.ID()) || i > 0 && resolverCopy[i-1].ID() == resolver.ID() {
			return nil, errors.New("[D125 DNS] external resolver ID 无效或重复")
		}
	}
	reconciler := &Reconciler{
		path: path, provider: provider, resolvers: resolverCopy, verify: verify,
		state: ReconcileStateV1{Schema: 1},
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return reconciler, nil
	}
	if err != nil {
		return nil, err
	}
	var state ReconcileStateV1
	if _, err := wire.DecodeStrict(body, 4<<20, &state); err != nil {
		return nil, fmt.Errorf("[D125 DNS] reconcile state 损坏: %w", err)
	}
	if err := validateReconcileState(&state); err != nil {
		return nil, err
	}
	if state.ActiveIntent != nil {
		if err := verify(state.ActiveIntent); err != nil {
			return nil, fmt.Errorf("[D125 DNS] 磁盘 active intent 已失去 certified authority: %w", err)
		}
	}
	reconciler.state = state
	return reconciler, nil
}

func ValidateCertifiedRRSetIntent(intent *CertifiedRRSetIntentV1) error {
	if intent == nil || intent.Schema != 1 || !validAuditID(intent.ClusterID) || !validAuditID(intent.OperationID) {
		return errors.New("[D125 DNS] certified RRSet intent header 无效")
	}
	for _, hash := range []string{intent.CertifiedHeadHash, intent.PublicAccessProfileHash, intent.RRSetHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	normalized, err := Normalize(intent.RRSet)
	if err != nil || !equalExactRRSet(normalized, intent.RRSet) {
		return errors.New("[D125 DNS] intent RRSet 必须已规范化")
	}
	wantHash, err := RRSetHash(normalized)
	if err != nil || wantHash != intent.RRSetHash {
		return errors.New("[D125 DNS] intent RRSet hash 与 exact desired bytes 不匹配")
	}
	return nil
}

func CertifiedRRSetIntentHash(intent *CertifiedRRSetIntentV1) (string, error) {
	if err := ValidateCertifiedRRSetIntent(intent); err != nil {
		return "", err
	}
	return wire.HashObject(domainRRSetIntent, intent)
}

func (r *Reconciler) Snapshot() ReconcileStateV1 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneReconcileState(r.state)
}

// Reconcile 在 provider write+readback 后，还要求两个独立 resolver 返回 exact RRSet；
// 任一步失败都不替换已验证 LKG，也不把“DNS 已写”误报成 active（D108、D125）。
func (r *Reconciler) Reconcile(ctx context.Context, intent CertifiedRRSetIntentV1) (ReconcileStateV1, error) {
	if err := ValidateCertifiedRRSetIntent(&intent); err != nil {
		return ReconcileStateV1{}, err
	}
	if err := r.verify(&intent); err != nil {
		return ReconcileStateV1{}, fmt.Errorf("[D125 DNS] desired state 未获 certified authority: %w", err)
	}
	intentHash, _ := CertifiedRRSetIntentHash(&intent)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.ActiveIntent != nil {
		activeHash, _ := CertifiedRRSetIntentHash(r.state.ActiveIntent)
		if r.state.ActiveIntent.OperationID == intent.OperationID && activeHash != intentHash {
			return ReconcileStateV1{}, errors.New("[D125 DNS] 同一 operation ID 禁止改写 desired bytes")
		}
		if activeHash == intentHash {
			return cloneReconcileState(r.state), nil
		}
	}

	providerReadback, err := r.provider.Read(ctx, intent.RRSet.Zone, intent.RRSet.Name, intent.RRSet.Type)
	if errors.Is(err, ErrNotFound) || err == nil && !equalExactRRSet(providerReadback.RRSet, intent.RRSet) {
		providerReadback, err = r.provider.Replace(ctx, intent.RRSet)
	}
	if err != nil || providerReadback.ObservedAt.IsZero() || !equalExactRRSet(providerReadback.RRSet, intent.RRSet) {
		return ReconcileStateV1{}, errors.New("[D125 DNS] provider write/readback 未收敛到 exact desired RRSet")
	}
	evidence := ReconcileEvidenceV1{
		Schema: 1, IntentHash: intentHash,
		ProviderObservation: observation("provider", providerReadback),
		ExternalResolvers:   make([]ResolverObservationV1, 0, len(r.resolvers)),
	}
	for _, resolver := range r.resolvers {
		readback, err := resolver.Resolve(ctx, intent.RRSet.Zone, intent.RRSet.Name, intent.RRSet.Type)
		if err != nil || readback.ObservedAt.IsZero() || !equalExactRRSet(readback.RRSet, intent.RRSet) {
			return ReconcileStateV1{}, fmt.Errorf("[D125 DNS] external resolver %s 尚未观察到 exact desired RRSet", resolver.ID())
		}
		evidence.ExternalResolvers = append(evidence.ExternalResolvers, observation(resolver.ID(), readback))
	}
	evidenceHash, err := validateAndHashEvidence(&evidence, &intent)
	if err != nil {
		return ReconcileStateV1{}, err
	}
	candidate := ReconcileStateV1{Schema: 1, ActiveIntent: &intent, Evidence: &evidence, EvidenceHash: evidenceHash}
	if err := r.persistLocked(candidate); err != nil {
		return ReconcileStateV1{}, err
	}
	r.state = candidate
	return cloneReconcileState(candidate), nil
}

func observation(id string, readback Readback) ResolverObservationV1 {
	return ResolverObservationV1{
		Schema: 1, ResolverID: id, RRSet: readback.RRSet,
		ObservedAt: readback.ObservedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
}

func validateAndHashEvidence(evidence *ReconcileEvidenceV1, intent *CertifiedRRSetIntentV1) (string, error) {
	intentHash, err := CertifiedRRSetIntentHash(intent)
	if err != nil || evidence == nil || evidence.Schema != 1 || evidence.IntentHash != intentHash ||
		evidence.ProviderObservation.ResolverID != "provider" || len(evidence.ExternalResolvers) < 2 {
		return "", errors.New("[D125 DNS] reconcile evidence header 无效")
	}
	all := append([]ResolverObservationV1{evidence.ProviderObservation}, evidence.ExternalResolvers...)
	for i := range all {
		item := &all[i]
		if item.Schema != 1 || !validAuditID(item.ResolverID) || !equalExactRRSet(item.RRSet, intent.RRSet) {
			return "", errors.New("[D125 DNS] reconcile observation identity/RRSet 无效")
		}
		if _, err := wire.ParseTimeZ(item.ObservedAt); err != nil {
			return "", err
		}
		if i > 1 && all[i-1].ResolverID >= item.ResolverID {
			return "", errors.New("[D125 DNS] external resolver observations 必须严格排序")
		}
	}
	return wire.HashObject(domainReconcileEvidence, evidence)
}

func validateReconcileState(state *ReconcileStateV1) error {
	if state == nil || state.Schema != 1 || (state.ActiveIntent == nil) != (state.Evidence == nil) ||
		(state.ActiveIntent == nil) != (state.EvidenceHash == "") {
		return errors.New("[D125 DNS] reconcile state shape 无效")
	}
	if state.ActiveIntent == nil {
		return nil
	}
	hash, err := validateAndHashEvidence(state.Evidence, state.ActiveIntent)
	if err != nil || hash != state.EvidenceHash {
		return errors.New("[D125 DNS] persisted evidence hash 无效")
	}
	return nil
}

func (r *Reconciler) persistLocked(state ReconcileStateV1) error {
	if err := validateReconcileState(&state); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(r.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, filepath.Base(r.path)+".tmp-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, r.path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func RRSetHash(set RRSet) (string, error) {
	normalized, err := Normalize(set)
	if err != nil || !equalExactRRSet(normalized, set) {
		return "", errors.New("[D125 DNS] RRSet hash 输入必须已规范化")
	}
	return wire.HashObject(domainRRSet, set)
}

func equalExactRRSet(left, right RRSet) bool {
	if left.Zone != right.Zone || left.Name != right.Name || left.Type != right.Type || left.TTL != right.TTL || len(left.Values) != len(right.Values) {
		return false
	}
	for i := range left.Values {
		if left.Values[i] != right.Values[i] {
			return false
		}
	}
	return true
}

func validAuditID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func cloneReconcileState(state ReconcileStateV1) ReconcileStateV1 {
	body, _ := wire.MarshalCanonical(state)
	var clone ReconcileStateV1
	_, _ = wire.DecodeStrict(body, 4<<20, &clone)
	return clone
}
