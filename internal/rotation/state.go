// Package rotation 实现公网 listener 的确定性生命周期 reducer。
// 它不查询端口、时钟或网络；所有输入必须先进入 certified operation，executor
// 只能按 reducer 输出幂等收敛外部资源（D120、D127）。
package rotation

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"loom/internal/wire"
)

const (
	DomainFrozenDependencies = "loom-listener-rotation-frozen-dependencies-v1"
	DomainIntent             = "loom-listener-rotation-intent-v1"
	DomainGuard              = "loom-listener-retirement-guard-v1"
	DomainGuardLeaf          = "loom-listener-retirement-dependency-leaf-v1"
	DomainState              = "loom-listener-rotation-state-v1"
)

type FrozenDependenciesV1 struct {
	Schema                                int      `json:"schema"`
	ClusterID                             string   `json:"cluster_id"`
	EndpointKind                          string   `json:"endpoint_kind"`
	EndpointSetID                         string   `json:"endpoint_set_id"`
	EndpointID                            string   `json:"endpoint_id"`
	LogicalServerID                       string   `json:"logical_server_id"`
	Transport                             string   `json:"transport"`
	SourceListenerGeneration              *int64   `json:"source_listener_generation,omitempty"`
	SourceListenerGenerationHash          string   `json:"source_listener_generation_hash,omitempty"`
	TargetListenerGeneration              int64    `json:"target_listener_generation"`
	LogicalPublicEndpointIntentHash       string   `json:"logical_public_endpoint_intent_hash"`
	PublicAccessProfileHash               string   `json:"public_access_profile_hash"`
	DNSAddressBindingHash                 string   `json:"dns_address_binding_hash"`
	CertificateIdentityProjectionHash     string   `json:"certificate_identity_projection_hash"`
	CredentialArtifactRefsRoot            string   `json:"credential_artifact_refs_root"`
	RenderContractHash                    string   `json:"render_contract_hash"`
	EvidencePolicyHash                    string   `json:"evidence_policy_hash"`
	PortPoolHash                          string   `json:"port_pool_hash"`
	FirewallPolicyHash                    string   `json:"firewall_policy_hash"`
	ForwardListenerResourceGenerationHash string   `json:"forward_listener_resource_generation_hash"`
	PortMappingIntentHash                 string   `json:"port_mapping_intent_hash,omitempty"`
	LinkIntentHashes                      []string `json:"link_intent_hashes"`
}

type IntentV1 struct {
	Schema                  int                  `json:"schema"`
	ClusterID               string               `json:"cluster_id"`
	RotationID              string               `json:"rotation_id"`
	OperationID             string               `json:"operation_id"`
	BaseHeadHash            string               `json:"base_head_hash"`
	ExpectedEndpointSetHash string               `json:"expected_endpoint_set_hash"`
	FrozenDependencies      FrozenDependenciesV1 `json:"frozen_dependencies"`
	FrozenDependenciesHash  string               `json:"frozen_dependencies_hash"`
	AdvertiseNotBefore      string               `json:"advertise_not_before"`
	PreferNotBefore         string               `json:"prefer_not_before"`
	DrainNotBefore          string               `json:"drain_not_before"`
	DrainNotAfter           string               `json:"drain_not_after"`
	RetireNotBefore         string               `json:"retire_not_before"`
	MinimumReaderFloor      int64                `json:"minimum_reader_floor"`
}

type RetirementDependencyLeafV1 struct {
	Schema            int    `json:"schema"`
	Kind              string `json:"kind"`
	ObjectHash        string `json:"object_hash"`
	ReferenceNotAfter string `json:"reference_not_after"`
}

type RetirementGuardV1 struct {
	Schema                       int                          `json:"schema"`
	ClusterID                    string                       `json:"cluster_id"`
	RotationID                   string                       `json:"rotation_id"`
	RotationIntentHash           string                       `json:"rotation_intent_hash"`
	SourceListenerGenerationHash string                       `json:"source_listener_generation_hash"`
	ReferenceCutoffHeadHash      string                       `json:"reference_cutoff_head_hash"`
	Dependencies                 []RetirementDependencyLeafV1 `json:"dependencies"`
	DependencyLeafCount          int64                        `json:"dependency_leaf_count"`
	DependencyRoot               string                       `json:"dependency_root"`
	MaximumReferenceNotAfter     string                       `json:"maximum_reference_not_after"`
	MinimumReaderFloor           int64                        `json:"minimum_reader_floor"`
	OfflineGraceNotBefore        string                       `json:"offline_grace_not_before"`
	QuietNotBefore               string                       `json:"quiet_not_before"`
	BackupRetainUntil            string                       `json:"backup_retain_until"`
}

type StateV1 struct {
	Schema                   int    `json:"schema"`
	ClusterID                string `json:"cluster_id"`
	RotationID               string `json:"rotation_id"`
	RotationIntentHash       string `json:"rotation_intent_hash"`
	FrozenDependenciesHash   string `json:"frozen_dependencies_hash"`
	Phase                    string `json:"phase"`
	SourceListenerGeneration *int64 `json:"source_listener_generation,omitempty"`
	TargetListenerGeneration int64  `json:"target_listener_generation"`
	RetirementGuardHash      string `json:"retirement_guard_hash,omitempty"`
	LastTransitionHeadHash   string `json:"last_transition_head_hash"`
	EvidenceRefsRoot         string `json:"evidence_refs_root"`
}

type Transition struct {
	NextPhase         string
	CertifiedHeadHash string
	CertifiedAt       string
	EvidenceRefs      []string
	ReaderFloor       int64
	Guard             *RetirementGuardV1
	Emergency         bool
}

func Allocate(intent IntentV1, certifiedHeadHash string) (StateV1, error) {
	if err := ValidateIntent(&intent); err != nil {
		return StateV1{}, err
	}
	if err := requireHash(certifiedHeadHash); err != nil {
		return StateV1{}, err
	}
	intentHash, _ := wire.HashObject(DomainIntent, intent)
	var sourceGeneration *int64
	if intent.FrozenDependencies.SourceListenerGeneration != nil {
		value := *intent.FrozenDependencies.SourceListenerGeneration
		sourceGeneration = &value
	}
	return StateV1{
		Schema: 1, ClusterID: intent.ClusterID, RotationID: intent.RotationID,
		RotationIntentHash: intentHash, FrozenDependenciesHash: intent.FrozenDependenciesHash,
		Phase: "allocated", SourceListenerGeneration: sourceGeneration,
		TargetListenerGeneration: intent.FrozenDependencies.TargetListenerGeneration,
		LastTransitionHeadHash:   certifiedHeadHash, EvidenceRefsRoot: emptyRoot(),
	}, nil
}

func Advance(intent IntentV1, current StateV1, transition Transition) (StateV1, error) {
	if err := ValidateIntent(&intent); err != nil {
		return StateV1{}, err
	}
	if err := validateState(intent, current); err != nil {
		return StateV1{}, err
	}
	if err := requireHash(transition.CertifiedHeadHash); err != nil {
		return StateV1{}, err
	}
	at, err := wire.ParseTimeZ(transition.CertifiedAt)
	if err != nil {
		return StateV1{}, err
	}
	if !allowedTransition(current.Phase, transition.NextPhase, transition.Emergency) {
		return StateV1{}, fmt.Errorf("[D120 rotation] 非法 phase transition %s -> %s", current.Phase, transition.NextPhase)
	}
	if transition.NextPhase == "advertised" {
		if err := notBefore(at, intent.AdvertiseNotBefore, "advertise"); err != nil {
			return StateV1{}, err
		}
		if len(transition.EvidenceRefs) < 2 {
			return StateV1{}, errors.New("[D120 rotation] advertise 前必须同时提交 local/external verify evidence")
		}
	}
	if transition.NextPhase == "preferred" {
		if err := notBefore(at, intent.PreferNotBefore, "prefer"); err != nil {
			return StateV1{}, err
		}
		if transition.ReaderFloor < intent.MinimumReaderFloor {
			return StateV1{}, errors.New("[D120 rotation] reader floor 未达到 Gate A 要求")
		}
	}
	if transition.NextPhase == "draining" {
		if err := notBefore(at, intent.DrainNotBefore, "drain"); err != nil {
			return StateV1{}, err
		}
		if transition.Guard == nil {
			return StateV1{}, errors.New("[D120 rotation] draining 必须建立 retirement guard")
		}
	}
	if transition.NextPhase == "retired" {
		if transition.Guard == nil {
			return StateV1{}, errors.New("[D120 rotation] retire 必须携带原 retirement guard")
		}
		guardHash, err := ValidateGuard(intent, transition.Guard)
		if err != nil {
			return StateV1{}, err
		}
		if current.RetirementGuardHash == "" || current.RetirementGuardHash != guardHash {
			return StateV1{}, errors.New("[D127 rotation] retire guard 与 draining 时冻结的 bytes 不一致")
		}
		if transition.ReaderFloor < transition.Guard.MinimumReaderFloor || transition.ReaderFloor < intent.MinimumReaderFloor {
			return StateV1{}, errors.New("[D120 rotation] retire reader floor 未满足")
		}
		for label, deadline := range map[string]string{
			"drain deadline": intent.DrainNotAfter, "retire deadline": intent.RetireNotBefore,
			"dependency deadline": transition.Guard.MaximumReferenceNotAfter,
			"offline grace":       transition.Guard.OfflineGraceNotBefore, "quiet window": transition.Guard.QuietNotBefore,
			"backup retention": transition.Guard.BackupRetainUntil,
		} {
			if err := notBefore(at, deadline, label); err != nil {
				return StateV1{}, err
			}
		}
	}
	if transition.NextPhase == "revoked" && transition.Emergency && len(transition.EvidenceRefs) == 0 {
		return StateV1{}, errors.New("[D120 rotation] emergency revoke 必须提交中断/安全事件 evidence")
	}
	if transition.NextPhase == "abandoned" && current.Phase == "preferred" {
		return StateV1{}, errors.New("[D127 rotation] target preferred 后不能用普通 cancel 跳过 drain")
	}
	root, err := refsRoot(transition.EvidenceRefs)
	if err != nil {
		return StateV1{}, err
	}
	next := current
	next.Phase = transition.NextPhase
	next.LastTransitionHeadHash = transition.CertifiedHeadHash
	next.EvidenceRefsRoot = root
	if transition.NextPhase == "draining" {
		hash, err := ValidateGuard(intent, transition.Guard)
		if err != nil {
			return StateV1{}, err
		}
		next.RetirementGuardHash = hash
	}
	return next, nil
}

func ValidateIntent(intent *IntentV1) error {
	if intent == nil || intent.Schema != 1 || intent.ClusterID == "" || intent.RotationID == "" || intent.OperationID == "" || intent.MinimumReaderFloor < 1 {
		return errors.New("[D120 rotation] intent header 无效")
	}
	for _, hash := range []string{intent.BaseHeadHash, intent.ExpectedEndpointSetHash} {
		if err := requireHash(hash); err != nil {
			return err
		}
	}
	if err := validateDependencies(&intent.FrozenDependencies); err != nil {
		return err
	}
	if intent.ClusterID != intent.FrozenDependencies.ClusterID {
		return errors.New("[D127 rotation] intent/frozen cluster 不一致")
	}
	want, err := wire.HashObject(DomainFrozenDependencies, intent.FrozenDependencies)
	if err != nil || want != intent.FrozenDependenciesHash {
		return errors.New("[D127 rotation] frozen_dependencies_hash 与 exact dependency bytes 不一致")
	}
	times := make([]time.Time, 0, 5)
	for _, value := range []string{intent.AdvertiseNotBefore, intent.PreferNotBefore, intent.DrainNotBefore, intent.DrainNotAfter, intent.RetireNotBefore} {
		parsed, err := wire.ParseTimeZ(value)
		if err != nil {
			return err
		}
		times = append(times, parsed)
	}
	for i := 1; i < len(times); i++ {
		if times[i].Before(times[i-1]) {
			return errors.New("[D120 rotation] lifecycle deadlines 必须单调不减")
		}
	}
	return nil
}

func BuildGuard(intent IntentV1, cutoffHead string, leaves []RetirementDependencyLeafV1, offline, quiet, backup string) (RetirementGuardV1, error) {
	if err := ValidateIntent(&intent); err != nil {
		return RetirementGuardV1{}, err
	}
	if intent.FrozenDependencies.SourceListenerGeneration == nil || intent.FrozenDependencies.SourceListenerGenerationHash == "" {
		return RetirementGuardV1{}, errors.New("[D120 rotation] 初次 provision 没有 source generation，不能 drain")
	}
	if err := requireHash(cutoffHead); err != nil {
		return RetirementGuardV1{}, errors.New("[D120 rotation] retirement reference cutoff head hash 无效")
	}
	ordered := append([]RetirementDependencyLeafV1(nil), leaves...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Kind != ordered[j].Kind {
			return ordered[i].Kind < ordered[j].Kind
		}
		return ordered[i].ObjectHash < ordered[j].ObjectHash
	})
	canonicalLeaves := make([][]byte, len(ordered))
	maximum := time.Unix(0, 0).UTC()
	for i, leaf := range ordered {
		if leaf.Schema != 1 || !allowedLeafKind(leaf.Kind) || requireHash(leaf.ObjectHash) != nil || i > 0 && ordered[i-1].Kind == leaf.Kind && ordered[i-1].ObjectHash == leaf.ObjectHash {
			return RetirementGuardV1{}, errors.New("[D120 rotation] retirement dependency leaf 无效/重复")
		}
		deadline, err := wire.ParseTimeZ(leaf.ReferenceNotAfter)
		if err != nil {
			return RetirementGuardV1{}, err
		}
		if deadline.After(maximum) {
			maximum = deadline
		}
		canonical, err := wire.MarshalCanonical(leaf)
		if err != nil {
			return RetirementGuardV1{}, err
		}
		canonicalLeaves[i] = canonical
	}
	for _, deadline := range []string{offline, quiet, backup} {
		if _, err := wire.ParseTimeZ(deadline); err != nil {
			return RetirementGuardV1{}, err
		}
	}
	intentHash, _ := wire.HashObject(DomainIntent, intent)
	return RetirementGuardV1{
		Schema: 1, ClusterID: intent.ClusterID, RotationID: intent.RotationID,
		RotationIntentHash: intentHash, SourceListenerGenerationHash: intent.FrozenDependencies.SourceListenerGenerationHash,
		ReferenceCutoffHeadHash: cutoffHead, Dependencies: ordered, DependencyLeafCount: int64(len(ordered)),
		DependencyRoot:           "sha256:" + hex.EncodeToString(wire.MerkleRoot(canonicalLeaves)),
		MaximumReferenceNotAfter: maximum.Format(time.RFC3339), MinimumReaderFloor: intent.MinimumReaderFloor,
		OfflineGraceNotBefore: offline, QuietNotBefore: quiet, BackupRetainUntil: backup,
	}, nil
}

func ValidateGuard(intent IntentV1, guard *RetirementGuardV1) (string, error) {
	if guard == nil || guard.Schema != 1 || guard.ClusterID != intent.ClusterID || guard.RotationID != intent.RotationID {
		return "", errors.New("[D120 rotation] retirement guard identity 无效")
	}
	want, err := BuildGuard(intent, guard.ReferenceCutoffHeadHash, guard.Dependencies, guard.OfflineGraceNotBefore, guard.QuietNotBefore, guard.BackupRetainUntil)
	if err != nil {
		return "", err
	}
	wantCanonical, _ := wire.MarshalCanonical(want)
	gotCanonical, _ := wire.MarshalCanonical(guard)
	if string(wantCanonical) != string(gotCanonical) {
		return "", errors.New("[D120 rotation] guard count/root/maximum 与 dependency leaves 不一致")
	}
	return wire.HashObject(DomainGuard, guard)
}

func validateDependencies(dep *FrozenDependenciesV1) error {
	if dep == nil || dep.Schema != 1 || dep.ClusterID == "" || dep.EndpointSetID == "" || dep.EndpointID == "" || dep.LogicalServerID == "" || dep.TargetListenerGeneration < 1 || !oneOf(dep.EndpointKind, "distribution", "bootstrap", "data") || !oneOf(dep.Transport, "https", "hysteria2", "trojan_tls", "wireguard") {
		return errors.New("[D127 rotation] frozen dependency identity 无效")
	}
	if (dep.SourceListenerGeneration == nil) != (dep.SourceListenerGenerationHash == "") {
		return errors.New("[D127 rotation] source generation/ref 必须同时存在或同时缺失")
	}
	if dep.SourceListenerGeneration != nil && (*dep.SourceListenerGeneration < 1 || *dep.SourceListenerGeneration >= dep.TargetListenerGeneration) {
		return errors.New("[D127 rotation] source/target generation 无效")
	}
	if dep.EndpointKind == "distribution" && dep.Transport != "https" ||
		dep.EndpointKind == "bootstrap" && !oneOf(dep.Transport, "hysteria2", "trojan_tls") ||
		dep.EndpointKind == "data" && !oneOf(dep.Transport, "hysteria2", "trojan_tls", "wireguard") {
		return errors.New("[D127 rotation] endpoint kind 与 transport role 不匹配")
	}
	hashes := []string{
		dep.LogicalPublicEndpointIntentHash, dep.PublicAccessProfileHash, dep.DNSAddressBindingHash,
		dep.CertificateIdentityProjectionHash, dep.CredentialArtifactRefsRoot, dep.RenderContractHash,
		dep.EvidencePolicyHash, dep.PortPoolHash, dep.FirewallPolicyHash, dep.ForwardListenerResourceGenerationHash,
	}
	if dep.SourceListenerGenerationHash != "" {
		hashes = append(hashes, dep.SourceListenerGenerationHash)
	}
	if dep.PortMappingIntentHash != "" {
		hashes = append(hashes, dep.PortMappingIntentHash)
	}
	hashes = append(hashes, dep.LinkIntentHashes...)
	for _, hash := range hashes {
		if err := requireHash(hash); err != nil {
			return err
		}
	}
	if !sortedUnique(dep.LinkIntentHashes) {
		return errors.New("[D127 rotation] link_intent_hashes 必须排序且唯一")
	}
	return nil
}

func validateState(intent IntentV1, state StateV1) error {
	intentHash, _ := wire.HashObject(DomainIntent, intent)
	if state.Schema != 1 || state.ClusterID != intent.ClusterID || state.RotationID != intent.RotationID || state.RotationIntentHash != intentHash || state.FrozenDependenciesHash != intent.FrozenDependenciesHash || state.TargetListenerGeneration != intent.FrozenDependencies.TargetListenerGeneration ||
		(state.SourceListenerGeneration == nil) != (intent.FrozenDependencies.SourceListenerGeneration == nil) ||
		state.SourceListenerGeneration != nil && *state.SourceListenerGeneration != *intent.FrozenDependencies.SourceListenerGeneration {
		return errors.New("[D127 rotation] state 与 frozen intent 不匹配")
	}
	if !oneOf(state.Phase, "allocated", "preparing", "advertised", "preferred", "draining", "retired", "abandoned", "revoked") ||
		requireHash(state.LastTransitionHeadHash) != nil || requireHash(state.EvidenceRefsRoot) != nil {
		return errors.New("[D120 rotation] state phase/head/evidence root 无效")
	}
	guardRequired := state.Phase == "draining" || state.Phase == "retired"
	if guardRequired != (state.RetirementGuardHash != "") || state.RetirementGuardHash != "" && requireHash(state.RetirementGuardHash) != nil {
		return errors.New("[D120 rotation] state phase 与 retirement guard hash 不一致")
	}
	return nil
}

func allowedTransition(from, to string, emergency bool) bool {
	if emergency {
		return to == "revoked" && from != "retired" && from != "abandoned" && from != "revoked"
	}
	allowed := map[string]string{"allocated": "preparing", "preparing": "advertised", "advertised": "preferred", "preferred": "draining", "draining": "retired"}
	if allowed[from] == to {
		return true
	}
	return to == "abandoned" && (from == "allocated" || from == "preparing" || from == "advertised")
}

func notBefore(now time.Time, deadline, label string) error {
	value, err := wire.ParseTimeZ(deadline)
	if err != nil {
		return err
	}
	if now.Before(value) {
		return fmt.Errorf("[D120 rotation] %s 尚未到达", label)
	}
	return nil
}

func refsRoot(refs []string) (string, error) {
	ordered := append([]string(nil), refs...)
	sort.Strings(ordered)
	canonical := make([][]byte, len(ordered))
	for i, ref := range ordered {
		if err := requireHash(ref); err != nil || i > 0 && ordered[i-1] == ref {
			return "", errors.New("[D120 rotation] evidence refs 必须是排序后唯一 hash set")
		}
		canonical[i] = []byte(ref)
	}
	return "sha256:" + hex.EncodeToString(wire.MerkleRoot(canonical)), nil
}

func emptyRoot() string {
	root, _ := refsRoot(nil)
	return root
}

func requireHash(value string) error {
	_, err := wire.ParseHash(value)
	return err
}

func sortedUnique(values []string) bool {
	for i, value := range values {
		if i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func allowedLeafKind(value string) bool {
	return oneOf(value, "endpoint_set", "catalog", "available_invite", "initial_capability", "resume_descriptor", "reserved_transaction", "device_view", "certificate_pin_overlap", "offline_lkg")
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
