package rotation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"loom/internal/wire"
)

const (
	DomainExecutionPlan      = "loom-listener-rotation-execution-plan-v1"
	DomainRuntimeProjection  = "loom-listener-rotation-runtime-projection-v1"
	DomainRuntimeObservation = "loom-listener-rotation-runtime-observation-v1"
	DomainReconcileEvidence  = "loom-listener-rotation-reconcile-evidence-v1"
	DomainWireGuardOverlap   = "loom-wireguard-generation-overlap-v1"
)

// ExecutionPlanV1 只描述本机对 frozen intent 的资源落点。端口、WG interface、
// route table 等一旦进入 plan 就不能在重试时重新探测/分配。
type ExecutionPlanV1 struct {
	Schema                 int               `json:"schema"`
	ClusterID              string            `json:"cluster_id"`
	RotationID             string            `json:"rotation_id"`
	FrozenDependenciesHash string            `json:"frozen_dependencies_hash"`
	SourceTuples           []Tuple           `json:"source_tuples"`
	TargetTuples           []Tuple           `json:"target_tuples"`
	WireGuardOverlap       *WireGuardOverlap `json:"wireguard_overlap,omitempty"`
}

type RuntimeProjectionV1 struct {
	Schema                 int     `json:"schema"`
	ClusterID              string  `json:"cluster_id"`
	RotationID             string  `json:"rotation_id"`
	FrozenDependenciesHash string  `json:"frozen_dependencies_hash"`
	ExecutionPlanHash      string  `json:"execution_plan_hash"`
	SourceGeneration       *int64  `json:"source_generation,omitempty"`
	TargetGeneration       int64   `json:"target_generation"`
	SourceState            string  `json:"source_state"`
	TargetState            string  `json:"target_state"`
	OwnedTuples            []Tuple `json:"owned_tuples"`
}

type RuntimeObservationV1 struct {
	Schema     int                 `json:"schema"`
	Projection RuntimeProjectionV1 `json:"projection"`
	ObservedAt string              `json:"observed_at"`
}

type ReconcileEvidenceV1 struct {
	Schema             int    `json:"schema"`
	ClusterID          string `json:"cluster_id"`
	RotationID         string `json:"rotation_id"`
	CertifiedStateHash string `json:"certified_state_hash"`
	ExecutionPlanHash  string `json:"execution_plan_hash"`
	DesiredStateHash   string `json:"desired_state_hash"`
	BeforeHash         string `json:"before_hash"`
	AfterHash          string `json:"after_hash"`
	Changed            bool   `json:"changed"`
}

// AuthorizedRuntimePlanV1 是完整重放 certified rotation history 并核对 durable
// frozen execution plan 后得到的不透明运行凭据。listener driver 只能消费这个值，
// 不能把磁盘里的 phase 或 tuple JSON 直接当成当前 ownership。
type AuthorizedRuntimePlanV1 struct {
	intent     IntentV1
	state      StateV1
	plan       ExecutionPlanV1
	projection RuntimeProjectionV1
}

// AuthorizeInitialPreparedRuntimePlan 用于控制面重验首次部署的 prepared
// listener 证据。它与节点侧 Store+ExecutionPlanStore 走相同的 reducer、hash
// 和 authority verifier，但不创建第二份本地持久状态。
func AuthorizeInitialPreparedRuntimePlan(intent IntentV1, plan ExecutionPlanV1,
	transition Transition, verify CertifiedAuthorityVerifier) (AuthorizedRuntimePlanV1, error) {
	transition = normalizeTransition(transition)
	if verify == nil || transition.NextPhase != "prepared" ||
		intent.FrozenDependencies.SourceListenerGeneration != nil {
		return AuthorizedRuntimePlanV1{}, errors.New("[rotation] 首次 prepared runtime authority 输入无效")
	}
	if err := ValidateIntent(&intent); err != nil {
		return AuthorizedRuntimePlanV1{}, err
	}
	if err := ValidateExecutionPlan(&intent, &plan); err != nil {
		return AuthorizedRuntimePlanV1{}, err
	}
	if err := validateInitialTransition(&intent, &transition); err != nil {
		return AuthorizedRuntimePlanV1{}, err
	}
	if err := verify(&intent, nil, &transition); err != nil {
		return AuthorizedRuntimePlanV1{}, fmt.Errorf("[rotation] prepared head 未获 certified authority: %w", err)
	}
	state, err := initialState(intent, transition)
	if err != nil {
		return AuthorizedRuntimePlanV1{}, err
	}
	record, err := newTransitionRecord(1, wire.EmptyHashV1, transition, state)
	if err != nil {
		return AuthorizedRuntimePlanV1{}, err
	}
	planHash, err := ExecutionPlanHash(&intent, &plan)
	if err != nil {
		return AuthorizedRuntimePlanV1{}, err
	}
	durable := DurableStateV1{Schema: 1, Intent: &intent, Current: &state,
		History: []TransitionRecordV1{record}}
	return AuthorizeRuntimePlan(durable, frozenExecutionPlan(plan, planHash), verify)
}

// AuthorizeRuntimePlan 把 Store 与 ExecutionPlanStore 的两个耐久边界重新合并验证。
// 这样独立进程重启后也必须重放每个 certified transition，且不能换用另一份端口计划。
func AuthorizeRuntimePlan(certified DurableStateV1, frozen FrozenExecutionPlanV1,
	verify CertifiedAuthorityVerifier) (AuthorizedRuntimePlanV1, error) {
	if verify == nil {
		return AuthorizedRuntimePlanV1{}, errors.New("[rotation] runtime authority verifier 缺失")
	}
	if err := validateDurableState(&certified, verify); err != nil {
		return AuthorizedRuntimePlanV1{}, errors.New("[rotation] runtime 拒绝未经 certified replay 的 state")
	}
	if certified.Intent == nil || certified.Current == nil {
		return AuthorizedRuntimePlanV1{}, errors.New("[rotation] runtime 缺已分配 rotation")
	}
	plan, err := validateFrozenExecutionPlan(certified.Intent, frozen)
	if err != nil {
		return AuthorizedRuntimePlanV1{}, err
	}
	projection, err := desiredRuntimeProjection(*certified.Intent, *certified.Current, plan)
	if err != nil {
		return AuthorizedRuntimePlanV1{}, err
	}
	return AuthorizedRuntimePlanV1{
		intent: cloneIntent(*certified.Intent), state: cloneState(*certified.Current),
		plan: cloneExecutionPlan(plan), projection: cloneRuntimeProjection(projection),
	}, nil
}

// Intent 返回 frozen dependency 的副本；返回值只能用于再次收窄，不能据此构造
// 新 AuthorizedRuntimePlanV1。
func (authorized AuthorizedRuntimePlanV1) Intent() IntentV1 {
	return cloneIntent(authorized.intent)
}

func (authorized AuthorizedRuntimePlanV1) State() StateV1 {
	return cloneState(authorized.state)
}

func (authorized AuthorizedRuntimePlanV1) Projection() RuntimeProjectionV1 {
	return cloneRuntimeProjection(authorized.projection)
}

// GenerationTuples 只返回当前 phase 实际拥有的 source/target tuple。retired、
// revoked、abandoned 或尚未 prepare 的代次不会意外重新获得 listener。
func (authorized AuthorizedRuntimePlanV1) GenerationTuples(generation int64) (string, []Tuple, bool) {
	if authorized.intent.Schema != 1 || authorized.state.Schema != 1 || authorized.plan.Schema != 1 ||
		authorized.projection.Schema != 1 || generation < 1 {
		return "", nil, false
	}
	if authorized.state.SourceListenerGeneration != nil && generation == *authorized.state.SourceListenerGeneration {
		state := authorized.projection.SourceState
		if state == "absent" || state == "retired" || state == "revoked" {
			return state, nil, false
		}
		return state, append([]Tuple(nil), authorized.plan.SourceTuples...), true
	}
	if generation == authorized.state.TargetListenerGeneration {
		state := authorized.projection.TargetState
		if state == "absent" || state == "retired" || state == "revoked" || state == "abandoned" {
			return state, nil, false
		}
		return state, append([]Tuple(nil), authorized.plan.TargetTuples...), true
	}
	return "", nil, false
}

type RuntimeDriver interface {
	Observe(context.Context, IntentV1, ExecutionPlanV1) (RuntimeObservationV1, error)
	Apply(context.Context, IntentV1, ExecutionPlanV1, RuntimeProjectionV1) error
}

// Reconciler 只消费完整、可重放验证的 durable state；调用方不能传一个伪造的
// phase 字符串直接触发旧 listener 删除。
type Reconciler struct {
	driver            RuntimeDriver
	verify            CertifiedAuthorityVerifier
	now               func() time.Time
	maxObservationAge time.Duration
}

func NewReconciler(driver RuntimeDriver, verify CertifiedAuthorityVerifier,
	now func() time.Time, maxObservationAge time.Duration) (*Reconciler, error) {
	if driver == nil || verify == nil || now == nil || maxObservationAge < time.Second || maxObservationAge > 5*time.Minute {
		return nil, errors.New("[rotation] runtime reconciler dependencies/observation age 无效")
	}
	return &Reconciler{driver: driver, verify: verify, now: now, maxObservationAge: maxObservationAge}, nil
}

func (reconciler *Reconciler) Reconcile(ctx context.Context, certified DurableStateV1,
	frozenPlan FrozenExecutionPlanV1) (ReconcileEvidenceV1, error) {
	if reconciler == nil {
		return ReconcileEvidenceV1{}, errors.New("[rotation] runtime reconciler 不能为空")
	}
	if err := ctx.Err(); err != nil {
		return ReconcileEvidenceV1{}, err
	}
	if err := validateDurableState(&certified, reconciler.verify); err != nil {
		return ReconcileEvidenceV1{}, errors.New("[rotation] runtime 拒绝未经 certified replay 的 state")
	}
	if certified.Intent == nil || certified.Current == nil {
		return ReconcileEvidenceV1{}, errors.New("[rotation] runtime 缺已分配 rotation")
	}
	plan, err := validateFrozenExecutionPlan(certified.Intent, frozenPlan)
	if err != nil {
		return ReconcileEvidenceV1{}, err
	}
	desired, err := desiredRuntimeProjection(*certified.Intent, *certified.Current, plan)
	if err != nil {
		return ReconcileEvidenceV1{}, err
	}
	before, err := reconciler.driver.Observe(ctx, *certified.Intent, plan)
	if err != nil {
		return ReconcileEvidenceV1{}, err
	}
	now := reconciler.now().UTC()
	if err := validateRuntimeObservation(&before, &desired, now, reconciler.maxObservationAge); err != nil {
		return ReconcileEvidenceV1{}, err
	}
	changed := !wire.EqualCanonical(before.Projection, desired)
	after := before
	if changed {
		if err := reconciler.driver.Apply(ctx, *certified.Intent, plan, desired); err != nil {
			return ReconcileEvidenceV1{}, err
		}
		after, err = reconciler.driver.Observe(ctx, *certified.Intent, plan)
		if err != nil {
			return ReconcileEvidenceV1{}, err
		}
		if err := validateRuntimeObservation(&after, &desired,
			reconciler.now().UTC(), reconciler.maxObservationAge); err != nil {
			return ReconcileEvidenceV1{}, err
		}
		if !wire.EqualCanonical(after.Projection, desired) {
			return ReconcileEvidenceV1{}, errors.New("[rotation] runtime apply 后未收敛到 certified desired state")
		}
	}
	return newReconcileEvidence(*certified.Current, plan, desired, before, after, changed)
}

func ValidateExecutionPlan(intent *IntentV1, plan *ExecutionPlanV1) error {
	if intent == nil {
		return errors.New("[rotation] execution plan 缺 intent")
	}
	if err := ValidateExecutionPlanShape(plan); err != nil {
		return err
	}
	if plan.ClusterID != intent.ClusterID ||
		plan.RotationID != intent.RotationID || plan.FrozenDependenciesHash != intent.FrozenDependenciesHash ||
		(intent.FrozenDependencies.SourceListenerGeneration != nil) != (len(plan.SourceTuples) > 0) {
		return errors.New("[rotation] execution plan identity/frozen binding 无效")
	}
	hasSource := intent.FrozenDependencies.SourceListenerGeneration != nil
	expectedTransport := "tcp"
	if intent.FrozenDependencies.Transport == "hysteria2" || intent.FrozenDependencies.Transport == "wireguard" {
		expectedTransport = "udp"
	}
	all := append(append([]Tuple(nil), plan.SourceTuples...), plan.TargetTuples...)
	if err := validateCanonicalTuples(plan.SourceTuples); err != nil {
		return err
	}
	if err := validateCanonicalTuples(plan.TargetTuples); err != nil {
		return err
	}
	for _, tuple := range all {
		if tuple.Transport != expectedTransport {
			return errors.New("[rotation] execution tuple transport 与 frozen listener 不一致")
		}
	}
	if err := ValidateTupleOwnership(all); err != nil {
		return err
	}
	if intent.FrozenDependencies.Transport == "wireguard" {
		if plan.WireGuardOverlap == nil || plan.WireGuardOverlap.Validate() != nil || !hasSource ||
			plan.WireGuardOverlap.Old.Generation != *intent.FrozenDependencies.SourceListenerGeneration ||
			plan.WireGuardOverlap.New.Generation != intent.FrozenDependencies.TargetListenerGeneration ||
			!containsTuple(plan.SourceTuples, plan.WireGuardOverlap.Old.ListenTuple) ||
			!containsTuple(plan.TargetTuples, plan.WireGuardOverlap.New.ListenTuple) {
			return errors.New("[WG] execution plan 未绑定独立 old/new overlap")
		}
	} else if plan.WireGuardOverlap != nil {
		return errors.New("[rotation] 非 WireGuard plan 禁止 WG overlap")
	}
	return nil
}

func ValidateExecutionPlanShape(plan *ExecutionPlanV1) error {
	if plan == nil || plan.Schema != 1 || plan.ClusterID == "" || plan.RotationID == "" ||
		requireHash(plan.FrozenDependenciesHash) != nil || plan.SourceTuples == nil ||
		plan.TargetTuples == nil || len(plan.TargetTuples) == 0 {
		return errors.New("[rotation] execution plan shape 无效")
	}
	if err := validateCanonicalTuples(plan.SourceTuples); err != nil {
		return err
	}
	if err := validateCanonicalTuples(plan.TargetTuples); err != nil {
		return err
	}
	return ValidateTupleOwnership(append(append([]Tuple(nil), plan.SourceTuples...), plan.TargetTuples...))
}

func ExecutionPlanHash(intent *IntentV1, plan *ExecutionPlanV1) (string, error) {
	if err := ValidateExecutionPlan(intent, plan); err != nil {
		return "", err
	}
	return wire.HashObject(DomainExecutionPlan, plan)
}

func validateFrozenExecutionPlan(intent *IntentV1,
	frozen FrozenExecutionPlanV1) (ExecutionPlanV1, error) {
	plan := frozen.Plan()
	planHash, err := ExecutionPlanHash(intent, &plan)
	if err != nil || frozen.planHash == "" || frozen.planHash != planHash {
		return ExecutionPlanV1{}, errors.New("[rotation] reconciler 只接受 durable frozen execution plan")
	}
	return plan, nil
}

func desiredRuntimeProjection(intent IntentV1, state StateV1,
	plan ExecutionPlanV1) (RuntimeProjectionV1, error) {
	if err := validateState(intent, state); err != nil {
		return RuntimeProjectionV1{}, err
	}
	planHash, err := ExecutionPlanHash(&intent, &plan)
	if err != nil {
		return RuntimeProjectionV1{}, err
	}
	sourceState, targetState := "absent", "absent"
	if state.SourceListenerGeneration != nil {
		sourceState = "preferred"
	}
	sourceOwned, targetOwned := state.SourceListenerGeneration != nil, false
	switch state.Phase {
	case "allocated":
	case "prepared":
		targetState, targetOwned = "prepared", true
	case "advertised":
		targetState, targetOwned = "advertised", true
	case "preferred":
		targetState, targetOwned = "preferred", true
		if state.SourceListenerGeneration != nil {
			sourceState = "advertised"
		}
	case "draining":
		targetState, targetOwned = "preferred", true
		if state.SourceListenerGeneration != nil {
			sourceState = "draining"
		}
	case "retired":
		targetState, targetOwned, sourceOwned = "preferred", true, false
		if state.SourceListenerGeneration != nil {
			sourceState = "retired"
		}
	case "abandoned":
		targetState = "abandoned"
	case "revoked":
		targetState = "revoked"
	default:
		return RuntimeProjectionV1{}, errors.New("[rotation] runtime phase 未获支持")
	}
	owned := make([]Tuple, 0, len(plan.SourceTuples)+len(plan.TargetTuples))
	if sourceOwned {
		owned = append(owned, plan.SourceTuples...)
	}
	if targetOwned {
		owned = append(owned, plan.TargetTuples...)
	}
	sortTuples(owned)
	return RuntimeProjectionV1{
		Schema: 1, ClusterID: intent.ClusterID, RotationID: intent.RotationID,
		FrozenDependenciesHash: intent.FrozenDependenciesHash, ExecutionPlanHash: planHash,
		SourceGeneration: cloneGeneration(state.SourceListenerGeneration),
		TargetGeneration: state.TargetListenerGeneration, SourceState: sourceState,
		TargetState: targetState, OwnedTuples: owned,
	}, nil
}

func validateRuntimeObservation(observation *RuntimeObservationV1, desired *RuntimeProjectionV1,
	now time.Time, maximumAge time.Duration) error {
	if observation == nil || desired == nil || observation.Schema != 1 || now.IsZero() ||
		observation.Projection.Schema != 1 || observation.Projection.ClusterID != desired.ClusterID ||
		observation.Projection.RotationID != desired.RotationID ||
		observation.Projection.FrozenDependenciesHash != desired.FrozenDependenciesHash ||
		observation.Projection.ExecutionPlanHash != desired.ExecutionPlanHash ||
		observation.Projection.TargetGeneration != desired.TargetGeneration ||
		!equalGeneration(observation.Projection.SourceGeneration, desired.SourceGeneration) {
		return errors.New("[rotation] runtime observation identity/frozen plan binding 无效")
	}
	if !oneOf(observation.Projection.SourceState, "absent", "preferred", "advertised", "draining", "retired", "revoked") ||
		!oneOf(observation.Projection.TargetState, "absent", "prepared", "advertised", "preferred", "draining", "retired", "revoked", "abandoned") ||
		validateCanonicalTuples(observation.Projection.OwnedTuples) != nil ||
		ValidateTupleOwnership(observation.Projection.OwnedTuples) != nil {
		return errors.New("[rotation] runtime observation state/tuple 无效")
	}
	observedAt, err := wire.ParseTimeZ(observation.ObservedAt)
	if err != nil || observedAt.After(now.Add(30*time.Second)) || now.Sub(observedAt) > maximumAge {
		return errors.New("[rotation] runtime observation 不新鲜")
	}
	return nil
}

func newReconcileEvidence(state StateV1, plan ExecutionPlanV1, desired RuntimeProjectionV1,
	before, after RuntimeObservationV1, changed bool) (ReconcileEvidenceV1, error) {
	stateHash, err := wire.HashObject(DomainState, state)
	if err != nil {
		return ReconcileEvidenceV1{}, err
	}
	planHash, err := wire.HashObject(DomainExecutionPlan, plan)
	if err != nil {
		return ReconcileEvidenceV1{}, err
	}
	desiredHash, err := wire.HashObject(DomainRuntimeProjection, desired)
	if err != nil {
		return ReconcileEvidenceV1{}, err
	}
	beforeHash, err := wire.HashObject(DomainRuntimeObservation, before)
	if err != nil {
		return ReconcileEvidenceV1{}, err
	}
	afterHash, err := wire.HashObject(DomainRuntimeObservation, after)
	if err != nil {
		return ReconcileEvidenceV1{}, err
	}
	return ReconcileEvidenceV1{
		Schema: 1, ClusterID: state.ClusterID, RotationID: state.RotationID,
		CertifiedStateHash: stateHash, ExecutionPlanHash: planHash, DesiredStateHash: desiredHash,
		BeforeHash: beforeHash, AfterHash: afterHash, Changed: changed,
	}, nil
}

func ReconcileEvidenceHash(evidence *ReconcileEvidenceV1) (string, error) {
	if evidence == nil || evidence.Schema != 1 || evidence.ClusterID == "" || evidence.RotationID == "" {
		return "", errors.New("[rotation] reconcile evidence header 无效")
	}
	for _, hash := range []string{evidence.CertifiedStateHash, evidence.ExecutionPlanHash,
		evidence.DesiredStateHash, evidence.BeforeHash, evidence.AfterHash} {
		if err := requireHash(hash); err != nil {
			return "", err
		}
	}
	if !evidence.Changed && evidence.BeforeHash != evidence.AfterHash {
		return "", errors.New("[rotation] unchanged evidence 的 before/after 不一致")
	}
	return wire.HashObject(DomainReconcileEvidence, evidence)
}

func validateCanonicalTuples(tuples []Tuple) error {
	if tuples == nil {
		return errors.New("[rotation] tuple list 不能为 null")
	}
	for index := range tuples {
		if index > 0 && !tupleLess(tuples[index-1], tuples[index]) {
			return errors.New("[rotation] tuples 必须严格规范排序")
		}
	}
	return ValidateTupleOwnership(tuples)
}

func sortTuples(tuples []Tuple) {
	sort.Slice(tuples, func(left, right int) bool { return tupleLess(tuples[left], tuples[right]) })
}

func cloneIntent(intent IntentV1) IntentV1 {
	body, _ := wire.MarshalCanonical(intent)
	var clone IntentV1
	_, _ = wire.DecodeStrict(body, 4<<20, &clone)
	return clone
}

func cloneState(state StateV1) StateV1 {
	body, _ := wire.MarshalCanonical(state)
	var clone StateV1
	_, _ = wire.DecodeStrict(body, 4<<20, &clone)
	return clone
}

func cloneRuntimeProjection(projection RuntimeProjectionV1) RuntimeProjectionV1 {
	body, _ := wire.MarshalCanonical(projection)
	var clone RuntimeProjectionV1
	_, _ = wire.DecodeStrict(body, 4<<20, &clone)
	return clone
}

func tupleLess(left, right Tuple) bool {
	if left.Transport != right.Transport {
		return left.Transport < right.Transport
	}
	if left.Address != right.Address {
		return left.Address < right.Address
	}
	return left.Port < right.Port
}

func containsTuple(tuples []Tuple, target Tuple) bool {
	for _, tuple := range tuples {
		if tuple == target {
			return true
		}
	}
	return false
}

func cloneGeneration(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func equalGeneration(left, right *int64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
