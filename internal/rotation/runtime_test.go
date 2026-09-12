package rotation

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

type runtimeDriverFixture struct {
	observation  RuntimeObservationV1
	applyCalls   int
	observeCalls int
	converge     bool
	now          time.Time
}

func (driver *runtimeDriverFixture) Observe(context.Context, IntentV1,
	ExecutionPlanV1) (RuntimeObservationV1, error) {
	driver.observeCalls++
	result := driver.observation
	result.ObservedAt = driver.now.Format(time.RFC3339)
	return result, nil
}

func (driver *runtimeDriverFixture) Apply(_ context.Context, _ IntentV1,
	_ ExecutionPlanV1, desired RuntimeProjectionV1) error {
	driver.applyCalls++
	if driver.converge {
		driver.observation.Projection = desired
	}
	return nil
}

func TestRuntimeReconcilerConvergesCertifiedStateIdempotently(t *testing.T) {
	intent, certified, verify := preparedRuntimeState(t)
	plan := runtimeExecutionPlan(intent)
	frozen := freezeRuntimeExecutionPlan(t, intent, plan)
	desired, err := desiredRuntimeProjection(intent, *certified.Current, plan)
	if err != nil {
		t.Fatal(err)
	}
	before := desired
	before.TargetState = "absent"
	before.OwnedTuples = append([]Tuple(nil), plan.SourceTuples...)
	now := time.Date(2026, 1, 1, 0, 0, 30, 0, time.UTC)
	driver := &runtimeDriverFixture{observation: RuntimeObservationV1{Schema: 1, Projection: before},
		converge: true, now: now}
	reconciler, err := NewReconciler(driver, verify, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := reconciler.Reconcile(context.Background(), certified, frozen)
	if err != nil || !evidence.Changed || driver.applyCalls != 1 || driver.observeCalls != 2 {
		t.Fatalf("首次 reconcile 未收敛: evidence=%#v applies=%d observes=%d err=%v",
			evidence, driver.applyCalls, driver.observeCalls, err)
	}
	if _, err := ReconcileEvidenceHash(&evidence); err != nil {
		t.Fatal(err)
	}
	replayed, err := reconciler.Reconcile(context.Background(), certified, frozen)
	if err != nil || replayed.Changed || driver.applyCalls != 1 || driver.observeCalls != 3 ||
		replayed.BeforeHash != replayed.AfterHash {
		t.Fatalf("已收敛 runtime replay 不幂等: evidence=%#v applies=%d observes=%d err=%v",
			replayed, driver.applyCalls, driver.observeCalls, err)
	}
}

func TestRuntimeReconcilerRejectsForgedRetirementAndNonConvergence(t *testing.T) {
	intent, certified, verify := preparedRuntimeState(t)
	plan := runtimeExecutionPlan(intent)
	frozen := freezeRuntimeExecutionPlan(t, intent, plan)
	desired, err := desiredRuntimeProjection(intent, *certified.Current, plan)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 30, 0, time.UTC)
	driver := &runtimeDriverFixture{observation: RuntimeObservationV1{Schema: 1, Projection: desired},
		converge: true, now: now}
	reconciler, err := NewReconciler(driver, verify, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	forged := cloneDurableState(certified)
	forged.Current.Phase = "retired"
	forged.Current.RetirementGuardHash = wire.HashRaw("rotation-runtime-test", []byte("forged-guard"))
	if _, err := reconciler.Reconcile(context.Background(), forged, frozen); err == nil || driver.observeCalls != 0 {
		t.Fatal("伪造 retired current 绕过 certified history replay 到达 runtime")
	}

	stale := desired
	stale.TargetState = "absent"
	stale.OwnedTuples = append([]Tuple(nil), plan.SourceTuples...)
	driver.observation.Projection = stale
	driver.converge = false
	if _, err := reconciler.Reconcile(context.Background(), certified, frozen); err == nil || driver.applyCalls != 1 {
		t.Fatal("driver apply 未收敛却被报告成功")
	}
}

func TestExecutionPlanFreezesTuplesAndWireGuardOverlap(t *testing.T) {
	intent := testIntent(t)
	plan := runtimeExecutionPlan(intent)
	if _, err := ExecutionPlanHash(&intent, &plan); err != nil {
		t.Fatal(err)
	}
	reallocated := plan
	reallocated.TargetTuples = []Tuple{plan.SourceTuples[0]}
	if _, err := ExecutionPlanHash(&intent, &reallocated); err == nil {
		t.Fatal("重试重新分配到 source tuple 未被拒绝")
	}

	wgIntent := testIntent(t)
	wgIntent.FrozenDependencies.EndpointKind = "data"
	wgIntent.FrozenDependencies.Transport = "wireguard"
	wgIntent.FrozenDependenciesHash, _ = wire.HashObject(DomainFrozenDependencies, wgIntent.FrozenDependencies)
	wgPlan := ExecutionPlanV1{
		Schema: 1, ClusterID: wgIntent.ClusterID, RotationID: wgIntent.RotationID,
		FrozenDependenciesHash: wgIntent.FrozenDependenciesHash,
		SourceTuples:           []Tuple{{Transport: "udp", Address: "0.0.0.0", Port: 42000}},
		TargetTuples:           []Tuple{{Transport: "udp", Address: "0.0.0.0", Port: 42001}},
	}
	if _, err := ExecutionPlanHash(&wgIntent, &wgPlan); err == nil {
		t.Fatal("WireGuard plan 缺独立 overlap 被接受")
	}
	wgPlan.WireGuardOverlap = &WireGuardOverlap{
		Old: WireGuardGeneration{Generation: 1, InterfaceName: "wg-old",
			ListenTuple: wgPlan.SourceTuples[0], PrivateKeyRef: wire.HashRaw("rotation-runtime-test", []byte("old-key")),
			PeerPublicKey: wgPublicKey(1), TunnelAddress: "10.1.0.1/32", RouteTable: 100, FwMark: 100,
			AllowedIPs: []string{"10.2.0.0/16"}, State: "active"},
		New: WireGuardGeneration{Generation: 2, InterfaceName: "wg-new",
			ListenTuple: wgPlan.TargetTuples[0], PrivateKeyRef: wire.HashRaw("rotation-runtime-test", []byte("new-key")),
			PeerPublicKey: wgPublicKey(2), TunnelAddress: "10.1.0.2/32", RouteTable: 101, FwMark: 101,
			AllowedIPs: []string{"10.2.0.0/16"}, State: "prepared"},
	}
	if _, err := ExecutionPlanHash(&wgIntent, &wgPlan); err != nil {
		t.Fatal(err)
	}
	wgPlan.WireGuardOverlap.New.RouteTable = wgPlan.WireGuardOverlap.Old.RouteTable
	if _, err := ExecutionPlanHash(&wgIntent, &wgPlan); err == nil {
		t.Fatal("WireGuard plan 复用了 old route table")
	}
}

func TestRuntimeDesiredProjectionKeepsSourceUntilCertifiedRetirement(t *testing.T) {
	intent := testIntent(t)
	plan := runtimeExecutionPlan(intent)
	state, err := Allocate(intent, testHash)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		phase       string
		sourceState string
		targetState string
		ownedTuples int
		guard       bool
	}{
		{phase: "allocated", sourceState: "preferred", targetState: "absent", ownedTuples: 1},
		{phase: "prepared", sourceState: "preferred", targetState: "prepared", ownedTuples: 2},
		{phase: "advertised", sourceState: "preferred", targetState: "advertised", ownedTuples: 2},
		{phase: "preferred", sourceState: "advertised", targetState: "preferred", ownedTuples: 2},
		{phase: "draining", sourceState: "draining", targetState: "preferred", ownedTuples: 2, guard: true},
		{phase: "retired", sourceState: "retired", targetState: "preferred", ownedTuples: 1, guard: true},
		{phase: "abandoned", sourceState: "preferred", targetState: "abandoned", ownedTuples: 1},
		{phase: "revoked", sourceState: "preferred", targetState: "revoked", ownedTuples: 1},
	}
	for _, test := range tests {
		candidate := state
		candidate.Phase = test.phase
		candidate.RetirementGuardHash = ""
		if test.guard {
			candidate.RetirementGuardHash = wire.HashRaw("rotation-runtime-test", []byte("guard"))
		}
		projection, err := desiredRuntimeProjection(intent, candidate, plan)
		if err != nil || projection.SourceState != test.sourceState || projection.TargetState != test.targetState ||
			len(projection.OwnedTuples) != test.ownedTuples {
			t.Fatalf("phase=%s projection=%#v err=%v", test.phase, projection, err)
		}
	}
}

func preparedRuntimeState(t *testing.T) (IntentV1, DurableStateV1, CertifiedAuthorityVerifier) {
	t.Helper()
	verify := func(_ *IntentV1, _ *StateV1, transition *Transition) error {
		return requireHash(transition.CertifiedHeadHash)
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "rotation.json"), verify)
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent(t)
	if _, err := store.Begin(intent, certifiedTransition("allocated", "2026-01-01T00:00:00Z", "runtime-allocated")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Advance(certifiedTransition("prepared", "2026-01-01T00:00:01Z", "runtime-prepared")); err != nil {
		t.Fatal(err)
	}
	return intent, store.Snapshot(), verify
}

func runtimeExecutionPlan(intent IntentV1) ExecutionPlanV1 {
	return ExecutionPlanV1{
		Schema: 1, ClusterID: intent.ClusterID, RotationID: intent.RotationID,
		FrozenDependenciesHash: intent.FrozenDependenciesHash,
		SourceTuples:           []Tuple{{Transport: "udp", Address: "0.0.0.0", Port: 41000}},
		TargetTuples:           []Tuple{{Transport: "udp", Address: "0.0.0.0", Port: 41001}},
	}
}

func freezeRuntimeExecutionPlan(t *testing.T, intent IntentV1,
	plan ExecutionPlanV1) FrozenExecutionPlanV1 {
	t.Helper()
	store, err := OpenExecutionPlanStore(filepath.Join(t.TempDir(), "execution-plans.json"))
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := store.Freeze(intent, plan)
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}
