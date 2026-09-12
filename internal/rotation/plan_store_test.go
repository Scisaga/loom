package rotation

import (
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestExecutionPlanStoreFreezesFirstAllocationAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "execution-plans.json")
	intent := testIntent(t)
	plan := runtimeExecutionPlan(intent)
	store, err := OpenExecutionPlanStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Freeze(intent, plan)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("execution plan store 权限不是 0600: %v %v", info, err)
	}
	reopened, err := OpenExecutionPlanStore(path)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := reopened.Freeze(intent, plan)
	if err != nil || replayed.PlanHash() != first.PlanHash() || !wire.EqualCanonical(replayed.Plan(), first.Plan()) {
		t.Fatalf("重启后 execution plan first-result 改变: %#v err=%v", replayed, err)
	}
	changed := plan
	changed.TargetTuples = []Tuple{{Transport: "udp", Address: "0.0.0.0", Port: 41002}}
	if _, err := reopened.Freeze(intent, changed); err == nil {
		t.Fatal("同一 rotation ID 在重启后重新分配了 target tuple")
	}
}

func TestExecutionPlanStoreRejectsTamperedIntentAndPlan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "execution-plans.json")
	intent := testIntent(t)
	plan := runtimeExecutionPlan(intent)
	store, err := OpenExecutionPlanStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Freeze(intent, plan); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state executionPlanStateV1
	if _, err := wire.DecodeStrict(body, 16<<20, &state); err != nil {
		t.Fatal(err)
	}
	state.Records[0].Plan.TargetTuples[0].Port++
	body, err = wire.MarshalCanonical(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExecutionPlanStore(path); err == nil {
		t.Fatal("被篡改的 execution plan store 仍可打开")
	}
}
