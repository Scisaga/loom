package clientruntime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/agent"
	"loom/internal/measure"
)

func TestWindowsAgentHistoryRequiresSamePlanAndDataPlane(t *testing.T) {
	root := t.TempDir()
	cfg := &agent.Config{Node: "history-test"}
	start := func(identity ...string) *WindowsAgent {
		t.Helper()
		a, err := StartWindowsAgent(context.Background(), cfg, root, identity...)
		if err != nil {
			t.Fatal(err)
		}
		<-a.Done()
		if err := a.Stop(); err != nil {
			t.Fatal(err)
		}
		return a
	}
	first := start("activated-transport-a")
	sample := measure.Measurement{TS: time.Now().UTC().Format(time.RFC3339), Node: cfg.Node, Declaration: "service", CandidateID: "same-tag", DecisionScope: "original-scope", FirstByteMs: 17, Kind: measure.Active, Point: measure.L4Tunnel}
	if err := measure.Append(first.measurementPath, []measure.Measurement{sample}); err != nil {
		t.Fatal(err)
	}
	same := start("activated-transport-a")
	if same.statePath == first.statePath || same.measurementPath != first.measurementPath {
		t.Fatal("same activation should preserve only raw history, not generation state")
	}
	ms, err := measure.Load(same.measurementPath)
	if err != nil || len(ms) != 1 || ms[0] != sample {
		t.Fatalf("history sample or its time changed: %+v %v", ms, err)
	}
	// An address or Hy2 credential can change without changing any Agent tag.
	changedTransport := start("activated-transport-b")
	if changedTransport.measurementPath == same.measurementPath {
		t.Fatal("same candidate tags reused measurements from a different data plane")
	}
	cfg.ProbeSecret = "new-probe-credential"
	changedPlan := start("activated-transport-a")
	if changedPlan.measurementPath == same.measurementPath {
		t.Fatal("changed hydrated plan reused old history")
	}
	legacyA, legacyB := start(), start()
	if legacyA.measurementPath == legacyB.measurementPath || filepath.Dir(legacyA.measurementPath) != filepath.Dir(legacyA.statePath) {
		t.Fatal("caller without transport identity must remain generation-isolated")
	}
}

func TestWindowsAgentHistoryRejectsNonRegularFiles(t *testing.T) {
	root := t.TempDir()
	cfg := &agent.Config{Node: "history-test"}
	a, err := StartWindowsAgent(context.Background(), cfg, root, "transport")
	if err != nil {
		t.Fatal(err)
	}
	<-a.Done()
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a.measurementPath, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := StartWindowsAgent(context.Background(), cfg, root, "transport"); err == nil {
		t.Fatal("directory accepted as historical measurement file")
	}
}
