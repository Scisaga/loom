package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"loom/internal/model"
	"loom/internal/webui"
)

func TestDefaultExitControlListsAuthorizedOptionsAndWritesSSOT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	initial := controlUIFixture(t)
	writeControlUIFile(t, path, initial)
	deps := controlDeps(&Control{SSOTPath: path})
	if deps.DefaultExits == nil {
		t.Fatal("control dependencies have no default-exit editor")
	}

	state, err := deps.DefaultExits.Get("workstation")
	if err != nil {
		t.Fatalf("Get default exit: %v", err)
	}
	if state.Node != "workstation" || state.Current != "best-egress" || len(state.Revision) != 64 {
		t.Fatalf("default exit state = %+v", state)
	}
	assertDefaultExitOption(t, state.Options, "", "none", true)
	assertDefaultExitOption(t, state.Options, "best-egress", "automatic", true)
	assertDefaultExitOption(t, state.Options, "sg-fixed", "fixed", true)
	assertDefaultExitOption(t, state.Options, "llm-ttft", "automatic", false)
	assertDefaultExitOption(t, state.Options, "llm-3p", "automatic", false)

	// 重复提交同一值必须是无写入的幂等操作，不能仅因 YAML 重编码推进 revision。
	unchanged, err := deps.DefaultExits.Set("workstation", "best-egress", state.Revision)
	if err != nil {
		t.Fatalf("idempotent Set: %v", err)
	}
	if unchanged.Revision != state.Revision || !bytes.Equal(readControlUIFile(t, path), initial) {
		t.Fatal("idempotent Set rewrote the SSOT")
	}

	selected, err := deps.DefaultExits.Set("workstation", "sg-fixed", state.Revision)
	if err != nil {
		t.Fatalf("Set sg-fixed: %v", err)
	}
	if selected.Current != "sg-fixed" || selected.Revision == state.Revision {
		t.Fatalf("selected state = %+v", selected)
	}
	afterSelect := readControlUIFile(t, path)
	assertControlUIComments(t, afterSelect)
	ssot, err := model.Load(afterSelect)
	if err != nil {
		t.Fatal(err)
	}
	if got := ssot.NodeByID()["workstation"].Access.DefaultDeclaration; got != "sg-fixed" {
		t.Fatalf("persisted default_declaration=%q", got)
	}

	if _, err := deps.DefaultExits.Set("workstation", "best-egress", state.Revision); err == nil ||
		!strings.Contains(err.Error(), "SSOT 已被其他操作修改") {
		t.Fatalf("stale default-exit save error = %v", err)
	}
	assertControlUIFile(t, path, afterSelect)

	if _, err := deps.DefaultExits.Set("workstation", "llm-ttft", selected.Revision); err == nil ||
		!strings.Contains(err.Error(), "没有可用候选") {
		t.Fatalf("non-proxy default-exit save error = %v", err)
	}
	if _, err := deps.DefaultExits.Set("phone", "best-egress", selected.Revision); err == nil ||
		!strings.Contains(err.Error(), "未获授权") {
		t.Fatalf("unauthorized default-exit save error = %v", err)
	}
	if _, err := deps.DefaultExits.Get("ci-runner"); err == nil || !strings.Contains(err.Error(), "不能承载") {
		t.Fatalf("fixed-only ingress Get error = %v", err)
	}

	cleared, err := deps.DefaultExits.Set("workstation", "", selected.Revision)
	if err != nil {
		t.Fatalf("clear default exit: %v", err)
	}
	if cleared.Current != "" {
		t.Fatalf("cleared state = %+v", cleared)
	}
	content := readControlUIFile(t, path)
	ssot, err = model.Load(content)
	if err != nil {
		t.Fatal(err)
	}
	if got := ssot.NodeByID()["workstation"].Access.DefaultDeclaration; got != "" {
		t.Fatalf("cleared persisted default_declaration=%q", got)
	}
}

func TestDefaultExitControlRevisionAllowsOneConcurrentWinner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	if err := os.WriteFile(path, controlUIFixture(t), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := controlDeps(&Control{SSOTPath: path})
	state, err := deps.DefaultExits.Get("workstation")
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, declaration := range []string{"sg-fixed", ""} {
		declaration := declaration
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := deps.DefaultExits.Set("workstation", declaration, state.Revision)
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	success, conflict := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			success++
		case strings.Contains(err.Error(), "SSOT 已被其他操作修改"):
			conflict++
		default:
			t.Fatalf("unexpected concurrent Set error: %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("concurrent Set success=%d conflict=%d", success, conflict)
	}
}

func assertDefaultExitOption(t *testing.T, options []webui.DefaultExitOption, id, mode string, available bool) {
	t.Helper()
	for _, option := range options {
		if option.ID == id {
			if option.Mode != mode || option.Available != available {
				t.Fatalf("option %q = %+v,want mode=%s available=%t", id, option, mode, available)
			}
			return
		}
	}
	t.Fatalf("option %q missing from %+v", id, options)
}
