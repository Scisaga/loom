package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"loom/internal/webui"
)

func TestControlUIRevisionRejectsStaleSaveWithoutTouchingDisk(t *testing.T) {
	dir := t.TempDir()
	ssotPath := filepath.Join(dir, "ssot.yaml")
	initial := controlUIFixture(t)
	writeControlUIFile(t, ssotPath, initial)

	deps := controlDeps(&Control{SSOTPath: ssotPath, BootstrapSSHKey: filepath.Join(dir, "bootstrap")})
	oldRevision, err := deps.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if len(oldRevision) != 64 {
		t.Fatalf("revision = %q, want a SHA-256 hex digest", oldRevision)
	}

	// Simulate a git/editor write after the browser loaded its form.
	external := append(append([]byte(nil), initial...), []byte("\n# external edit\n")...)
	writeControlUIFile(t, ssotPath, external)
	candidate := string(initial) + "\n# stale browser edit\n"
	if err := deps.SaveIfRevision(candidate, oldRevision); err == nil ||
		!strings.Contains(err.Error(), "SSOT") {
		t.Fatalf("SaveIfRevision with stale revision error = %v", err)
	}
	assertControlUIFile(t, ssotPath, external)
	assertNoControlUITemps(t, dir)

	currentRevision, err := deps.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if currentRevision == oldRevision {
		t.Fatal("revision did not change after the on-disk content changed")
	}

	want := string(initial) + "\n# accepted browser edit\n"
	if err := deps.SaveIfRevision(want, currentRevision); err != nil {
		t.Fatalf("SaveIfRevision with current revision: %v", err)
	}
	assertControlUIFile(t, ssotPath, []byte(want))
	assertNoControlUITemps(t, dir)
	if next, err := deps.Revision(); err != nil {
		t.Fatal(err)
	} else if next == currentRevision {
		t.Fatal("revision did not advance after a successful save")
	}
}

func TestControlUIConcurrentSaveIfRevisionHasOneWinner(t *testing.T) {
	dir := t.TempDir()
	ssotPath := filepath.Join(dir, "ssot.yaml")
	initial := controlUIFixture(t)
	writeControlUIFile(t, ssotPath, initial)

	deps := controlDeps(&Control{SSOTPath: ssotPath, BootstrapSSHKey: filepath.Join(dir, "bootstrap")})
	revision, err := deps.Revision()
	if err != nil {
		t.Fatal(err)
	}
	contents := []string{
		string(initial) + "\n# concurrent revision writer A\n",
		string(initial) + "\n# concurrent revision writer B\n",
	}

	start := make(chan struct{})
	errs := make(chan error, len(contents))
	var wg sync.WaitGroup
	for _, content := range contents {
		content := content
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- deps.SaveIfRevision(content, revision)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	succeeded, conflicted := 0, 0
	for err := range errs {
		if err == nil {
			succeeded++
		} else if strings.Contains(err.Error(), "SSOT") {
			conflicted++
		} else {
			t.Fatalf("unexpected concurrent save error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent results: %d succeeded, %d conflicted; want 1 and 1", succeeded, conflicted)
	}
	got, err := os.ReadFile(ssotPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != contents[0] && string(got) != contents[1] {
		t.Fatal("winning save did not leave one complete candidate on disk")
	}
	assertNoControlUITemps(t, dir)
}

func TestControlUIServicesPreserveCommentsAndUseRevisionGuard(t *testing.T) {
	dir := t.TempDir()
	ssotPath := filepath.Join(dir, "ssot.yaml")
	initial := controlUIFixture(t)
	writeControlUIFile(t, ssotPath, initial)

	deps := controlDeps(&Control{SSOTPath: ssotPath, BootstrapSSHKey: filepath.Join(dir, "bootstrap")})
	if deps.Services == nil {
		t.Fatal("control dependencies have no structured service editor")
	}
	revision0, err := deps.Revision()
	if err != nil {
		t.Fatal(err)
	}

	update := webui.ServiceInput{
		ID:          "existing-service",
		Name:        "Updated service",
		Addresses:   []string{"updated.example.com", ".updated.example.net"},
		Declaration: "best-egress",
	}
	if err := deps.Services.Upsert(update, revision0); err != nil {
		t.Fatalf("upsert service: %v", err)
	}
	afterUpdate := readControlUIFile(t, ssotPath)
	assertControlUIComments(t, afterUpdate)
	for _, want := range []string{"Updated service", "updated.example.com", ".updated.example.net"} {
		if !bytes.Contains(afterUpdate, []byte(want)) {
			t.Errorf("updated SSOT does not contain %q", want)
		}
	}

	if err := deps.Services.Upsert(webui.ServiceInput{
		ID: "stale-service", Addresses: []string{"stale.example.com"}, Declaration: "best-egress",
	}, revision0); err == nil {
		t.Fatal("service upsert accepted an old revision")
	}
	assertControlUIFile(t, ssotPath, afterUpdate)

	revision1, err := deps.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.Services.Upsert(webui.ServiceInput{
		ID: "temporary-service", Addresses: []string{"temporary.example.com"}, Declaration: "best-egress",
	}, revision1); err != nil {
		t.Fatalf("add temporary service: %v", err)
	}
	afterAdd := readControlUIFile(t, ssotPath)
	assertControlUIComments(t, afterAdd)

	if err := deps.Services.Delete("temporary-service", revision1); err == nil {
		t.Fatal("service delete accepted an old revision")
	}
	assertControlUIFile(t, ssotPath, afterAdd)

	revision2, err := deps.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.Services.Delete("temporary-service", revision2); err != nil {
		t.Fatalf("delete service: %v", err)
	}
	afterDelete := readControlUIFile(t, ssotPath)
	assertControlUIComments(t, afterDelete)
	if bytes.Contains(afterDelete, []byte("temporary-service")) {
		t.Fatal("deleted service remains in SSOT")
	}
	assertNoControlUITemps(t, dir)
}

func controlUIFixture(t *testing.T) []byte {
	t.Helper()
	base, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatalf("read SSOT fixture: %v", err)
	}
	return append(base, []byte(`

# preserve the service catalog comment
services:
  # preserve the existing service comment
  - id: existing-service
    name: Existing service
    addresses: [api.example.com] # preserve the address comment
    declaration: best-egress
`)...)
}

func assertControlUIComments(t *testing.T, content []byte) {
	t.Helper()
	for _, comment := range []string{
		"# preserve the service catalog comment",
		"# preserve the existing service comment",
		"# preserve the address comment",
		"# 组件版本是期望态的一部分",
	} {
		if !bytes.Contains(content, []byte(comment)) {
			t.Errorf("structured service edit lost comment %q", comment)
		}
	}
}

func writeControlUIFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readControlUIFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func assertControlUIFile(t *testing.T, path string, want []byte) {
	t.Helper()
	if got := readControlUIFile(t, path); !bytes.Equal(got, want) {
		t.Fatalf("%s changed unexpectedly\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func assertNoControlUITemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain after atomic save: %v", matches)
	}
}
