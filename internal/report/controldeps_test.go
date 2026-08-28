package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"loom/internal/model"
	"loom/internal/validate"
	"loom/internal/webui"
)

const validControlSSOT = `
defaults:
  dns: [223.5.5.5]
  distribution_url: https://distribution.example/loom/
  components: {sing_box: 1, wireguard: 1, agent: 1}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: Sfhh2xviqn8iws9mnVojcZEQRZANuhoLjoMqjN89y6Q=}
    access:
      platform: linux-server
      credentials: [c1]
      mixed_ports: [{port: 1080, declaration: d1}]
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: 11en8KSnR461ATx3ePxn3hM1+7omYdXS2K6YEPHt3To=}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, egress_capable: true, wg_public_key: dVg67BLu61j4V2JshVQMHJFuVjhthA+RO4DKSCTtHA0=}}
tunnels:
  - {from: acc, to: b, listen_port: 61637, from_addr: 10.99.0.1/32, to_addr: 10.99.0.2/32}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, max_hops: 2, allowed_servers: [a, b]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
`

func TestControlSaveRejectsInvalidWithoutChangingSSOT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	if err := os.WriteFile(path, []byte(validControlSSOT), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := controlDeps(&Control{SSOTPath: path})

	bad := strings.Replace(validControlSSOT, "direction: bidirectional", "direction: bogus", 1)
	if err := deps.Save(bad); err == nil || !strings.Contains(err.Error(), "校验不通过") {
		t.Fatalf("保存无效 SSOT 的错误 = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != validControlSSOT {
		t.Fatal("校验失败后 SSOT 仍被改写")
	}
	assertNoSSOTTemps(t, dir)
}

func TestControlSaveConcurrentIsAtomicAndLeavesNoTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	if err := os.WriteFile(path, []byte(validControlSSOT), 0o644); err != nil {
		t.Fatal(err)
	}
	const writers = 24
	contents := make([]string, writers)
	saves := make([]func(string) error, writers)
	wantFinal := make(map[string]bool, writers)
	for i := range contents {
		contents[i] = fmt.Sprintf("%s\n# concurrent-writer-%02d\n", validControlSSOT, i)
		// 每个保存函数来自独立 deps 实例,故意不共享进程内锁。
		// 这能同时覆盖多实例/多进程需要的唯一临时文件语义。
		saves[i] = controlDeps(&Control{SSOTPath: path}).Save
		wantFinal[contents[i]] = true
	}

	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i, content := range contents {
		save := saves[i]
		wg.Add(1)
		go func(content string, save func(string) error) {
			defer wg.Done()
			<-start
			errs <- save(content)
		}(content, save)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("并发保存失败:%v", err)
		}
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !wantFinal[string(got)] {
		t.Fatal("最终 SSOT 不是任何一个完整的并发输入")
	}
	s, err := model.Load(got)
	if err != nil {
		t.Fatalf("最终 SSOT 不可解析:%v", err)
	}
	if fs := validate.Validate(s); len(fs) != 0 {
		t.Fatalf("最终 SSOT 不可用:\n%s", validate.Format(fs))
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o644 {
		t.Fatalf("SSOT mode = %o, 期望 644", info.Mode().Perm())
	}
	assertNoSSOTTemps(t, dir)
}

func TestIndependentControlDepsRevisionGuardAllowsOnlyOneWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssot.yaml")
	if err := os.WriteFile(path, []byte(validControlSSOT), 0o640); err != nil {
		t.Fatal(err)
	}
	a := controlDeps(&Control{SSOTPath: path})
	b := controlDeps(&Control{SSOTPath: path})
	revision, err := a.Revision()
	if err != nil {
		t.Fatal(err)
	}
	contents := []string{
		validControlSSOT + "\n# independent-a\n",
		validControlSSOT + "\n# independent-b\n",
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	for i, deps := range []*webui.ControlDeps{a, b} {
		go func(content string, deps *webui.ControlDeps) {
			<-start
			errs <- deps.SaveIfRevision(content, revision)
		}(contents[i], deps)
	}
	close(start)
	var success, conflict int
	for range 2 {
		if err := <-errs; err == nil {
			success++
		} else if strings.Contains(err.Error(), "SSOT") {
			conflict++
		} else {
			t.Fatalf("unexpected guarded save error: %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("independent guarded writers: success=%d conflict=%d", success, conflict)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("SSOT mode was not preserved: info=%v err=%v", info, err)
	}
}

func TestSSOTRejectsSymlinkHardlinkAndExternalSnapshotChange(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, []byte(validControlSSOT), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.yaml")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readSSOTSnapshot(symlink); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("SSOT symlink error = %v", err)
	}
	hardlink := filepath.Join(dir, "hardlink.yaml")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readSSOTSnapshot(target); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("SSOT hardlink error = %v", err)
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readSSOTSnapshot(target)
	if err != nil {
		t.Fatal(err)
	}
	external := append(append([]byte(nil), snapshot.body...), []byte("\n# external\n")...)
	if err := os.WriteFile(target, external, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveSSOTAtomicFromSnapshot(target, []byte(validControlSSOT), snapshot); err == nil ||
		!strings.Contains(err.Error(), "外部修改") {
		t.Fatalf("stale snapshot save error = %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, external) {
		t.Fatalf("external SSOT edit was overwritten: err=%v", err)
	}
}

func TestSaveSSOTAtomicCleansTempAfterRenameFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "ssot.yaml")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := saveSSOTAtomic(target, []byte(validControlSSOT)); err == nil {
		t.Fatal("用文件替换非空目录竟然成功")
	}
	assertNoSSOTTemps(t, dir)
}

func assertNoSSOTTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("遗留 SSOT 临时文件:%v", matches)
	}
}
