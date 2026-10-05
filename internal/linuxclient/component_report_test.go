package linuxclient

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"loom/internal/control"
)

func TestLinuxComponentReadbacksFollowRunningImageAcrossReplacement(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte(`package main
import ("fmt"; "os"; "time")
var fixtureVersion string
func main() {
 if len(os.Args)>1 && os.Args[1]=="version" {fmt.Println("sing-box version " + fixtureVersion);return}
 fmt.Println("ready")
 for {time.Sleep(time.Hour)}
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	build := func(path, version string) {
		t.Helper()
		command := exec.Command("go", "build", "-o", path, "-ldflags", "-X main.fixtureVersion="+version, source)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build component fixture: %v %s", err, output)
		}
	}
	path, replacement := filepath.Join(dir, "sing-box"), filepath.Join(dir, "replacement")
	build(path, "demo-old")
	build(replacement, "demo-new")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { command.Process.Kill(); command.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal("component fixture did not start")
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	readbacks, err := linuxComponentReadbacks(context.Background(), command.Process.Pid)
	if err != nil || len(readbacks) != 2 {
		t.Fatalf("running components missing without expectations: %+v %v", readbacks, err)
	}
	for _, value := range readbacks {
		if value.Platform != "linux-"+runtime.GOARCH || value.Validate() != nil {
			t.Fatalf("actual platform or coordinate lost: %+v", value)
		}
	}
	if readbacks[0].ComponentID != "agent" || readbacks[1].ComponentID != "sing-box" || readbacks[1].Version != "demo-old" || readbacks[1].ArtifactDigest != control.ReleaseDigest(original) {
		t.Fatalf("disk replacement was confused with the running process: %+v", readbacks)
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil || readbacks[0].ArtifactDigest != control.ReleaseDigest(self) {
		t.Fatal("agent digest does not identify the running image")
	}
}

func TestLinuxUnavailableDataPlaneRetainsActualAgent(t *testing.T) {
	for _, pid := range []int{0, -1} {
		readbacks, err := linuxComponentReadbacks(context.Background(), pid)
		if len(readbacks) != 1 || readbacks[0].ComponentID != "agent" || (err == nil) != (pid == 0) {
			t.Fatalf("unavailable data plane fabricated or erased components: %+v %v", readbacks, err)
		}
	}
}
