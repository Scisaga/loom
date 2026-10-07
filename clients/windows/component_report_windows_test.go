//go:build windows

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientcomponent"
	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestWindowsComponentProcess(t *testing.T) {
	if os.Getenv("LOOM_COMPONENT_HELPER") != "1" {
		return
	}
	fmt.Println("ready")
	io.Copy(io.Discard, os.Stdin)
}

func TestWindowsComponentReadbacksMeasureRunningFilesWithoutExpectations(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	paths := clientcomponent.RuntimePaths{SingBox: filepath.Join(root, "demo-component.exe"), Wintun: filepath.Join(root, "wintun.dll")}
	for _, item := range []struct {
		path  string
		body  []byte
		value *clientcomponent.Component
	}{
		{paths.SingBox, body, &paths.Manifest.SingBox},
		{paths.Wintun, []byte("demo unloaded component"), &paths.Manifest.Wintun},
	} {
		if err := os.WriteFile(item.path, item.body, 0600); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(item.body)
		*item.value = clientcomponent.Component{Version: "demo-version", SHA256: hex.EncodeToString(hash[:])}
	}
	held, err := pinWindowsRuntimeComponents(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, file := range held {
			file.Close()
		}
	}()
	command := exec.Command(paths.SingBox, "-test.run=^TestWindowsComponentProcess$")
	command.Env = append(os.Environ(), "LOOM_COMPONENT_HELPER=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Process.Kill()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatal("real child did not become ready", err)
	}
	readbacks, err := windowsComponentReadbacks(command.Process.Pid, paths, held)
	if err != nil || len(readbacks) != 2 || readbacks[0].ComponentID != "agent" || readbacks[1].ComponentID != "sing-box" || readbacks[1].ArtifactDigest != "sha256:"+paths.Manifest.SingBox.SHA256 {
		t.Fatal("actual child or agent missing, or unloaded DLL fabricated", readbacks, err)
	}
	for _, path := range []string{paths.SingBox, paths.Wintun} {
		if err := os.Rename(path, path+".replaced"); err == nil {
			t.Fatal("held component was replaceable")
		}
		if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			file.Close()
			t.Fatal("held component was writable")
		}
	}
	wrong := paths
	wrong.Manifest.SingBox.SHA256 = strings.Repeat("1", 64)
	if result, err := windowsComponentReadbacks(command.Process.Pid, wrong, held); err == nil || len(result) != 1 || result[0].ComponentID != "agent" {
		t.Fatal("unverified file became a reported component, or agent was erased", result, err)
	}
	input.Close()
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	if result, err := windowsComponentReadbacks(command.Process.Pid, paths, held); err == nil || len(result) != 1 || result[0].ComponentID != "agent" {
		t.Fatal("stopped process remained reported", result, err)
	}
	for _, file := range held {
		file.Close()
	}
	for _, path := range []string{paths.SingBox, paths.Wintun} {
		if err := os.Rename(path, path+".released"); err != nil {
			t.Fatal("normal stop retained a component handle", err)
		}
	}
}
func TestWindowsReportBindsActualServiceTargetAndLeavesOtherScopesUnknown(t *testing.T) {
	invite, envelope := windowsFixture(t)
	public := invite.ControlProof.Genesis.Payload.(control.Genesis).ControlConfig.Members[0].PublicKey
	lkg := envelope(public, 7)
	lkg.View.DNSServers = []string{"192.0.2.53"}
	lkg.View.BusinessProbeTargets = []control.ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{"https://demo.example/"}}}
	route := lkg.View.Routes[0]
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	activation := clientadapter.Activation{State: clientadapter.State{NetworkGeneration: "demo-network", Observations: []clientmodel.Observation{{CandidateID: route.ID, Scope: route.Scope, NetworkGeneration: "demo-network", Action: "business", Result: "unavailable", ObservedAt: now.Format(time.RFC3339), ValidUntil: now.Add(time.Minute).Format(time.RFC3339)}}}, Selections: []clientadapter.SelectionStatus{{Scope: route.Scope, CandidateID: route.ID}}}
	activation.State.Preference = clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}
	report, err := windowsDeviceReport(&lkg, activation, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Runtime.State != "running" || report.Runtime.AppliedViewDigest != lkg.ViewDigest || len(report.Selections) != 1 || report.Selections[0].ServiceID != route.ServiceID || len(report.Observations) != 1 || report.Observations[0].Target != "https://demo.example/" || report.Observations[0].SpecDigest != route.SpecDigest || report.Observations[0].Validate() != nil {
		t.Fatal("report lost authenticated coordinates or coupled runtime to business failure")
	}
	first := windowsRuntimeFactsDigest(activation, nil)
	activation.State.Preference = clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-unavailable-exit"}
	changed, err := windowsDeviceReport(&lkg, activation, nil, now)
	if err != nil || changed.Preference == nil || changed.Preference.Mode != "fixed_exit" || changed.Preference.Exit != "demo-unavailable-exit" || first == windowsRuntimeFactsDigest(activation, nil) || changed.Selections[0] != report.Selections[0] {
		t.Fatal("setting change was not reported independently from the selector", err)
	}
	first = windowsRuntimeFactsDigest(activation, nil)
	activation.State.Observations[0].Result = "available"
	if first == windowsRuntimeFactsDigest(activation, nil) {
		t.Fatal("actual result change lost")
	}
	lkg.View.BusinessProbeTargets[0].Targets = append(lkg.View.BusinessProbeTargets[0].Targets, "https://demo.example/other")
	report, err = windowsDeviceReport(&lkg, activation, nil, now)
	if err != nil || len(report.Observations) != 0 {
		t.Fatal("ambiguous target became a fabricated observation")
	}
}
