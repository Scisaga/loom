//go:build windows

package main

import (
	"loom/internal/clientadapter"
	"loom/internal/clientcomponent"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWindowsComponentReadbacksOnlyReportActualCertifiedCoordinates(t *testing.T) {
	view := control.DeviceView{ExpectedComponents: []control.ComponentReadback{{ComponentID: "demo-uninstalled", Platform: "windows-" + runtime.GOARCH}, {ComponentID: "sing-box", Platform: "windows-" + runtime.GOARCH}}}
	components := clientcomponent.RuntimePaths{Manifest: clientcomponent.Manifest{SingBox: clientcomponent.Component{Version: "v1.11.4", SHA256: strings.Repeat("1", 64)}}}
	readbacks := windowsComponentReadbacks(view, components)
	if len(readbacks) != 1 || readbacks[0].ComponentID != "sing-box" || readbacks[0].ArtifactDigest != "sha256:"+strings.Repeat("1", 64) {
		t.Fatal("uninstalled component was fabricated or verified component missing")
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
	report, err := windowsDeviceReport(&lkg, activation, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Runtime.State != "running" || report.Runtime.AppliedViewDigest != lkg.ViewDigest || len(report.Selections) != 1 || report.Selections[0].ServiceID != route.ServiceID || len(report.Observations) != 1 || report.Observations[0].Target != "https://demo.example/" || report.Observations[0].SpecDigest != route.SpecDigest || report.Observations[0].Validate() != nil {
		t.Fatal("report lost authenticated coordinates or coupled runtime to business failure")
	}
	first := windowsRuntimeFactsDigest(activation, nil)
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
