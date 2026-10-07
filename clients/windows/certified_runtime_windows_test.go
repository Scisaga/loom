//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func windowsCertifiedTestView(t *testing.T, store *deviceclient.ProtectedStore, sequence uint64, revoke bool) control.DeviceViewEnvelope {
	_, envelope := windowsFixture(t)
	return envelope(store.PublicKey(), sequence, func(view *control.DeviceView) {
		if revoke {
			view.PolicyIDs = []string{}
			view.Policies = []control.NetworkPolicy{}
			view.Services = []control.Service{}
			view.BusinessProbeTargets = []control.ServiceProbeTargets{}
		}
	})
}

func TestWindowsRuntimeReadyRequiresSelectorStatusWithoutBusinessSuccess(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "runtime"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runtime", ".sing-box-active-demo.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if waitForPortableRuntime(ctx, root) {
		t.Fatal("temporary runtime config was mistaken for a connected selector")
	}
	lkg := &control.DeviceViewEnvelope{View: control.DeviceView{DeviceID: "demo-windows"}, ViewDigest: "sha256:" + strings.Repeat("1", 64)}
	activation := clientadapter.Activation{
		State:      clientadapter.State{Preference: clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeAuto}, NetworkGeneration: "demo-network"},
		Selections: []clientadapter.SelectionStatus{{Scope: "demo-service", CandidateID: "demo-route", State: "unknown"}},
	}
	if err := writeWindowsRuntimeStatus(root, lkg, activation, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !waitForPortableRuntime(ctx, root) {
		t.Fatal("actual selector readback required a successful business probe or report")
	}
}

func TestWindowsProbeDoesNotInventTargetScopeOrReduction(t *testing.T) {
	view := control.DeviceView{Routes: []control.RouteCandidate{{ID: "demo-route", FinalExit: "direct", Scope: "service:demo-service", ServiceID: "demo-service"}},
		DNSServers: []string{"192.0.2.53"}, BusinessProbeTargets: []control.ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{"https://demo.example/demo-probe"}}}}
	if probe, err := windowsBusinessProbe(view); err != nil || probe == nil {
		t.Fatalf("single authorized target unavailable: %v", err)
	}
	for _, missing := range []string{"dns", "target", "multiple-targets", "multiple-scopes"} {
		t.Run(missing, func(t *testing.T) {
			input := view
			switch missing {
			case "dns":
				input.DNSServers = nil
			case "target":
				input.BusinessProbeTargets = nil
			case "multiple-targets":
				input.BusinessProbeTargets = []control.ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{"https://demo.example/demo-probe", "https://demo.example/demo-other"}}}
			case "multiple-scopes":
				input.Routes = append(append([]control.RouteCandidate(nil), input.Routes...),
					control.RouteCandidate{ID: "demo-other", FinalExit: "direct", Scope: "service:demo-other-service", ServiceID: "demo-other-service"})
			}
			if probe, err := windowsBusinessProbe(input); err != nil || probe != nil {
				t.Fatalf("business scope without an unambiguous authorized target did not stay unknown: %v", err)
			}
		})
	}
}

func TestWindowsCertifiedRevocationSurvivesApplicationFailureAndRestart(t *testing.T) {
	testWindowsRevocationRecovery(t, clientsecret.UserProtector{})
}
func TestWindowsInstalledCertifiedRevocationSurvivesApplicationFailureAndRestart(t *testing.T) {
	testWindowsRevocationRecovery(t, clientsecret.MachineProtector{})
}
func testWindowsRevocationRecovery(t *testing.T, protector clientsecret.Protector) {
	t.Helper()
	root := t.TempDir()
	edition, profile := windowsTestEdition(protector)
	path := windowsProfileStatePath(root)
	store, err := deviceclient.OpenProtected(path, brokerTestInvite(t), protector)
	if err != nil {
		t.Fatal(err)
	}
	previous := windowsCertifiedTestView(t, store, 7, false)
	if err := store.SaveLKG(previous); err != nil {
		t.Fatal(err)
	}
	next := windowsCertifiedTestView(t, store, 8, true)
	// The current application verifies its bundled component, not an old local
	// component state. Missing bundle trust prevents all data-plane execution.
	originalKey := buildPlatformPublicKey
	buildPlatformPublicKey = ""
	t.Cleanup(func() { buildPlatformPublicKey = originalKey })
	if run, err := prepareClientAt(root, protector, edition); err != nil || run == nil {
		t.Fatalf("component failure prevented preparation of the authenticated repair path: %v", err)
	}
	fetch := func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		return next, nil
	}
	err = runWindowsGeneration(context.Background(), root, store, profile, fetch)
	if err == nil || !strings.Contains(err.Error(), "load signed Windows runtime components") {
		t.Fatalf("expected component application failure, got %v", err)
	}
	if !reflect.DeepEqual(store.LKG(), &next) {
		t.Fatal("failed component application restored a revoked service")
	}
	reopened, err := deviceclient.LoadProtected(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.LKG(), &next) || reopened.PublicKey() != store.PublicKey() {
		t.Fatal("restart lost the accepted LKG or device identity")
	}
	if err := reopened.SaveLKG(previous); err == nil {
		t.Fatal("restart allowed the pre-revocation floor")
	}
	offline := func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		return control.DeviceViewEnvelope{}, errors.New("demo private control unavailable")
	}
	if err := runWindowsGeneration(context.Background(), root, reopened, profile, offline); err == nil {
		t.Fatal("broken component unexpectedly ran after restart")
	}
	if !reflect.DeepEqual(reopened.LKG(), &next) {
		t.Fatal("offline retry restored old authorization")
	}
	if _, err := os.Stat(windowsRuntimeStatusPath(root)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed application left a current runtime status")
	}
}

func TestWindowsResponsibilityRemovalPersistsBeforeRuntimeProjection(t *testing.T) {
	testWindowsResponsibilityRemoval(t, clientsecret.UserProtector{})
}
func TestWindowsInstalledResponsibilityRemovalPersistsBeforeRuntimeProjection(t *testing.T) {
	testWindowsResponsibilityRemoval(t, clientsecret.MachineProtector{})
}
func testWindowsResponsibilityRemoval(t *testing.T, protector clientsecret.Protector) {
	t.Helper()
	root := t.TempDir()
	edition, profile := windowsTestEdition(protector)
	invite, envelope := windowsFixture(t)
	store, err := deviceclient.OpenProtected(windowsProfileStatePath(root), invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	previous := envelope(store.PublicKey(), 7)
	if err = store.SaveLKG(previous); err != nil {
		t.Fatal(err)
	}
	removed := envelope(store.PublicKey(), 8, func(view *control.DeviceView) {
		view.Responsibilities = []string{}
		view.PolicyIDs = []string{}
		view.Policies = []control.NetworkPolicy{}
		view.Services = []control.Service{}
		view.BusinessProbeTargets = []control.ServiceProbeTargets{}
	})
	if removed.View.RuntimeProfile != nil {
		t.Fatal("fixture retained execution authorization")
	}
	fetch := func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		return removed, nil
	}
	if err = runWindowsGeneration(context.Background(), root, store, profile, fetch); err == nil {
		t.Fatal("revoked access unexpectedly started")
	}
	reopened, err := deviceclient.LoadProtected(windowsProfileStatePath(root), protector)
	if err != nil || !reflect.DeepEqual(reopened.LKG(), &removed) {
		t.Fatal("no-runtime authorization was not durably accepted")
	}
	if reopened.SaveLKG(previous) == nil {
		t.Fatal("responsibility revocation rolled back")
	}
	if _, err = prepareClientAt(root, protector, edition); err != nil {
		t.Fatal("revoked access cannot prepare its authenticated refresh path", err)
	}
}

func TestWindowsSelectorFailureCannotPublishRunning(t *testing.T) {
	routes := []clientmodel.RouteCandidate{{ID: "demo-route", Scope: "demo-service", FinalExit: "direct"}}
	state := clientadapter.State{NetworkGeneration: "demo-network"}
	if windowsActivationApplied(clientadapter.Activation{State: state}, routes) {
		t.Fatal("failed selector application accepted as running")
	}
	if !windowsActivationApplied(clientadapter.Activation{State: state}, nil) {
		t.Fatal("deny-only execution demanded a granted candidate")
	}
}

func windowsTestEdition(protector clientsecret.Protector) (clientEdition, clientruntime.WindowsRuntimeProfile) {
	if _, ok := protector.(clientsecret.MachineProtector); ok {
		return editionInstalled, clientruntime.WindowsInstalledProfile
	}
	return editionPortableMixed, clientruntime.WindowsPortableMixedProfile
}

func TestWindowsUnrelatedCertifiedProgressDoesNotRestartRuntime(t *testing.T) {
	root := t.TempDir()
	protector := clientsecret.MachineProtector{}
	invite, envelope := windowsFixture(t)
	store, err := deviceclient.OpenProtected(windowsProfileStatePath(root), invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	before := envelope(store.PublicKey(), 7)
	if err = store.SaveLKG(before); err != nil {
		t.Fatal(err)
	}
	after := envelope(store.PublicKey(), 8)
	if before.ViewDigest != after.ViewDigest {
		t.Fatal("fixture changed execution inputs")
	}
	fetch := func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		return after, nil
	}
	changed, err := refreshWindowsCertifiedView(context.Background(), store, fetch)
	if err != nil || changed {
		t.Fatalf("same View restarted runtime: %v", err)
	}
	reopened, err := deviceclient.LoadProtected(windowsProfileStatePath(root), protector)
	if err != nil || !reflect.DeepEqual(reopened.LKG(), &after) {
		t.Fatal("new proof/frontier was not durable")
	}
	// A concurrent process can advance only the proof as well.
	further := envelope(store.PublicKey(), 9)
	if err = reopened.SaveLKG(further); err != nil {
		t.Fatal(err)
	}
	fetch = func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		return further, nil
	}
	if changed, err = refreshWindowsCertifiedView(context.Background(), store, fetch); err != nil || changed || !reflect.DeepEqual(store.LKG(), &further) {
		t.Fatal("durable Reload caused an unrelated restart", err)
	}
	racing := envelope(store.PublicKey(), 10)
	fetch = func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		if err := reopened.SaveLKG(racing); err != nil {
			t.Fatal(err)
		}
		return further, nil
	}
	if changed, err = refreshWindowsCertifiedView(context.Background(), store, fetch); err != nil || changed || !reflect.DeepEqual(store.LKG(), &racing) {
		t.Fatal("older in-flight response disturbed newer durable progress", err)
	}

}
