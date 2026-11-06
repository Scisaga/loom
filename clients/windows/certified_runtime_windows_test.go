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
		State:      clientadapter.State{Preference: clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, NetworkGeneration: "demo-network"},
		Selections: []clientadapter.SelectionStatus{{Scope: "service:demo-service", CandidateID: "demo-route", State: "unknown"}},
	}
	readAt := time.Date(2030, 1, 1, 0, 0, 20, 0, time.UTC)
	if err := writeWindowsRuntimeStatus(root, lkg, activation, false, readAt); err != nil {
		t.Fatal(err)
	}
	status, err := readWindowsRuntimeStatus(root)
	if err != nil || status.SelectorReadAt != readAt.Format(time.RFC3339Nano) {
		t.Fatal("selector readback completion time was not preserved", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !waitForPortableRuntime(ctx, root) {
		t.Fatal("actual selector readback required a successful business probe or report")
	}
}

func TestWindowsSelectedPolicyUsesOnlyItsServicesOptionalMeasurementURLs(t *testing.T) {
	view := control.DeviceView{PolicyIDs: []string{"demo-policy", "demo-policy-other"}, Services: []control.Service{{ID: "demo-service", ProbeURLs: []string{"https://demo.example/"}}, {ID: "demo-other", ProbeURLs: []string{"https://demo-other.example/"}}}, Policies: []control.NetworkPolicy{{ID: "demo-policy", ServiceID: "demo-service", Action: "allow"}, {ID: "demo-policy-other", ServiceID: "demo-other", Action: "allow"}}}
	service, targets := windowsProbeTargets(view, "demo-policy")
	if service != "demo-service" || !reflect.DeepEqual(targets, []string{"https://demo.example/"}) {
		t.Fatal("unselected Service supplied targets")
	}
	view.Services[0].ProbeURLs = nil
	if _, targets := windowsProbeTargets(view, "demo-policy"); len(targets) != 0 {
		t.Fatal("missing optional URLs invented defaults")
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
	if changed, err := refreshWindowsCertifiedView(context.Background(), store, fetch); err != nil || !changed {
		t.Fatalf("certified revocation was not accepted before application: %v", err)
	}
	fetchCalled := false
	startupFetch := func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		fetchCalled = true
		return control.DeviceViewEnvelope{}, errors.New("demo slow private control must not gate local component application")
	}
	err = runWindowsGeneration(context.Background(), root, store, profile, startupFetch)
	if fetchCalled {
		t.Fatal("runtime startup waited for private configuration before using its authenticated LKG")
	}
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

	})
	if testDeviceExecution(removed.View).RuntimeProfile != nil {
		t.Fatal("fixture retained execution authorization")
	}
	fetch := func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		return removed, nil
	}
	if changed, err := refreshWindowsCertifiedView(context.Background(), store, fetch); err != nil || !changed {
		t.Fatalf("responsibility revocation was not accepted: %v", err)
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
	routes := []clientmodel.RouteCandidate{{ID: "demo-route", Scope: "service:demo-service", FinalExit: "direct", PolicyID: "demo-policy"}}
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

func TestWindowsConcurrentAcceptedProgressKeepsNewerResponseAndReportSequence(t *testing.T) {
	root := t.TempDir()
	protector := clientsecret.MachineProtector{}
	invite, envelope := windowsFixture(t)
	path := windowsProfileStatePath(root)
	store, err := deviceclient.OpenProtected(path, invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	before := envelope(store.PublicKey(), 7)
	if err = store.SaveLKG(before); err != nil {
		t.Fatal(err)
	}
	concurrent, err := deviceclient.LoadProtected(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	intermediate := envelope(store.PublicKey(), 8)
	next := envelope(store.PublicKey(), 9)
	var reserved control.U64
	fetch := func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		if err := concurrent.SaveLKG(intermediate); err != nil {
			t.Fatal(err)
		}
		reserved, err = concurrent.ReserveReportSequence()
		if err != nil {
			t.Fatal(err)
		}
		return next, nil
	}
	if changed, err := refreshWindowsCertifiedView(context.Background(), store, fetch); err != nil || changed {
		t.Fatalf("same execution inputs changed or failed: %v", err)
	}
	if !reflect.DeepEqual(store.LKG(), &next) {
		t.Fatal("concurrent accepted progress discarded the newer authenticated response")
	}
	if nextSequence, err := store.ReserveReportSequence(); err != nil || nextSequence <= reserved {
		t.Fatal("configuration acceptance rolled back a report reservation", err)
	}
}

func TestWindowsFailedFetchStillReportsConcurrentlyAcceptedRevocation(t *testing.T) {
	root := t.TempDir()
	protector := clientsecret.MachineProtector{}
	invite, envelope := windowsFixture(t)
	path := windowsProfileStatePath(root)
	store, err := deviceclient.OpenProtected(path, invite, protector)
	if err != nil {
		t.Fatal(err)
	}
	before := envelope(store.PublicKey(), 7)
	if err := store.SaveLKG(before); err != nil {
		t.Fatal(err)
	}
	concurrent, err := deviceclient.LoadProtected(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	revoked := envelope(store.PublicKey(), 8, func(view *control.DeviceView) {
		view.PolicyIDs = []string{}
		view.Policies = []control.NetworkPolicy{}
		view.Services = []control.Service{}
	})
	fetch := func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
		if err := concurrent.SaveLKG(revoked); err != nil {
			t.Fatal(err)
		}
		return control.DeviceViewEnvelope{}, errors.New("demo private request failed after concurrent revocation")
	}
	changed, err := refreshWindowsCertifiedView(context.Background(), store, fetch)
	if err != nil || !changed {
		t.Fatalf("network failure hid accepted revocation from runtime cancellation: %v", err)
	}
	if !reflect.DeepEqual(store.LKG(), &revoked) {
		t.Fatal("failed request replaced the concurrently accepted revocation")
	}
	if err := store.SaveLKG(before); err == nil {
		t.Fatal("failed request allowed the pre-revocation floor")
	}
}
