//go:build windows

package main

import (
	"context"
	"testing"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/clientsecret"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

func TestWindowsPolicyApplyFailureStopsRuntimeWhenRejectionCannotBeVerified(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := &portableGUI{edition: editionPortableMixed, root: t.TempDir(), ctx: ctx, state: guiConnected, joined: true, runCancel: cancel}
	invite, makeView := windowsFixture(t)
	path := windowsProfileStatePath(app.root)
	store, err := deviceclient.OpenProtected(path, invite, clientsecret.UserProtector{})
	if err != nil {
		t.Fatal(err)
	}
	view := makeView(store.PublicKey(), 7, func(view *control.DeviceView) {
		other := view.Policies[0]
		other.ID = "demo-policy-other"
		view.Policies = append(view.Policies, other)
		view.PolicyIDs = append(view.PolicyIDs, other.ID)
	})
	if err := store.SaveLKG(view); err != nil {
		t.Fatal(err)
	}
	preference, err := clientmodel.ChoosePolicy(store.Preference(), view.View, "demo-service", "demo-policy")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.setRoutePreference(preference); err == nil || ctx.Err() == nil {
		t.Fatal("unverified selector rejection left the runtime serving")
	}
	reopened, err := deviceclient.LoadProtected(path, clientsecret.UserProtector{})
	if err != nil || !reopened.Preference().Equal(preference) || reopened.PublicKey() != store.PublicKey() {
		t.Fatal("failed application lost the saved choice or identity", err)
	}
}

func TestWindowsReportedPreferenceComesFromReopenedDPAPISettings(t *testing.T) {
	for _, edition := range []clientEdition{editionPortableMixed, editionPortableTUN, editionInstalled} {
		t.Run(string(edition), func(t *testing.T) {
			app := &portableGUI{edition: edition, root: t.TempDir(), ctx: context.Background(), state: guiStopped, joined: true, routeSelected: -1}
			var protector clientsecret.Protector = clientsecret.UserProtector{}
			if edition == editionInstalled {
				protector = clientsecret.MachineProtector{}
			}
			invite, makeView := windowsFixture(t)
			path := windowsProfileStatePath(app.root)
			store, err := deviceclient.OpenProtected(path, invite, protector)
			if err != nil {
				t.Fatal(err)
			}
			view := makeView(store.PublicKey(), 7, func(view *control.DeviceView) {
				view.Responsibilities = []string{"access", "internet_egress"}
				view.Policies[0].LocalEgressDevices = new([]string{view.DeviceID})
				second := view.Policies[0]
				second.ID = "demo-policy-other"
				view.Policies = append(view.Policies, second)
				view.PolicyIDs = append(view.PolicyIDs, second.ID)
			})
			if err := store.SaveLKG(view); err != nil {
				t.Fatal(err)
			}
			var actual control.RouteCandidate
			for _, route := range view.View.Routes {
				if route.FinalExit == "direct" {
					actual = route
				}
			}
			if actual.ID == "" {
				t.Fatal("demo Direct readback missing")
			}
			for _, policy := range view.View.Policies {
				preference, err := clientmodel.ChoosePolicy(clientmodel.EmptyPreference(), view.View, policy.ServiceID, policy.ID)
				if err != nil {
					t.Fatal(err)
				}
				// This is the same write operation used by the native GUI/broker.
				// No transport is launched: this test covers saved settings/readback.
				if err := app.setRoutePreference(preference); err != nil {
					t.Fatal(err)
				}
				reopened, err := deviceclient.LoadProtected(path, protector)
				if err != nil || reopened.PublicKey() != store.PublicKey() || !reopened.Preference().Equal(preference) {
					t.Fatal("native preference write lost its original DPAPI identity", err)
				}
				activation := clientadapter.Activation{State: clientadapter.State{Preference: reopened.Preference(), NetworkGeneration: "demo-underlay"}, Selections: []clientadapter.SelectionStatus{{Scope: actual.Scope, CandidateID: actual.ID}}}
				report, err := windowsDeviceReport(reopened.LKG(), activation, nil, time.Now())
				if err != nil || report.PolicyChoices == nil || report.Preference != nil || (*report.PolicyChoices)[0].PolicyID != policy.ID || report.Selections[0].CandidateID != actual.ID {
					t.Fatal("native report replaced the setting with the actual selector", err)
				}
				sequence, err := reopened.ReserveReportSequence()
				if err != nil {
					t.Fatal(err)
				}
				report.Schema, report.NetworkID, report.DeviceID, report.ReportSequence = 3, view.NetworkID, view.View.DeviceID, sequence
				report, err = control.SignDeviceReport(report, reopened.PrivateKey())
				if err != nil || report.Verify(reopened.PublicKey()) != nil {
					t.Fatal("native signed preference did not verify", err)
				}
			}
		})
	}
}
