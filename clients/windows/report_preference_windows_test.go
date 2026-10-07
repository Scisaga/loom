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
				view.Policies[0].LocalEgressDevices = []string{view.DeviceID}
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
			for _, preference := range []clientmodel.Preference{{Schema: 3, Mode: clientmodel.ModeAuto}, {Schema: 3, Mode: clientmodel.ModeDirect}, {Schema: 3, Mode: clientmodel.ModeFixed, Exit: view.View.DeviceID}} {
				// This is the same write operation used by the native GUI/broker.
				// No transport is launched: this test covers saved settings/readback.
				if err := app.setRoutePreference(preference); err != nil {
					t.Fatal(err)
				}
				reopened, err := deviceclient.LoadProtected(path, protector)
				if err != nil || reopened.PublicKey() != store.PublicKey() || reopened.Preference() != preference {
					t.Fatal("native preference write lost its original DPAPI identity", err)
				}
				activation := clientadapter.Activation{State: clientadapter.State{Preference: reopened.Preference(), NetworkGeneration: "demo-underlay"}, Selections: []clientadapter.SelectionStatus{{Scope: actual.Scope, CandidateID: actual.ID}}}
				report, err := windowsDeviceReport(reopened.LKG(), activation, nil, time.Now())
				if err != nil || report.Preference == nil || report.Preference.Mode != string(preference.Mode) || report.Preference.Exit != preference.Exit || report.Selections[0].CandidateID != actual.ID {
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
