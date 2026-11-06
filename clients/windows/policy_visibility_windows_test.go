//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestWindowsRouteVisibilityPreservesLatestChoiceAndExpiresWithoutNewSamples(t *testing.T) {
	_, envelope := windowsFixture(t)
	view := envelope(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), 7, func(view *control.DeviceView) {
		other := view.Policies[0]
		other.ID = "demo-policy-other"
		ungranted := other
		ungranted.ID = "demo-policy-ungranted"
		view.Policies = append(view.Policies, other, ungranted)
		view.PolicyIDs = append(view.PolicyIDs, other.ID)
	}).View
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	until := at.Add(30 * time.Second).UnixMilli()
	hidden := map[string]int64{"demo-policy": until, "demo-policy-other": until}
	for _, selected := range []string{"demo-policy", "demo-policy-other"} {
		options, err := windowsRouteOptions(view, clientmodel.Preference{Schema: 3, PolicyID: selected}, hidden, at)
		if err != nil || len(options) != 1 || options[0].PolicyID != selected {
			t.Fatal("cached failure hid the latest legal selection or exposed an ungranted Policy", err)
		}
	}
	for _, cache := range []map[string]int64{nil, hidden} {
		options, err := windowsRouteOptions(view, clientmodel.Preference{Schema: 3, PolicyID: "demo-policy"}, cache, time.UnixMilli(until))
		if err != nil || len(options) != 2 {
			t.Fatal("offline/expired cache did not restore authorized options", err)
		}
	}
	app := &portableGUI{runCancel: func() {}, routeHidden: hidden, routeHiddenViewDigest: "demo-old-view"}
	if app.routeHiddenForView("demo-new-view") != nil || len(app.routeHidden) != 0 {
		t.Fatal("View change retained stale visibility evidence")
	}
}
