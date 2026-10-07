package clientadapter

import (
	"testing"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestReportedPreferenceRequiresRealLocalInputOnlyForAccess(t *testing.T) {
	view := control.DeviceView{Responsibilities: []string{"control"}}
	if value, err := ReportedPreference(view, clientmodel.Preference{}); err != nil || value != nil {
		t.Fatal("pure control acquired an access preference", err)
	}
	view.Responsibilities = []string{"access"}
	if _, err := ReportedPreference(view, clientmodel.Preference{}); err == nil {
		t.Fatal("missing local setting manufactured Auto")
	}
	pref := clientmodel.Preference{Schema: 3, Mode: clientmodel.ModeFixed, Exit: "demo-removed-exit"}
	value, err := ReportedPreference(view, pref)
	if err != nil || value.Mode != "fixed_exit" || value.Exit != pref.Exit {
		t.Fatal("revoked candidate availability erased local intent", err)
	}
}
