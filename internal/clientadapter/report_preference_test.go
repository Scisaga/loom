package clientadapter

import (
	"testing"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestReportedPreferenceRequiresRealLocalInputOnlyForAccess(t *testing.T) {
	view := control.DeviceView{Responsibilities: []string{"control"}}
	if value, err := ReportedPolicyChoices(view, clientmodel.Preference{}); err != nil || value != nil {
		t.Fatal("pure control acquired an access preference", err)
	}
	view.Responsibilities = []string{"access"}
	if _, err := ReportedPolicyChoices(view, clientmodel.Preference{}); err == nil {
		t.Fatal("missing local setting manufactured Auto")
	}
	pref := clientmodel.Preference{Schema: 3, Services: []clientmodel.ServicePreference{{ServiceID: "demo-service", PolicyID: "demo-policy"}}}
	value, err := ReportedPolicyChoices(view, pref)
	if err != nil || value == nil || len(*value) != 1 || (*value)[0].PolicyID != "demo-policy" {
		t.Fatal("revoked candidate availability erased local intent", err)
	}
}
