package control

import "testing"

func TestCandidateDiagnosticsAndCredentialsDoNotBorrowAnotherServicesDenial(t *testing.T) {
	p := hy2ProjectionFixture(t)
	other := Service{ID: "demo-other", Name: "Demo other", Kind: "internet", ProbeURLs: []string{"https://demo-other.example/"}, RestrictToProbeTargets: new(true)}
	policy := p.NetworkIntent.Policies[0]
	policy.ID = "demo-denied-policy"
	policy.ServiceID = other.ID
	policy.Action = "deny"
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, other)
	p.NetworkIntent.Policies = append([]NetworkPolicy{policy}, p.NetworkIntent.Policies...)
	p.DeviceAuthorizations[0].PolicyIDs = append([]string{policy.ID}, p.DeviceAuthorizations[0].PolicyIDs...)
	for _, id := range []string{"demo-access", "demo-exit"} {
		view, err := ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range testDeviceExecution(view).Routes {
			if route.PolicyID == policy.ID {
				t.Fatal("denied alternative became an executable candidate")
			}
		}

	}
}
