package control

import (
	"bytes"
	"reflect"
	"testing"
)

func TestServiceProbeConfigurationIsTheOnlyCurrentInternetDefinition(t *testing.T) {
	service := Service{ID: "demo-service", Name: "Demo service", Kind: "internet", RestrictToProbeTargets: new(false)}
	before, err := CanonicalEncode(service)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != `{"id":"demo-service","kind":"internet","name":"Demo service","restrict_to_probe_targets":false}` {
		t.Fatal("unexpected current Service wire", string(before))
	}
	service.ProbeURLs = []string{"https://demo.example/check?kind=health", "https://demo.example:8443/health"}
	if err := service.ValidateCurrent(); err != nil {
		t.Fatal(err)
	}
	if !targetMatchesService("https://other.example/application-dependency", service) {
		t.Fatal("optional measurement samples restricted ordinary Internet")
	}
	body, err := CanonicalEncode(service)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Service
	if err := DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}); err != nil || !reflect.DeepEqual(decoded, service) {
		t.Fatal("current Service did not round trip", err)
	}
	service.RestrictToProbeTargets = new(true)
	for _, target := range []string{"https://demo.example/other-path", "https://demo.example:8443/application"} {
		if !targetMatchesService(target, service) {
			t.Fatal("allowed host and port rejected", target)
		}
	}
	for _, target := range []string{"https://api.demo.example/", "https://other.example/", "https://demo.example:9443/"} {
		if targetMatchesService(target, service) {
			t.Fatal("restriction ignored exact host or port", target)
		}
	}
	permission := executionService(service)
	service.ProbeURLs = []string{"https://demo.example/different", "https://demo.example:8443/different?query=changed"}
	if !reflect.DeepEqual(permission, executionService(service)) {
		t.Fatal("only changing URL paths changed permissions or credentials")
	}
	for _, urls := range [][]string{nil, {}, {"https://127.0.0.1/"}, {"https://control.loom/"}, {"https://demo.example/", "https://demo.example/"}} {
		service.ProbeURLs = urls
		if service.ValidateCurrent() == nil {
			t.Fatal("accepted invalid restricted targets", urls)
		}
	}
}

func TestHistoricalServiceBytesRemainEvidenceAndCannotBeSignedOrExecuted(t *testing.T) {
	service := Service{ID: "demo-service", Name: "Demo service", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "dns_suffix", Value: "demo.example"}}}
	original := []byte(`{"id":"demo-service","kind":"internet","matchers":[{"kind":"dns_suffix","value":"demo.example"}],"name":"Demo service"}`)
	body, err := CanonicalEncode(service)
	if err != nil || !bytes.Equal(body, original) {
		t.Fatal("historical bytes changed", err)
	}
	if validateCurrentTransportPayload(service) == nil || service.ValidateCurrent() == nil || len(service.TargetMatchers()) != 0 {
		t.Fatal("legacy destinations remained a current writer or runtime source")
	}
	projection := hy2ProjectionFixture(t)
	projection.NetworkIntent.Services[0] = service
	if _, err := ProjectDeviceView(projection, "demo-access"); err == nil {
		t.Fatal("silently reprojected a historical Service at the same authenticated frontier")
	}
}

func TestOrdinaryInternetIsSeparateFromLANAndRestrictionCannotExpandIt(t *testing.T) {
	service := Service{ID: "demo-internet", Name: "Demo internet", Kind: "internet", RestrictToProbeTargets: new(false)}
	for _, restricted := range []bool{false, true} {
		service.RestrictToProbeTargets = new(restricted)
		service.ProbeURLs = []string{"https://demo.example/health"}
		for _, target := range []string{"https://control.loom/", "https://demo.local/", "https://127.0.0.1/", "https://10.0.0.1/", "https://[::1]/"} {
			if targetMatchesService(target, service) {
				t.Fatal("internet granted a local scope", target)
			}
		}
	}
	service.Matchers = []ServiceMatcher{{Kind: "dns_exact", Value: "demo.example"}}
	if service.ValidateCurrent() == nil {
		t.Fatal("accepted a second editable destinations source")
	}
}

func TestHistoricalProbePoolCannotBeSilentlyReprojected(t *testing.T) {
	_, _, projection := deviceContractFixture(t)
	projection.NetworkIntent.BusinessProbeTargets = []BusinessProbeTarget{{ID: "demo-historical-probe", URL: "https://demo-service.example/health"}}
	if _, err := ProjectDeviceView(projection, "demo-access"); err == nil {
		t.Fatal("rewrote an old frontier without retiring its historical pool")
	}
}
