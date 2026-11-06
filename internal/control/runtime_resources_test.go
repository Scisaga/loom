package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func hy2ProjectionFixture(t *testing.T) Projection {
	t.Helper()
	_, _, projection := deviceContractFixture(t)
	root := sha256.Sum256([]byte("demo-service-credential-root"))
	projection.DeviceAuthorizations[0].RuntimeKey = base64.RawURLEncoding.EncodeToString(root[:])
	owner := projection.DeviceAuthorizations[0]
	owner.ID, owner.Name = "demo-exit", "Demo exit"
	owner.Responsibilities, owner.PolicyIDs = []string{"internet_egress"}, []string{}
	projection.DeviceAuthorizations = append(projection.DeviceAuthorizations, owner)
	ca := testTransportCA(t, t.TempDir())
	certificates := []string{base64.RawURLEncoding.EncodeToString(ca.certificate.Raw)}
	name := "demo.example"
	projection.NetworkIntent.Resources = []TransportResource{{ID: "demo-hy2", Kind: "hysteria2", OwnerNodeID: owner.ID, ListenerID: "demo-listener", DialHost: "192.0.2.10", DialPort: 443,
		Authentication: ResourceAuthentication{ServerName: &name, CACertificates: &certificates}}}
	policy := &projection.NetworkIntent.Policies[0]
	policy.AllowDirect = new(false)
	policy.EntryScope = PolicyScope{Mode: "only", NodeIDs: []string{owner.ID}}
	policy.ExitScope = new(PolicyScope{Mode: "only", NodeIDs: []string{owner.ID}})
	registerTestWireGuardIdentities(t, &projection)
	return projection
}

func TestHy2ResourceTrustHasOneCanonicalShape(t *testing.T) {
	projection := hy2ProjectionFixture(t)
	resource := projection.NetworkIntent.Resources[0]
	body, err := CanonicalEncode(resource)
	var decoded TransportResource
	if err != nil || DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 20, MaxItems: 1000}) != nil || !reflect.DeepEqual(decoded, resource) {
		t.Fatal("Hy2 public trust did not round trip", err)
	}
	for name, change := range map[string]func(*TransportResource){
		"missing trust": func(r *TransportResource) { r.Authentication.CACertificates = nil },
		"empty trust":   func(r *TransportResource) { values := []string{}; r.Authentication.CACertificates = &values },
		"duplicate CA": func(r *TransportResource) {
			values := append([]string{}, (*r.Authentication.CACertificates)[0], (*r.Authentication.CACertificates)[0])
			r.Authentication.CACertificates = &values
		},
		"non-certificate": func(r *TransportResource) { values := []string{"ZGVtbw"}; r.Authentication.CACertificates = &values },
		"missing name":    func(r *TransportResource) { r.Authentication.ServerName = nil },
		"extra pin": func(r *TransportResource) {
			pin := "sha256:" + strings.Repeat("a", 64)
			r.Authentication.SPKISHA256 = &pin
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := resource
			change(&bad)
			if _, err := CanonicalEncode(bad); err == nil {
				t.Fatal("accepted an incomplete or alternative Hy2 trust shape")
			}
		})
	}
}

func TestHy2OneHopSharesCredentialsWithoutSharingAccessAssignment(t *testing.T) {
	projection := hy2ProjectionFixture(t)
	access, err := ProjectDeviceView(projection, "demo-access")
	if err != nil || len(testDeviceExecution(access).Routes) != 1 || len(access.TransportCredentials) != 1 {
		t.Fatal("one-hop access projection failed", err)
	}
	route := testDeviceExecution(access).Routes[0]
	if route.FinalExit != "demo-exit" || route.FirstResourceID != "demo-hy2" || route.EntryNodeID != "demo-exit" {
		t.Fatal("one-hop candidate lost resource or exit identity")
	}
	receiver, err := ProjectDeviceView(projection, "demo-exit")
	if err != nil || len(receiver.TransportCredentials) != 1 || len(receiver.PolicyIDs) != 0 || testDeviceExecution(receiver).RuntimeProfile == nil || len(receiver.Policies) != 1 {
		t.Fatal("receiver borrowed the source access assignment", err)
	}
	passwords, err := executionCredentials(access)
	if err != nil || passwords[route.FirstResourceID] != receiver.TransportCredentials[0].Credential {
		t.Fatal("access and receiver did not consume the same derived credential")
	}
	for _, view := range []DeviceView{access, receiver} {
		body, err := CanonicalEncode(view)
		var decoded DeviceView
		if err != nil || DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) != nil || !reflect.DeepEqual(view, decoded) {
			t.Fatal("Hy2 View failed canonical recovery", err)
		}
		if bytes.Contains(body, []byte(projection.DeviceAuthorizations[0].RuntimeKey)) {
			t.Fatal("View leaked the source RuntimeKey")
		}
	}
	for _, change := range []func(*Projection){
		func(p *Projection) { p.DeviceAuthorizations[0].PolicyIDs = []string{} },
		func(p *Projection) { p.NetworkIntent.Policies[0].Action = "deny" },
		func(p *Projection) { p.NetworkIntent.Resources = []TransportResource{} },
		func(p *Projection) { p.DeviceAuthorizations[1].Responsibilities = []string{"forward"} },
	} {
		p := hy2ProjectionFixture(t)
		change(&p)
		for _, id := range []string{"demo-access", "demo-exit"} {
			view, err := ProjectDeviceView(p, id)
			if err != nil || len(testDeviceExecution(view).Routes) != 0 || len(view.TransportCredentials) != 0 {
				t.Fatal("withdrawal retained a remote route or receiver credential", err)
			}
		}
	}
}

func TestHy2ReceiverUsesCurrentServiceRestrictionAndRejectsOldACLReport(t *testing.T) {
	p := hy2ProjectionFixture(t)
	p.NetworkIntent.Services[0].RestrictToProbeTargets = new(true)
	p.NetworkIntent.Services[0].ProbeURLs = []string{"https://demo-limited.example:8443/health"}
	other := Service{ID: "demo-z-service", Name: "Demo denied", Kind: "internet", RestrictToProbeTargets: new(false)}
	policy := materialTestPolicy("demo-z-policy", other.ID)
	policy.Action = "deny"
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, other)
	p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, policy)
	p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, policy.ID)
	// A denied alternative does not change the current Service targets.
	access, err := ProjectDeviceView(p, "demo-access")
	if err != nil || len(testDeviceExecution(access).BusinessProbeTargets) != 1 || len(testDeviceExecution(access).BusinessProbeTargets[0].Targets) != 1 {
		t.Fatal("current Service restriction did not survive projection", err)
	}
	receiver, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(receiver.TransportCredentials) != 1 || !reflect.DeepEqual(receiver.Services[0].TargetMatchers(receiver.DNSRecords...), []ServiceMatcher{{Kind: "dns_exact", Value: "demo-limited.example", Port: 8443}}) {
		t.Fatal("receiver changed the current Service permission because of an alternative", err)
	}
	digest, _ := DeviceViewDigest(receiver)
	acl, _ := InboundACLDigest(receiver, "demo-hy2")
	values := []ResourceReadback{{ResourceID: "demo-hy2", ListenerID: "demo-listener", Listen: "192.0.2.10:443", CertificateDigest: "sha256:" + strings.Repeat("a", 64), ACLDigest: acl}}
	report := DeviceReport{ViewDigest: digest, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest, Resources: &values}}
	if err := verifyReportViewFields(report, receiver); err != nil {
		t.Fatal(err)
	}
	values[0].ACLDigest = "sha256:" + strings.Repeat("f", 64)
	if verifyReportViewFields(report, receiver) == nil {
		t.Fatal("a previous loaded ACL was accepted as the current receiver execution")
	}
}
