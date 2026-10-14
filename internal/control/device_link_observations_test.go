package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestScopedLinkDeliveryVerifiesOriginalReportAndCurrentExecution(t *testing.T) {
	p := relayProjectionFixture(t)
	key := testKey(t)
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" {
			p.DeviceAuthorizations[i].DevicePublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		}
	}
	viewFor := func(id string) (DeviceView, error) { return ProjectDeviceView(p, id) }
	source, err := viewFor("demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := viewFor("demo-access")
	if err != nil {
		t.Fatal(err)
	}
	link := testDerivedLink(t, p, "demo-entry", "demo-exit")
	spec, _ := LinkSpecDigest(source, link.ID)
	digest, _ := DeviceViewDigest(source)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	sample := Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_dns", NetworkGeneration: "demo-source-underlay", Result: "unavailable", ObservedAt: now.Add(-time.Second).UnixMilli(), ValidUntil: now.Add(29 * time.Second).UnixMilli()}
	resources := []ResourceReadback{}
	for _, resource := range source.Resources {
		if resource.OwnerNodeID != source.DeviceID {
			continue
		}
		acl, _ := InboundACLDigest(source, resource.ID)
		value := ResourceReadback{ResourceID: resource.ID, ListenerID: resource.ListenerID, Listen: net.JoinHostPort(resource.DialHost, strconv.Itoa(resource.DialPort)), ACLDigest: acl, CertificateDigest: ReleaseDigest([]byte("demo-certificate"))}
		if resource.Kind == "wireguard" {
			value.CertificateDigest = ""
			value.PublicKey = *resource.Authentication.PublicKey
		}
		resources = append(resources, value)
	}
	base := DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: source.DeviceID, ReportSequence: 7, ViewDigest: digest, NetworkGeneration: sample.NetworkGeneration, ReportedAt: now.UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{sample}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest, Resources: &resources}, Components: []ComponentReadback{}}
	signed, err := SignDeviceReport(base, key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := projectDeviceLinkObservations(p, recipient, []DeviceReport{signed}, now, viewFor)
	if err != nil || len(result.Observations) != 1 || !reflect.DeepEqual(result.Observations[0].Observation, sample) {
		t.Fatal("current signed original was not delivered", err, result)
	}
	body, err := CanonicalEncode(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DeviceLinkObservations
	if DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}) != nil || !reflect.DeepEqual(decoded, result) {
		t.Fatal("delivery did not canonically round trip")
	}
	for _, tc := range []struct {
		name   string
		change func(*DeviceReport)
		at     time.Time
	}{
		{"signature", func(r *DeviceReport) { r.Signature = "demo-invalid" }, now},
		{"unapplied runtime", func(r *DeviceReport) { r.Runtime.AppliedViewDigest = ReleaseDigest([]byte("demo-other")) }, now},
		{"stopped", func(r *DeviceReport) {
			r.Runtime.State = "stopped"
			r.Runtime.AppliedViewDigest = ""
			r.Runtime.Resources = nil
		}, now},
		{"source generation", func(r *DeviceReport) { r.NetworkGeneration = "demo-other-underlay" }, now},
		{"spec", func(r *DeviceReport) { r.Observations[0].SpecDigest = ReleaseDigest([]byte("demo-other")) }, now},
		{"expired", func(*DeviceReport) {}, now.Add(30 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Observations = append([]Observation{}, base.Observations...)
			tc.change(&r)
			if tc.name != "signature" && tc.name != "source generation" {
				r, err = SignDeviceReport(r, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := projectDeviceLinkObservations(p, recipient, []DeviceReport{r}, tc.at, viewFor)
			if err != nil || len(got.Observations) != 0 {
				t.Fatal("invalid execution sample delivered", err, got)
			}
		})
	}
	copy := recipient
	copy.Links = []NetworkLink{}
	if result.ValidateForView(copy) == nil {
		t.Fatal("recipient scope withdrawal was ignored")
	}
}

func TestDeviceLinkObservationEndpointRequiresCurrentAuthenticatedView(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("join failed")
	}
	envelope, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	request := DeviceLinkObservationRequest{Schema: 3, ViewDigest: envelope.ViewDigest}
	identity := tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}
	response := enrollmentHTTP(t, server, "/device/link-observations", request, identity)
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	var result DeviceLinkObservations
	if DecodeCanonical(response.Body.Bytes(), &result, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}) != nil || result.ValidateForView(envelope.View) != nil || len(result.Observations) != 0 {
		t.Fatal("empty current scope is invalid")
	}
	if enrollmentHTTP(t, server, "/device/link-observations", request, enrollmentTunnel(invite)).Code != http.StatusForbidden {
		t.Fatal("bootstrap could read observations")
	}
	request.ViewDigest = ReleaseDigest([]byte("demo-old-view"))
	if enrollmentHTTP(t, server, "/device/link-observations", request, identity).Code != http.StatusConflict {
		t.Fatal("stale View could read observations")
	}
}
