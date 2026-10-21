package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestEmptyLinkScopeDoesNotReadUnrelatedReportOriginals(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("join failed", response.Code)
	}
	envelope, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || len(envelope.View.Links) != 0 {
		t.Fatal("fixture must have an empty relay source scope", err)
	}
	root := server.Runtime.Authority.root
	if err := server.Runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server.Runtime = runtime
	// Corrupt only a test-owned unrelated original. An all-owner read would
	// fail, but this recipient has no reason to consume that owner's history.
	raw := []byte("demo-corrupt-unrelated-original")
	ref := reportReference{NetworkID: envelope.NetworkID, DeviceID: "demo-unrelated", ReportSequence: 1}
	err = server.Runtime.Reports.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		return tx.Bucket(observationBucket).Put(ref.key(ReleaseDigest(raw)), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Runtime.Reports.Latest(context.Background()); err == nil {
		t.Fatal("fixture did not exercise an unrelated failed read")
	}
	response := enrollmentHTTP(t, server, "/device/link-observations", DeviceLinkObservationRequest{Schema: 3, ViewDigest: envelope.ViewDigest}, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID})
	if response.Code != http.StatusOK {
		t.Fatal("empty recipient scope consumed an unrelated report", response.Code, response.Body.String())
	}
	var result DeviceLinkObservations
	if err := DecodeCanonical(response.Body.Bytes(), &result, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}); err != nil || result.ValidateForView(envelope.View) != nil || len(result.Observations) != 0 {
		t.Fatal("empty current scope did not return its canonical empty projection", err)
	}
	cache := &runtime.Authority.deviceConfigs
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.items) == 0 {
		t.Fatal("cold Link delivery did not retain its current view")
	}
	for _, item := range cache.items {
		if len(item.Value.(*deviceConfigEntry).value.body) != 0 {
			t.Fatal("reading Link observations unnecessarily signed a configuration")
		}
	}
}

func TestScopedLinkDeliveryVerifiesOriginalReportAndCurrentExecution(t *testing.T) {
	p := relayProjectionFixture(t)
	key := testKey(t)
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" {
			p.DeviceAuthorizations[i].DevicePublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		}
	}
	calls := map[string]int{}
	viewFor := deviceLinkViewFor(func(id string) (DeviceView, error) {
		calls[id]++
		return ProjectDeviceView(p, id)
	})
	source, digest, err := viewFor("demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	recipient, recipientDigest, err := viewFor("demo-access")
	if err != nil {
		t.Fatal(err)
	}
	link := testDerivedLink(t, p, "demo-entry", "demo-exit")
	spec, _ := LinkSpecDigest(source, link.ID)
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
	result, err := projectDeviceLinkObservations(p, recipient.DeviceID, recipientDigest, []DeviceReport{signed}, now, viewFor)
	if err != nil || len(result.Observations) != 1 || !reflect.DeepEqual(result.Observations[0].Observation, sample) {
		t.Fatal("current signed original was not delivered", err, result)
	}
	if calls[source.DeviceID] != 1 || calls[recipient.DeviceID] != 1 {
		t.Fatal("recipient and report checks rebuilt a View in the same request", calls)
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
		{"stale view", func(r *DeviceReport) { r.ViewDigest = ReleaseDigest([]byte("demo-old-view")) }, now},
		{"other network", func(r *DeviceReport) { r.NetworkID = "demo-other-network" }, now},
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
			got, err := projectDeviceLinkObservations(p, recipient.DeviceID, recipientDigest, []DeviceReport{r}, tc.at, viewFor)
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
	copy = recipient
	copy.Schema = 0
	if result.ValidateForView(copy) == nil {
		t.Fatal("public validation trusted a previously matching digest for an invalid View")
	}
}

func TestDeviceLinkViewReuseIsRequestLocalAndRejectsFailedProjections(t *testing.T) {
	p := relayProjectionFixture(t)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	calls := map[string]int{}
	viewFor := deviceLinkViewFor(func(id string) (DeviceView, error) {
		calls[id]++
		return ProjectDeviceView(p, id)
	})
	view, digest, err := viewFor("demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	again, againDigest, err := viewFor("demo-entry")
	if err != nil || digest != againDigest || !reflect.DeepEqual(view, again) || calls["demo-entry"] != 1 {
		t.Fatal("one request rebuilt the same successful View or changed its digest", err, calls)
	}
	if _, _, err := viewFor("demo-exit"); err != nil || calls["demo-exit"] != 1 {
		t.Fatal("another source did not keep its own projection", err, calls)
	}
	for _, recipient := range []string{view.DeviceID, "demo-exit"} {
		wrong := ReleaseDigest([]byte("demo-wrong-view"))
		if recipient != view.DeviceID {
			wrong = digest
		}
		if _, err := projectDeviceLinkObservations(p, recipient, wrong, nil, now, viewFor); err == nil {
			t.Fatal("private projection accepted a digest paired with another recipient View")
		}
	}
	changed := cloneAuthorityProjection(p)
	for i := range changed.DeviceAuthorizations {
		if changed.DeviceAuthorizations[i].ID == view.DeviceID {
			changed.DeviceAuthorizations[i].Name = "Demo renamed entry"
		}
	}
	next := deviceLinkViewFor(func(id string) (DeviceView, error) { return ProjectDeviceView(changed, id) })
	_, nextDigest, err := next(view.DeviceID)
	if err != nil || nextDigest == digest {
		t.Fatal("a later request reused an earlier authorization projection", err)
	}
	if _, err := projectDeviceLinkObservations(changed, view.DeviceID, digest, nil, now, next); err == nil {
		t.Fatal("private projection paired an earlier digest with a changed authorization View")
	}
	for _, mode := range []string{"projection error", "invalid View", "another device"} {
		t.Run(mode, func(t *testing.T) {
			attempts := 0
			read := deviceLinkViewFor(func(string) (DeviceView, error) {
				attempts++
				if attempts < 3 {
					if mode == "projection error" {
						return DeviceView{}, errors.New("demo unavailable projection")
					}
					if mode == "another device" {
						return ProjectDeviceView(p, "demo-exit")
					}
					invalid := view
					invalid.Schema = 0
					return invalid, nil
				}
				return view, nil
			})
			for range 2 {
				if _, _, err := read(view.DeviceID); err == nil {
					t.Fatal("failed projection or invalid View was accepted")
				}
			}
			if _, got, err := read(view.DeviceID); err != nil || got != digest || attempts != 3 {
				t.Fatal("failed projection was cached or recovery changed its canonical digest", err, attempts)
			}
		})
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
	projection := server.Runtime.Authority.Snapshot()
	policy := projection.NetworkIntent.Policies[0]
	policy.AllowDirect = new(false)
	policy.EntryScope = PolicyScope{Mode: "none", NodeIDs: []string{}}
	target, _ := projection.CurrentTarget("policy", policy.ID)
	service, _ := projection.CurrentTarget("service", policy.ServiceID)
	dependencies := sortedUniqueDependencies(append(append([]string{}, target.MaterialIDs...), service.MaterialIDs...))
	operation := Operation{Schema: 3, RequestID: "demo-link-withdraw-policy", Operation: "policy.put", TargetKind: "policy", TargetID: policy.ID, Dependencies: dependencies, Payload: policy}
	if response := localNetworkAdminHTTP(t, server, "/api/control/operations", operation); response.Code != http.StatusOK {
		t.Fatal("policy update failed", response.Code)
	}
	request.ViewDigest = envelope.ViewDigest
	if enrollmentHTTP(t, server, "/device/link-observations", request, identity).Code != http.StatusConflict {
		t.Fatal("the next request retained the previous authorization digest")
	}
	next, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || next.ViewDigest == envelope.ViewDigest {
		t.Fatal("changed authorization did not produce a new View", err)
	}
	request.ViewDigest = next.ViewDigest
	response = enrollmentHTTP(t, server, "/device/link-observations", request, identity)
	if response.Code != http.StatusOK {
		t.Fatal("new current View could not read observations", response.Code)
	}
	if DecodeCanonical(response.Body.Bytes(), &result, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}) != nil || result.ValidateForView(next.View) != nil || result.ValidateForView(envelope.View) == nil {
		t.Fatal("request-local reuse returned another request's recipient scope")
	}
}
