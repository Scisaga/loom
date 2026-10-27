package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestInviteDeliversDNSInTheFirstAuthenticatedView(t *testing.T) {
	servers := []string{"192.0.2.53"}
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t, func(invite *Invite) { invite.DNSServers = servers })
	response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite))
	if response.Code != http.StatusOK {
		t.Fatal("claim failed")
	}
	var joined EnrollmentResponse
	if err := DecodeCanonical(response.Body.Bytes(), &joined, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if joined.DeviceView == nil || !reflect.DeepEqual(joined.DeviceView.View.DNSServers, servers) {
		t.Fatal("first join lost invited DNS")
	}
}

func TestDoHInviteAndDeviceUpdatePreserveIdentityAndCanonicalState(t *testing.T) {
	servers := []string{"https://192.0.2.53/dns-query", "https://[2001:db8::53]/dns-query"}
	server, invite, _, claim, _, dependencies := enrollmentAuthorityFixture(t, func(v *Invite) { v.DNSServers = servers })
	response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite))
	if response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	original := server.Runtime.Authority.Snapshot().DeviceAuthorizations[0]
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || !reflect.DeepEqual(view.View.DNSServers, servers) {
		t.Fatal("initial DoH configuration missing", err)
	}
	body, err := CanonicalEncode(view)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DeviceViewEnvelope
	if err := DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	again, _ := CanonicalEncode(decoded)
	if !bytes.Equal(body, again) {
		t.Fatal("DoH signed bytes changed")
	}
	current, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	nextDNS := []string{"https://192.0.2.54:8443/dns-query"}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-encrypted-update", Operation: "device.put", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: sortedUniqueDependencies(append(dependencies, current.MaterialIDs...)), Payload: DevicePut{ID: original.ID, Name: original.Name, Responsibilities: original.Responsibilities, PolicyIDs: original.PolicyIDs, DistributionURLs: original.DistributionURLs, DNSServers: nextDNS}})
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	next := reopened.Snapshot().DeviceAuthorizations[0]
	if next.RuntimeKey != original.RuntimeKey || next.DevicePublicKey != original.DevicePublicKey || next.TransactionID != original.TransactionID || !reflect.DeepEqual(next.DNSServers, nextDNS) {
		t.Fatal("DNS forward update lost identity or configuration")
	}
	for _, bad := range [][]string{{"192.0.2.53", "https://192.0.2.54/dns-query"}, {"https://demo.example/dns-query"}, {servers[0], servers[0]}} {
		next.DNSServers = bad
		if _, err := CanonicalEncode(next); err == nil {
			t.Fatal("accepted invalid resolver collection")
		}
	}
}

func TestInvitationDefaultIsDraftOnlyAndMissingRequiredDNSCannotBeSigned(t *testing.T) {
	server, invite, _, _, _, dependencies := enrollmentAuthorityFixture(t)
	recorder := httptest.NewRecorder()
	server.enrollmentOptions(recorder, httptest.NewRequest("GET", "/api/control/ui/enrollment-options", nil))
	var options struct {
		DNS []string `json:"default_dns_servers"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &options); err != nil || len(options.DNS) != 2 || validateOptionalDNS(options.DNS) != nil {
		t.Fatal("new invitation has no valid encrypted default", err)
	}
	for _, resolver := range options.DNS {
		if !strings.HasPrefix(resolver, "https://") {
			t.Fatal("unencrypted default")
		}
	}
	if invite.DNSServers != nil {
		t.Fatal("reading defaults rewrote existing invitation")
	}
	invite.ID, invite.DeviceID = "demo-new-invitation", "demo-new-access"
	invite.Endpoint.Host = "demo-entry.example"
	op := Operation{Schema: 3, RequestID: "demo-missing-resolver", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(dependencies), Payload: invite}
	body, err := EncodeOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	before := server.Runtime.Authority.Snapshot().Frontier
	if _, err := server.Runtime.Submit(t.Context(), body); err == nil || !strings.HasPrefix(err.Error(), "dns_servers:") {
		t.Fatal("missing resolver was signed", err)
	}
	if !reflect.DeepEqual(before, server.Runtime.Authority.Snapshot().Frontier) {
		t.Fatal("rejected invitation advanced signed history")
	}
}

func TestDeviceDNSManagementPersistsAndProjectsWithoutChangingIdentity(t *testing.T) {
	server, invite, _, claim, _, dependencies := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("claim failed")
	}
	original := server.Runtime.Authority.Snapshot().DeviceAuthorizations[0]
	legacy, err := CanonicalEncode(original)
	if err != nil || bytes.Contains(legacy, []byte(`"dns_servers"`)) {
		t.Fatal("unconfigured authoritative bytes changed", err)
	}
	var decoded DeviceAuthorization
	if err := DecodeCanonical(legacy, &decoded, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 16, MaxItems: 1024}); err != nil || !reflect.DeepEqual(original, decoded) {
		t.Fatal("existing identity no longer round trips", err)
	}
	current, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	servers := []string{"192.0.2.53", "2001:db8::53"}
	op := Operation{Schema: 3, RequestID: "demo-device-dns", Operation: "device.put", TargetKind: "device", TargetID: invite.DeviceID,
		Dependencies: sortedUniqueDependencies(append(dependencies, current.MaterialIDs...)), Payload: DevicePut{ID: original.ID, Name: original.Name, Responsibilities: original.Responsibilities, PolicyIDs: original.PolicyIDs, DistributionURLs: original.DistributionURLs, DNSServers: servers}}
	result := submitAuthority(t, server.Runtime, op)
	if again := submitAuthority(t, server.Runtime, op); again.MaterialID != result.MaterialID {
		t.Fatal("DNS retry signed another fact")
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	reopened, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	server.Runtime = reopened
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || !reflect.DeepEqual(view.View.DNSServers, servers) {
		t.Fatal("signed DNS projection lost after restart", err)
	}
	next := reopened.Authority.Snapshot().DeviceAuthorizations[0]
	if next.RuntimeKey != original.RuntimeKey || next.DevicePublicKey != original.DevicePublicKey {
		t.Fatal("DNS update replaced device identity")
	}
	web := projectWebDevices(reopened.Authority.Snapshot())
	found := false
	for _, device := range web {
		if device.ID == invite.DeviceID {
			found = reflect.DeepEqual(device.DNSServers, servers)
		}
	}
	if !found {
		t.Fatal("normal UI readback lost DNS")
	}
	for i, bad := range [][]string{{}, {"demo.example"}, {"192.0.2.53", "192.0.2.53"}, {"2001:db8::53", "192.0.2.53"}, {"0.0.0.0"}, {"2001:db8::1%demo"}} {
		value := op.Payload.(DevicePut)
		value.DNSServers = bad
		op.Payload = value
		if _, err := EncodeOperation(op); err == nil {
			t.Fatalf("accepted DNS input %d", i)
		}
	}
	// A public rename carries the existing complete configuration, and a stale
	// writer cannot remove a newer resolver value without its dependency.
	op.Payload = DevicePut{ID: original.ID, Name: "Demo renamed", Responsibilities: original.Responsibilities, PolicyIDs: original.PolicyIDs, DistributionURLs: original.DistributionURLs, DNSServers: servers}
	op.RequestID = "demo-stale-dns-update"
	if body, err := EncodeOperation(op); err != nil {
		t.Fatal(err)
	} else if _, err := reopened.Submit(context.Background(), body); err == nil {
		t.Fatal("stale update removed newer DNS")
	}
}
