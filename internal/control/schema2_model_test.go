package control

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testNetworkIntent(t *testing.T) NetworkIntent {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-data-plane-ca"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return NetworkIntent{Schema: 2, DNS: []string{"1.1.1.1"}, PublicDataPlaneCA: ca,
		Components: []ComponentExpectation{{Name: "agent", Version: "2.0.0"}},
		Nodes: []NetworkNode{{ID: "demo-egress", Name: "Demo egress", Platform: "linux", Roles: []string{"server"},
			Server: &ServerIntent{Direction: "bidirectional", PublicDataIngress: true, PublicEndpoint: "192.0.2.10", InboundPort: 443,
				InboundProtocol: "hysteria2", EgressCapable: true,
				WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
		Policies: []NetworkPolicy{{ID: "demo-policy", Name: "Demo policy", AllowedServers: []string{"demo-egress"}, AllowedExits: []string{"demo-egress"},
			AllowDirect: true, MaxHops: 2}},
		Services: []Service{{ID: "demo-service", Name: "Demo service", Matchers: []string{"example.com"}, Policy: "demo-policy"}},
		Links:    []NetworkLink{},
	}
}

func TestNetworkIntentMaterialRoundTripAndProjection(t *testing.T) {
	value := NetworkImport{Intent: testNetworkIntent(t), RecoveryEvidenceHash: "sha256:" + strings.Repeat("1", 64)}
	material := Material{Schema: 2, Kind: "network.import", RequestID: "demo-import", BaseHead: "sha256:" + strings.Repeat("2", 64), NetworkImport: &value}
	body, _, err := EncodeMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMaterial(body)
	if err != nil {
		t.Fatal(err)
	}
	again, _, _ := EncodeMaterial(decoded)
	if string(body) != string(again) {
		t.Fatal("network import canonical round trip changed bytes")
	}
	projection, err := Reduce(Projection{Schema: 1, Web: WebProjection{Schema: 1}}, material, "sha256:"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if projection.NetworkIntent == nil || len(projection.Web.Services) != 1 || len(projection.Web.Devices) != 1 {
		t.Fatalf("network intent was not projected: %+v", projection.Web)
	}
	if _, err := Reduce(projection, Material{Schema: 2, Kind: "network.import", RequestID: "demo-import-2",
		BaseHead: material.BaseHead, NetworkImport: &value}, "sha256:"+strings.Repeat("4", 64)); err == nil {
		t.Fatal("a different second network import was accepted")
	}
	var wire map[string]any
	_ = json.Unmarshal(body, &wire)
	wire["unknown"] = true
	nonCanonical, _ := json.Marshal(wire)
	if _, err := DecodeMaterial(nonCanonical); err == nil {
		t.Fatal("network import accepted an unknown field")
	}
}

func TestSchema2WebProjectionDoesNotResurrectRevokedEnrollmentHistory(t *testing.T) {
	intent := testNetworkIntent(t)
	projection := Projection{Schema: 1, NetworkIntent: &intent, Enrollments: []EnrollmentTransaction{
		{Schema: enrollmentSchema, ID: "demo-completed", State: "completed",
			Intent: EnrollmentIntent{DeviceID: "demo-revoked", Name: "Revoked fixture", Platform: "linux", Roles: []string{"access"}}},
		{Schema: enrollmentSchemaV2, ID: "demo-pending", State: "open",
			Intent: EnrollmentIntent{Schema: enrollmentSchemaV2, DeviceID: "d-0123456789", Name: "Pending client",
				Platform: "windows", Roles: []string{"access"}, DestinationGrants: []string{"demo-policy"}}},
	}}
	projectNetworkWeb(&projection)
	projectEnrollmentWeb(&projection)
	if len(projection.Web.Devices) != 2 || projection.Web.Devices[0].ID != "d-0123456789" ||
		projection.Web.Devices[1].ID != "demo-egress" {
		t.Fatalf("current inventory contains revoked history: %+v", projection.Web.Devices)
	}

	legacy := Projection{Schema: 1, Enrollments: projection.Enrollments}
	projectEnrollmentWeb(&legacy)
	if len(legacy.Web.Devices) != 2 {
		t.Fatalf("pre-import replay semantics changed before the forward correction: %+v", legacy.Web.Devices)
	}
}

func TestHistoricalServiceMaterialReplaysBeforeNetworkIntentButNewWriteFailsClosed(t *testing.T) {
	service := Service{ID: "demo-historical-service", Name: "Historical fixture",
		Matchers: []string{"historical.example"}, Policy: "demo-policy"}
	material := Material{Schema: MaterialSchema, Kind: "service.put", RequestID: "demo-historical-service-put",
		BaseHead: "sha256:" + strings.Repeat("1", 64), Service: &service}
	_, id, err := EncodeMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	legacy := Projection{Schema: 1, Web: WebProjection{Schema: 1}}
	replayed, err := Reduce(legacy, material, id)
	if err != nil || len(replayed.Web.Services) != 1 || replayed.Web.Services[0].ID != service.ID {
		t.Fatalf("historical service material no longer replays: projection=%+v err=%v", replayed, err)
	}
	if err := validateSubmission(legacy, material, id); err == nil {
		t.Fatal("new service write bypassed the NetworkIntent authority boundary")
	}
}

func TestServerRuntimeRejectsUserWithoutAuthorizedDestination(t *testing.T) {
	password := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	profile := ServerRuntimeProfile{Kind: "sing_box", Protocol: "hysteria2", ListenPort: 443,
		Users: []ServerRuntimeUser{{Name: "demo-user", Password: password}}}
	if err := profile.Validate(); err == nil {
		t.Fatal("server runtime accepted a credential with no ACL")
	}
	profile.ACL = []ServerRuntimeACL{{User: "demo-user", Action: "egress", DestinationMatchers: []string{"example.com"}}}
	if err := profile.Validate(); err != nil {
		t.Fatalf("valid server runtime rejected: %v", err)
	}
}

func TestSchema2EgressEnrollmentAtomicallyExtendsNetworkIntent(t *testing.T) {
	intent := testNetworkIntent(t)
	projection := Projection{Schema: 1, NetworkIntent: &intent}
	server := &ServerIntent{Direction: "bidirectional", PublicDataIngress: true, PublicEndpoint: "192.0.2.20", InboundPort: 443,
		InboundProtocol: "hysteria2", EgressCapable: true,
		WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	enrollment := EnrollmentIntent{Schema: enrollmentSchemaV2, DeviceID: "d-0123456789", Name: "Demo new egress",
		Platform: "linux", Roles: []string{"server"}, DestinationGrants: []string{"demo-policy"},
		Server: &ServerIntent{Direction: "bidirectional", PublicDataIngress: true, EgressCapable: true}}
	if err := integrateEnrollmentNetworkIntent(&projection, enrollment, server); err != nil {
		t.Fatal(err)
	}
	if node, found := networkNode(projection.NetworkIntent, enrollment.DeviceID); !found || node.Server == nil || !node.Server.EgressCapable {
		t.Fatalf("enrolled server was not added to network intent: %+v", projection.NetworkIntent.Nodes)
	}
	policy, found := networkPolicy(projection.NetworkIntent, "demo-policy")
	if !found || !contains(policy.AllowedExits, enrollment.DeviceID) {
		t.Fatalf("enrolled egress was not added to its granted policy: %+v", policy)
	}
}

func TestSchema2ServerClaimCannotExpandCertifiedResponsibility(t *testing.T) {
	var rejected ServerClaimV2
	if err := decodeRawStrict([]byte(`{"public_endpoint":"192.0.2.20","inbound_port":443,"inbound_protocol":"hysteria2","wg_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","egress_capable":true}`), &rejected); err == nil {
		t.Fatal("server claim wire accepted authority-owned egress capability")
	}
	projection := Projection{Schema: 1, Enrollments: []EnrollmentTransaction{{Schema: enrollmentSchemaV2,
		ID: "demo-transaction", State: "open", Intent: EnrollmentIntent{Schema: enrollmentSchemaV2,
			DeviceID: "d-0123456789", Name: "Demo forwarder", Platform: "linux", Roles: []string{"server"},
			Server: &ServerIntent{Direction: "reverse_only"}}}}}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	bind := EnrollmentBind{TransactionID: "demo-transaction", ClaimRequestID: "demo-claim",
		DevicePublicKey: base64.RawURLEncoding.EncodeToString(public), ClaimedAt: time.Unix(100, 0).UTC().Format(time.RFC3339),
		Server: &ServerClaimV2{PublicEndpoint: "192.0.2.20", InboundPort: 443, InboundProtocol: "hysteria2",
			WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}
	if err := reduceEnrollmentBind(&projection, bind); err != nil || projection.Enrollments[0].Intent.Server.EgressCapable {
		t.Fatalf("bounded server claim changed certified responsibility: %v", err)
	}
}

func TestSchema2ClientPlatformsRejectServerResponsibilitiesAtBothBoundaries(t *testing.T) {
	for _, platform := range []string{"android", "windows"} {
		payload := enrollmentCreatePayload{Schema: enrollmentSchemaV2, Name: "Demo client", Platform: platform,
			Responsibilities: []string{"forward", "use_loom"}, DestinationGrants: []string{"demo-policy"},
			Direction: "bidirectional"}
		if _, err := productEnrollmentIntent(payload); err == nil {
			t.Fatalf("%s product request accepted server responsibility", platform)
		}
		intent := EnrollmentIntent{Schema: enrollmentSchemaV2, DeviceID: "d-0123456789", Name: "Demo client",
			Platform: platform, Roles: []string{"access", "server"}, DestinationGrants: []string{"demo-policy"},
			Server: &ServerIntent{Direction: "bidirectional"}}
		if err := intent.Validate(); err == nil {
			t.Fatalf("%s domain intent accepted server responsibility", platform)
		}
	}
}

func TestExistingNodeRejoinKeepsCertifiedNodeFacts(t *testing.T) {
	intent := testNetworkIntent(t)
	intent.Nodes[0].Server.Country = "DE"
	intent.Nodes[0].Server.City = "Berlin"
	intent.Nodes[0].Server.Provider = "demo-provider"
	projection := Projection{Schema: 1, NetworkIntent: &intent}
	node := intent.Nodes[0]
	enrollment := EnrollmentIntent{Schema: enrollmentSchemaV2, DeviceID: node.ID, Name: node.Name,
		Platform: node.Platform, Roles: node.Roles, DestinationGrants: []string{"demo-policy"},
		Server: &ServerIntent{Direction: node.Server.Direction, PublicDataIngress: node.Server.PublicDataIngress, EgressCapable: true}}
	claim := *node.Server
	claim.Country = ""
	claim.City = ""
	claim.Provider = ""
	if err := integrateEnrollmentNetworkIntent(&projection, enrollment, &claim); err != nil {
		t.Fatal(err)
	}
	if len(projection.NetworkIntent.Nodes) != len(intent.Nodes) {
		t.Fatalf("rejoin duplicated the certified node: %+v", projection.NetworkIntent.Nodes)
	}
	kept := projection.NetworkIntent.Nodes[0].Server
	if kept.Country != "DE" || kept.City != "Berlin" || kept.Provider != "demo-provider" {
		t.Fatalf("rejoin changed certified location facts: %+v", kept)
	}
	changed := claim
	changed.PublicEndpoint = "192.0.2.99"
	if err := integrateEnrollmentNetworkIntent(&projection, enrollment, &changed); err == nil {
		t.Fatal("rejoin changed the certified server endpoint")
	}
}

func TestExpiredEnrollmentMustUseCertifiedTransitionBeforeRejoin(t *testing.T) {
	transaction := EnrollmentTransaction{Schema: enrollmentSchemaV2, ID: "demo-expired-transaction", State: "open",
		Intent: EnrollmentIntent{Schema: enrollmentSchemaV2, DeviceID: "demo-egress", Name: "Demo egress", Platform: "linux",
			Roles: []string{"server"}, DestinationGrants: []string{"demo-policy"},
			Server: &ServerIntent{Direction: "bidirectional", EgressCapable: true}},
		ExpiresAt: "2030-01-01T00:00:00Z"}
	projection := Projection{Schema: 1, Enrollments: []EnrollmentTransaction{transaction}, Web: WebProjection{Schema: 1}}
	early := EnrollmentExpire{TransactionID: transaction.ID, ExpiredAt: "2029-12-31T23:59:59Z"}
	if _, err := Reduce(projection, Material{Schema: MaterialSchema, Kind: "enrollment.expire", RequestID: "demo-expire-early",
		BaseHead: "sha256:" + strings.Repeat("1", 64), EnrollmentExpire: &early}, "sha256:"+strings.Repeat("2", 64)); err == nil {
		t.Fatal("enrollment expired before its certified expiry")
	}
	expire := EnrollmentExpire{TransactionID: transaction.ID, ExpiredAt: "2030-01-01T00:00:00Z"}
	next, err := Reduce(projection, Material{Schema: MaterialSchema, Kind: "enrollment.expire", RequestID: "demo-expire",
		BaseHead: "sha256:" + strings.Repeat("1", 64), EnrollmentExpire: &expire}, "sha256:"+strings.Repeat("3", 64))
	if err != nil {
		t.Fatal(err)
	}
	if next.Enrollments[0].State != "expired" || projection.Enrollments[0].State != "open" {
		t.Fatalf("expiration did not preserve immutable replay: before=%s after=%s", projection.Enrollments[0].State, next.Enrollments[0].State)
	}
}

func TestEnrollmentProjectionKeepsCertifiedNodeMetadata(t *testing.T) {
	intent := testNetworkIntent(t)
	projection := Projection{Schema: 1, NetworkIntent: &intent, Web: WebProjection{Schema: 1},
		Enrollments: []EnrollmentTransaction{{Schema: enrollmentSchemaV2, ID: "demo-transaction", State: "bound",
			Intent: EnrollmentIntent{Schema: enrollmentSchemaV2, DeviceID: "demo-egress", Name: "Demo egress",
				Platform: "linux", Roles: []string{"server"}, Server: &ServerIntent{Direction: "bidirectional"}}}}}
	projectNetworkWeb(&projection)
	projectEnrollmentWeb(&projection)
	if len(projection.Web.Devices) != 1 {
		t.Fatalf("devices=%+v", projection.Web.Devices)
	}
	device := projection.Web.Devices[0]
	if device.Endpoint != "192.0.2.10" || len(device.ExpectedComponents) != 1 || device.ExpectedComponents[0].Name != "agent" {
		t.Fatalf("enrollment discarded certified node metadata: %+v", device)
	}
}

func TestServiceDeleteMaterialDoesNotReadServicePayload(t *testing.T) {
	material := Material{Schema: MaterialSchema, Kind: "service.delete", RequestID: "demo-delete",
		BaseHead: "sha256:" + strings.Repeat("1", 64), ServiceDelete: &ServiceDelete{ID: "demo-service"}}
	if _, _, err := EncodeMaterial(material); err != nil {
		t.Fatalf("valid service deletion was rejected: %v", err)
	}
}

func TestSchema2AuthorizationProjectsPrivateRuntimeWithoutRuntimeKey(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	runtimeKey := make([]byte, 32)
	_, _ = rand.Read(runtimeKey)
	intent := testNetworkIntent(t)
	intent.Nodes = append([]NetworkNode{{ID: "d-0123456789", Name: "Demo client", Platform: "windows", Roles: []string{"access"}}}, intent.Nodes...)
	projection := Projection{Schema: 1, NetworkIntent: &intent,
		EndpointGenerations: []EndpointGeneration{{Schema: 1, EndpointID: "demo-endpoint", Generation: 1,
			Node: "demo-egress", Transport: "tls_tunnel", Listen: "127.0.0.1:8443", Address: "192.0.2.10:8443",
			ServerName: "control.example", SPKISHA256: strings.Repeat("a", 64), State: "serving"}},
		DeviceAuthorizations: []DeviceAuthorization{{Schema: 2, DeviceID: "d-0123456789", DestinationGrants: []string{"demo-policy"},
			DevicePublicKey: base64.RawURLEncoding.EncodeToString(public), RuntimeKey: base64.RawURLEncoding.EncodeToString(runtimeKey), Floor: 1}}}
	if routes, runtime, err := projectAuthorizationRuntime(projection, projection.DeviceAuthorizations[0]); err != nil {
		t.Fatalf("derive schema-2 runtime: %v routes=%+v runtime=%+v", err, routes, runtime)
	}
	view, found := projectDeviceView(projection, "d-0123456789")
	if !found || view.Validate() != nil || len(view.Routes) != 2 || view.Runtime == nil {
		t.Fatalf("schema-2 DeviceView was not derived: found=%t view=%+v", found, view)
	}
	body, _ := json.Marshal(view)
	if strings.Contains(string(body), base64.RawURLEncoding.EncodeToString(runtimeKey)) || strings.Contains(string(body), "runtime_key") {
		t.Fatal("RuntimeKey leaked into DeviceView")
	}
	webBody, _ := json.Marshal(projection.Web)
	if strings.Contains(string(webBody), base64.RawURLEncoding.EncodeToString(runtimeKey)) {
		t.Fatal("RuntimeKey leaked into WebProjection")
	}
}

func TestHybridAccessUsesItsCertifiedWireGuardLinkWithoutPublicIngress(t *testing.T) {
	intent := testNetworkIntent(t)
	intent.Nodes[0].Server.PublicDataIngress = false
	intent.Nodes[0].Server.Direction = "direct_only"
	intent.Nodes = append(intent.Nodes, NetworkNode{ID: "demo-hybrid", Name: "Demo hybrid", Platform: "linux",
		Roles: []string{"access", "server"}, Server: &ServerIntent{Direction: "reverse_only",
			PublicDataIngress: false, PublicEndpoint: "198.51.100.20", InboundPort: 443,
			InboundProtocol: "hysteria2", WGPublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x01", 32)))}})
	intent.Links = []NetworkLink{{ID: "demo-wg", From: "demo-egress", To: "demo-hybrid", Transport: "wireguard",
		FromAddress: "10.20.0.1/32", ToAddress: "10.20.0.2/32", ListenPort: 51820,
		ProbeTargets: []NetworkLinkProbeTarget{{Reporter: "demo-egress", Target: "10.20.0.2"},
			{Reporter: "demo-hybrid", Target: "10.20.0.1"}}}}
	intent.Policies[0].AllowedServers = []string{"demo-egress", "demo-hybrid"}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	runtimeKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	projection := Projection{Schema: 1, NetworkIntent: &intent,
		DeviceAuthorizations: []DeviceAuthorization{{Schema: 2, DeviceID: "demo-hybrid",
			DevicePublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			RuntimeKey:      runtimeKey, Floor: 1, DestinationGrants: []string{"demo-policy"}}}}
	routes, profile, err := projectAuthorizationRuntime(projection, projection.DeviceAuthorizations[0])
	if err != nil {
		t.Fatal(err)
	}
	var wgRoute *RouteCandidate
	for index := range routes {
		if len(routes[index].Chain) == 2 && routes[index].Chain[0] == "demo-hybrid" && routes[index].Chain[1] == "demo-egress" {
			wgRoute = &routes[index]
		}
		if len(routes[index].Chain) == 1 && routes[index].Chain[0] == "demo-egress" {
			t.Fatal("exit without public data ingress received a public one-hop candidate")
		}
	}
	if wgRoute == nil || profile == nil || !strings.Contains(profile.Config, `"bind_interface":"wg-demo-egress"`) {
		t.Fatalf("hybrid WG candidate/runtime missing: routes=%+v profile=%+v", routes, profile)
	}
	exitRuntime, err := projectServerRuntime(projection, "demo-egress", *intent.Nodes[0].Server)
	if err != nil || len(exitRuntime.Users) != 1 || len(exitRuntime.ACL) != 1 || exitRuntime.ACL[0].Action != "egress" {
		t.Fatalf("exit runtime=%+v err=%v", exitRuntime, err)
	}
	hybridRuntime, err := projectServerRuntime(projection, "demo-hybrid", *intent.Nodes[1].Server)
	if err != nil || len(hybridRuntime.Users) != 0 || len(hybridRuntime.ACL) != 0 || len(hybridRuntime.WireGuard) != 1 ||
		hybridRuntime.WireGuard[0].Mode != "initiator" {
		t.Fatalf("hybrid runtime invented a local inbound or missed WG initiation: runtime=%+v err=%v", hybridRuntime, err)
	}
}

func TestSchema2ServerRuntimeDerivesUsersAndACLFromAuthorizations(t *testing.T) {
	accessPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	serverPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	runtimeKey := make([]byte, 32)
	_, _ = rand.Read(runtimeKey)
	intent := testNetworkIntent(t)
	intent.Nodes = append([]NetworkNode{{ID: "d-0123456789", Name: "Demo client", Platform: "linux", Roles: []string{"access"}}}, intent.Nodes...)
	projection := Projection{Schema: 1, NetworkIntent: &intent,
		EndpointGenerations: []EndpointGeneration{{Schema: 1, EndpointID: "demo-endpoint", Generation: 1,
			Node: "demo-egress", Transport: "tls_tunnel", Listen: "127.0.0.1:8443", Address: "192.0.2.10:8443",
			ServerName: "control.example", SPKISHA256: strings.Repeat("a", 64), State: "serving"}},
		DeviceAuthorizations: []DeviceAuthorization{
			{Schema: 2, DeviceID: "d-0123456789", DestinationGrants: []string{"demo-policy"}, DevicePublicKey: base64.RawURLEncoding.EncodeToString(accessPublic),
				RuntimeKey: base64.RawURLEncoding.EncodeToString(runtimeKey), Floor: 1},
			{Schema: 2, DeviceID: "demo-egress",
				DevicePublicKey: base64.RawURLEncoding.EncodeToString(serverPublic), RuntimeKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				Floor: 1},
		}}
	view, found := projectDeviceView(projection, "demo-egress")
	if !found || view.Validate() != nil || view.ServerRuntime == nil {
		t.Fatalf("server DeviceView was not derived: found=%t view=%+v", found, view)
	}
	if len(view.ServerRuntime.Users) != 1 || len(view.ServerRuntime.ACL) != 1 || view.ServerRuntime.ACL[0].Action != "egress" {
		t.Fatalf("server users/ACL do not match the authorized path: %+v", view.ServerRuntime)
	}
	body, _ := json.Marshal(view)
	if strings.Contains(string(body), base64.RawURLEncoding.EncodeToString(runtimeKey)) || strings.Contains(string(body), "runtime_key") {
		t.Fatal("RuntimeKey leaked into server DeviceView")
	}
}

func TestDeviceReportV2UsesIndependentSignatureDomain(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	report := DeviceReport{Schema: 2, DeviceID: "d-0123456789", ViewDigest: "sha256:" + strings.Repeat("a", 64),
		ReportedAt: "2030-01-01T00:00:00Z", Runtime: &RuntimeReadback{State: "running", AppliedViewDigest: "sha256:" + strings.Repeat("a", 64)},
		Selections: []ReportSelection{{Scope: "policy:demo", CandidateID: "route:demo:direct"}}}
	signed, err := SignDeviceReport(report, private)
	if err != nil || signed.Verify(base64.RawURLEncoding.EncodeToString(public)) != nil {
		t.Fatalf("schema-2 report failed sign/verify: %v", err)
	}
	legacyDomain := signed
	legacyDomain.Schema = 1
	legacyDomain.Selections, legacyDomain.Runtime = nil, nil
	legacyDomain.Selection = "route:demo:direct"
	legacyDomain.Signature = signed.Signature
	if legacyDomain.Verify(base64.RawURLEncoding.EncodeToString(public)) == nil {
		t.Fatal("schema-2 signature was accepted in the schema-1 domain")
	}
}

func TestSchema2ProjectsPublicAndReverseWireGuardCandidates(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	runtimeKey := make([]byte, 32)
	_, _ = rand.Read(runtimeKey)
	intent := testNetworkIntent(t)
	intent.Nodes = append([]NetworkNode{
		{ID: "d-0123456789", Name: "Demo access", Platform: "linux", Roles: []string{"access"}},
		{ID: "demo-cn", Name: "Demo entry", Platform: "linux", Roles: []string{"server"}, Server: &ServerIntent{
			Direction: "reverse_only", PublicDataIngress: true, PublicEndpoint: "192.0.2.20", InboundPort: 443,
			InboundProtocol: "hysteria2", WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
	}, intent.Nodes...)
	intent.Nodes[2].Server.Direction = "direct_only"
	intent.Policies[0].AllowedServers = []string{"demo-cn", "demo-egress"}
	intent.Links = []NetworkLink{{ID: "demo-cn-egress", From: "demo-cn", To: "demo-egress", Transport: "wireguard",
		FromAddress: "10.0.0.1/32", ToAddress: "10.0.0.2/32", ListenPort: 51820,
		ProbeTargets: []NetworkLinkProbeTarget{{Reporter: "demo-cn", Target: "10.0.0.2"},
			{Reporter: "demo-egress", Target: "10.0.0.1"}}}}
	if err := intent.Validate(); err != nil {
		t.Fatalf("valid reverse-only topology rejected: %v", err)
	}
	projection := Projection{Schema: 1, NetworkIntent: &intent,
		DeviceAuthorizations: []DeviceAuthorization{{Schema: 2, DeviceID: "d-0123456789",
			DestinationGrants: []string{"demo-policy"}, DevicePublicKey: base64.RawURLEncoding.EncodeToString(public),
			RuntimeKey: base64.RawURLEncoding.EncodeToString(runtimeKey), Floor: 1}}}
	routes, _, err := projectAuthorizationRuntime(projection, projection.DeviceAuthorizations[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 || len(routes[0].Chain) != 2 || len(routes[1].Chain) != 1 || routes[2].FinalExit != "direct" {
		t.Fatalf("direct, relay and one-hop candidates were not preserved: %+v", routes)
	}
	entryRuntime, err := projectServerRuntime(projection, "demo-cn", *intent.Nodes[1].Server)
	if err != nil {
		t.Fatal(err)
	}
	if len(entryRuntime.WireGuard) != 1 || entryRuntime.WireGuard[0].Mode != "initiator" ||
		entryRuntime.WireGuard[0].Endpoint != "192.0.2.10:51820" || entryRuntime.WireGuard[0].PersistentKeepalive != 25 ||
		len(entryRuntime.ACL) != 1 || entryRuntime.ACL[0].Action != "next_hop" ||
		entryRuntime.ACL[0].NextHost != "10.0.0.2" || entryRuntime.ACL[0].BindInterface != "wg-demo-egress" {
		t.Fatalf("reverse-only transport or next-hop ACL is wrong: %+v", entryRuntime)
	}
}

func TestNetworkIntentRejectsDirectionsThatCannotEstablishWireGuard(t *testing.T) {
	intent := testNetworkIntent(t)
	second := intent.Nodes[0]
	second.ID, second.Name = "demo-entry", "Demo entry"
	second.Server = &ServerIntent{Direction: "direct_only", PublicDataIngress: true, PublicEndpoint: "192.0.2.20",
		InboundPort: 443, InboundProtocol: "hysteria2", WGPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	intent.Nodes = append(intent.Nodes, second)
	intent.Nodes[0].Server.Direction = "direct_only"
	intent.Policies[0].AllowedServers = []string{"demo-egress", "demo-entry"}
	intent.Links = []NetworkLink{{ID: "demo-link", From: "demo-egress", To: "demo-entry", Transport: "wireguard",
		FromAddress: "10.0.0.1/32", ToAddress: "10.0.0.2/32", ListenPort: 51820,
		ProbeTargets: []NetworkLinkProbeTarget{{Reporter: "demo-egress", Target: "10.0.0.2"},
			{Reporter: "demo-entry", Target: "10.0.0.1"}}}}
	if err := intent.Validate(); err == nil {
		t.Fatal("two direct-only peers were accepted")
	}
}
