package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testWireCapability(t *testing.T) BootstrapCapability {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	memberID := "demo-control"
	digest := "sha256:" + strings.Repeat("1", 64)
	config := StableConfig([]Member{{ID: memberID, Node: "demo-node",
		PublicKey: base64.RawURLEncoding.EncodeToString(public)}})
	capability := BootstrapCapability{Schema: 1, TransactionID: "demo-transaction",
		IssuedHead: digest, ConfigMaterial: digest, ControlConfig: config,
		ExpiresAt: "2030-01-01T00:00:00Z", Actions: []string{"claim", "resume"},
		Endpoints: []EndpointReference{{EndpointID: "demo-entry", Generation: 1, Transport: "tls_tunnel",
			Address: "192.0.2.1:443", ServerName: "demo.example", SPKISHA256: strings.Repeat("2", 64), State: "serving"}},
		ConstraintDigest: digest, IssuerMemberID: memberID}
	capability, err = SignBootstrapCapability(capability, NodeConfig{MemberID: memberID,
		IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(private)})
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func TestEnrollmentClaimAndResumeSchemaHaveDistinctSigningDomains(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(public)
	claim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 2, Capability: testWireCapability(t),
		RequestID: "demo-request", DevicePublicKey: key}, private)
	if err != nil {
		t.Fatal(err)
	}
	tamperedClaim := claim
	tamperedClaim.Schema = 1
	if tamperedClaim.Validate() == nil {
		t.Fatal("schema-2 claim signature remained valid after downgrade to schema 1")
	}

	resume, err := SignEnrollmentResume(EnrollmentResumeRequest{Schema: 2, TransactionID: "demo-transaction",
		RequestID: "demo-request", DevicePublicKey: key}, private)
	if err != nil {
		t.Fatal(err)
	}
	tamperedResume := resume
	tamperedResume.Schema = 1
	if tamperedResume.Validate() == nil {
		t.Fatal("schema-2 resume signature remained valid after downgrade to schema 1")
	}
}

func TestLegacyEnrollmentClaimCannotCarrySchema2ServerFacts(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 1, Capability: testWireCapability(t),
		RequestID: "demo-request", DevicePublicKey: base64.RawURLEncoding.EncodeToString(public),
		Server: &ServerClaimV2{PublicEndpoint: "demo.example:443", InboundPort: 443,
			InboundProtocol: "hysteria2", WGPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}}, private)
	if err == nil {
		t.Fatal("legacy enrollment claim accepted schema-2 server facts")
	}
}

func TestEnrollmentIntentToWireSchemaMappingPreservesHistory(t *testing.T) {
	if got := enrollmentWireSchema(EnrollmentIntent{}); got != 1 {
		t.Fatalf("historical intent mapped to wire schema %d", got)
	}
	if got := enrollmentWireSchema(EnrollmentIntent{Schema: 2}); got != 2 {
		t.Fatalf("schema-2 intent mapped to wire schema %d", got)
	}
}
