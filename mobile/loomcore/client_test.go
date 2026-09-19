package loomcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"loom/internal/clientmodel"
)

func TestAndroidDeviceProfileProjectsCertifiedName(t *testing.T) {
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodeKey := func(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }
	digest := "sha256:" + strings.Repeat("0", 64)
	endpoint := endpointReference{
		EndpointID: "demo-endpoint", Generation: 1, Transport: "tls_tunnel",
		Address: "192.0.2.1:443", ServerName: "control.example",
		SPKISHA256: strings.Repeat("0", 64), State: "serving",
	}
	config := controlConfig{Mode: "stable", Members: []member{{
		ID: "demo-control", PublicKey: encodeKey(controlPublic), Node: "demo-server",
	}}, Quorum: 1}
	capability := bootstrapCapability{
		Schema: 1, TransactionID: "demo-enrollment", IssuedHead: digest,
		ConfigMaterial: digest, ControlConfig: config, ExpiresAt: "2030-01-01T00:00:00Z",
		Actions: []string{"claim", "resume"}, Endpoints: []endpointReference{endpoint},
		ConstraintDigest: digest, IssuerMemberID: "demo-control",
	}
	if err := signValue(capabilityDomain, capability, &capability.Signature, controlPrivate); err != nil {
		t.Fatal(err)
	}
	runtimeConfig, err := clientmodel.CanonicalizeRuntimeConfig([]byte(`{
		"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],
		"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"default","outbounds":["direct"]}],
		"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	routes := []clientmodel.RouteCandidate{{ID: "direct", FinalExit: "direct", Scope: "default"}}
	view := deviceView{
		Schema: 1, DeviceID: "demo-android", Name: "Loom A", Platform: "android",
		DevicePublicKey: encodeKey(devicePublic), Floor: 1, Endpoints: []endpointReference{endpoint},
		Routes: routes, Runtime: &clientmodel.RuntimeProfile{Kind: "sing_box", Config: runtimeConfig},
	}
	leaf, err := viewLeaf(view)
	if err != nil {
		t.Fatal(err)
	}
	head := governanceHead{
		Schema: 1, Index: 1, LogDigest: digest, ProjectionDigest: digest,
		DeviceViewsDigest: "sha256:" + hex.EncodeToString(leaf), ConfigMaterial: digest,
	}
	message, err := signingBytes(headDomain, head)
	if err != nil {
		t.Fatal(err)
	}
	head.Signatures = []headSignature{{
		MemberID: "demo-control",
		Value:    base64.RawURLEncoding.EncodeToString(ed25519.Sign(controlPrivate, message)),
	}}
	stateBody, err := encodeState(deviceState{
		Schema: 1, PrivateKey: encodeKey(devicePrivate), PublicKey: encodeKey(devicePublic),
		ClaimRequestID: "demo-request", Capability: capability, Claimed: true, Floor: 1,
		LKG: &deviceViewEnvelope{
			Schema: 1, View: view, Head: head, ControlConfig: config,
			Proof: deviceViewProof{Index: 0, Size: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	profileBody, err := AndroidDeviceProfile(stateBody)
	if err != nil {
		t.Fatal(err)
	}
	var profile androidProfile
	if err := decodeStrictJSON(profileBody, 8<<20, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Name != "Loom A" {
		t.Fatalf("certified display name was not projected: %q", profile.Name)
	}
}
