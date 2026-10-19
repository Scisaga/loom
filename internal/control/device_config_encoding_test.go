package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"reflect"
	"testing"
)

func TestSingleStrictBuilderMatchesPublicSigningAndCanonicalBytes(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("demo join")
	}
	request, err := server.newDeviceConfigRequest()
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := KeyID(request.member.PublicKey)
	base := DeviceViewEnvelope{Schema: 3, NetworkID: request.input.projection.NetworkID, GenesisDigest: request.config.GenesisID, IssuerControlID: request.member.ControlID, IssuerKeyID: kid, ControlProof: request.input.proof, FactFrontier: request.input.projection.Frontier}
	for _, change := range []string{"same", "quoted"} {
		p := request.input.projection
		if change == "quoted" {
			p.DeviceAuthorizations = append([]DeviceAuthorization{}, p.DeviceAuthorizations...)
			for i := range p.DeviceAuthorizations {
				if p.DeviceAuthorizations[i].ID == invite.DeviceID {
					p.DeviceAuthorizations[i].Name = "Demo quoted \"view\" π"
				}
			}
		}
		view, e := ProjectDeviceView(p, invite.DeviceID, request.sets...)
		if e != nil {
			t.Fatal(e)
		}
		ordinary := base
		ordinary.View = view
		ordinary, e = SignDeviceViewEnvelope(ordinary, request.key)
		if e != nil {
			t.Fatal(e)
		}
		expected, e := CanonicalEncode(ordinary)
		if e != nil {
			t.Fatal(e)
		}
		actual, wire, e := signProjectedDeviceConfig(base, p, invite.DeviceID, request.sets, request.key)
		if e != nil || !bytes.Equal(wire, expected) || !reflect.DeepEqual(actual, ordinary) {
			t.Fatal("private builder differs", e)
		}
		var decoded DeviceViewEnvelope
		if e = DecodeCanonical(wire, &decoded, ContractDecodeLimits{MaxBytes: 4 << 20, MaxDepth: 128, MaxItems: 1 << 20}); e != nil || !reflect.DeepEqual(decoded, ordinary) {
			t.Fatal("public decode rejected", e)
		}
	}
	seed := sha256.Sum256([]byte("demo-wrong-config-key"))
	wrong := ed25519.NewKeyFromSeed(seed[:])
	for _, key := range []ed25519.PrivateKey{nil, wrong} {
		if _, _, e := signProjectedDeviceConfig(base, request.input.projection, invite.DeviceID, request.sets, key); e == nil {
			t.Fatal("invalid signing key accepted")
		}
	}
	for _, mutate := range []func(*DeviceViewEnvelope){func(v *DeviceViewEnvelope) { v.Schema = 2 }, func(v *DeviceViewEnvelope) { v.NetworkID = "demo-other" }, func(v *DeviceViewEnvelope) { v.GenesisDigest = emptyMaterialTip() }, func(v *DeviceViewEnvelope) { v.IssuerControlID = "demo-missing" }, func(v *DeviceViewEnvelope) { v.FactFrontier = nil }, func(v *DeviceViewEnvelope) { v.ControlProof.Successors = nil }} {
		bad := base
		mutate(&bad)
		if _, _, e := signProjectedDeviceConfig(bad, request.input.projection, invite.DeviceID, request.sets, request.key); e == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	dirty := base
	dirty.ControlProof.Genesis.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, _, err := signProjectedDeviceConfig(dirty, request.input.projection, invite.DeviceID, request.sets, request.key); err == nil {
		t.Fatal("dirty signed proof accepted")
	}
	for _, invalid := range []string{"utf8", "collection"} {
		projection := request.input.projection
		projection.DeviceAuthorizations = append([]DeviceAuthorization{}, projection.DeviceAuthorizations...)
		for i := range projection.DeviceAuthorizations {
			if projection.DeviceAuthorizations[i].ID == invite.DeviceID {
				if invalid == "utf8" {
					projection.DeviceAuthorizations[i].Name = "Demo \xff"
				} else {
					projection.DeviceAuthorizations[i].Responsibilities = nil
				}
			}
		}
		_, publicErr := ProjectDeviceView(projection, invite.DeviceID, request.sets...)
		_, _, privateErr := signProjectedDeviceConfig(base, projection, invite.DeviceID, request.sets, request.key)
		if publicErr == nil || privateErr == nil {
			t.Fatal("public/private malformed projection acceptance differs", invalid, publicErr, privateErr)
		}
	}
}
