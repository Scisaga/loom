package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func validationEnvelopeFixture(tb testing.TB) (materialFixture, DeviceViewEnvelope) {
	tb.Helper()
	f, proof, projection := deviceContractFixture(tb)
	for i := 1; i < 8; i++ {
		service := materialTestService(fmt.Sprintf("demo-service-%02d", i))
		policy := materialTestPolicy(fmt.Sprintf("demo-policy-%02d", i), service.ID)
		projection.NetworkIntent.Services = append(projection.NetworkIntent.Services, service)
		projection.NetworkIntent.Policies = append(projection.NetworkIntent.Policies, policy)
		projection.DeviceAuthorizations[0].PolicyIDs = append(projection.DeviceAuthorizations[0].PolicyIDs, policy.ID)
	}
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		tb.Fatal(err)
	}
	keyID, _ := KeyID(f.members[1].PublicKey)
	envelope, err := SignDeviceViewEnvelope(DeviceViewEnvelope{Schema: 3, NetworkID: projection.NetworkID,
		GenesisDigest: materialTestID(tb, f.genesis), IssuerControlID: f.members[1].ControlID, IssuerKeyID: keyID,
		ControlProof: proof, FactFrontier: []FactFrontier{}, View: view}, f.keys[1])
	if err != nil {
		tb.Fatal(err)
	}
	return f, envelope
}

func TestDeviceViewEnvelopeUnsignedCoversEveryNonSignatureField(t *testing.T) {
	_, envelope := validationEnvelopeFixture(t)
	unsigned := envelope.unsigned()
	value := reflect.ValueOf(envelope)
	if len(unsigned) != value.NumField()-1 {
		t.Fatal("unsigned envelope does not cover the complete fixed field set")
	}
	for index := range value.NumField() {
		field := value.Type().Field(index)
		name, options, hasOptions := strings.Cut(field.Tag.Get("json"), ",")
		if field.PkgPath != "" || field.Anonymous || !contractJSONKey(name) || hasOptions || options != "" {
			t.Fatal("envelope field shape changed without revisiting its fixed inspection boundary", field.Name)
		}
		got, found := unsigned[name]
		if name == "signature" {
			if found {
				t.Fatal("signature became part of its own unsigned body")
			}
			continue
		}
		if !found || !reflect.DeepEqual(got, value.Field(index).Interface()) {
			t.Fatal("unsigned field is absent or differs from the actual envelope value", name)
		}
	}
}

func TestDeviceViewEnvelopeCanonicalFragmentKeepsBytesAndDomains(t *testing.T) {
	f, envelope := validationEnvelopeFixture(t)
	for _, name := range []string{"Demo access", `Demo "view": {"signature":"nested"} \\ 管理`} {
		envelope.View.Name = name
		var err error
		envelope, err = SignDeviceViewEnvelope(envelope, f.keys[1])
		if err != nil {
			t.Fatal(err)
		}
		unsigned, err := CanonicalEncode(envelope.unsigned())
		if err != nil {
			t.Fatal(err)
		}
		var fragment struct {
			View json.RawMessage `json:"view"`
		}
		if err := json.Unmarshal(unsigned, &fragment); err != nil {
			t.Fatal(err)
		}
		view, err := CanonicalEncode(envelope.View)
		if err != nil || !bytes.Equal(fragment.View, view) {
			t.Fatal("nested canonical View differs from its independent encoding", err)
		}
		digest, err := DeviceViewDigest(envelope.View)
		if err != nil || digest != deviceViewDigestFromCanonical(fragment.View) || digest != envelope.ViewDigest {
			t.Fatal("canonical fragment changed the View digest framing", err)
		}
		public, _ := base64.RawURLEncoding.DecodeString(f.members[1].PublicKey)
		signature, _ := base64.RawURLEncoding.DecodeString(envelope.Signature)
		if !ed25519.Verify(ed25519.PublicKey(public), append([]byte("loom-device-view-v3\x00"), unsigned...), signature) {
			t.Fatal("the original signature domain no longer covers the exact unsigned body")
		}
		body, err := CanonicalEncode(envelope)
		if err != nil {
			t.Fatal(err)
		}
		var decoded DeviceViewEnvelope
		limits := ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}
		if err := DecodeCanonical(body, &decoded, limits); err != nil || !reflect.DeepEqual(decoded, envelope) {
			t.Fatal("canonical envelope did not preserve its complete signed value", err)
		}
		again, err := CanonicalEncode(decoded)
		if err != nil || !bytes.Equal(body, again) {
			t.Fatal("envelope canonical bytes changed on round trip", err)
		}
		// This canonical object contains deliberate nested lookalikes. Only the
		// top-level member may supply the exact View fragment.
		lookalikes, err := CanonicalEncode(map[string]any{"nested": map[string]any{"signature": "demo-nested", "view": map[string]any{"name": "demo-other"}}, "text": `demo "view": {"signature":"nested"}`, "view": envelope.View})
		if err != nil || json.Unmarshal(lookalikes, &fragment) != nil || !bytes.Equal(fragment.View, view) {
			t.Fatal("nested members or quoted lookalikes changed top-level extraction", err)
		}
	}
}

// Ordinary inspection checks the same actual fields without the fixed Envelope
// shortcut. It retains the public semantic validator before the generic pass.
func ordinaryEnvelopeEncoding(envelope DeviceViewEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	fields := map[string]any{}
	value := reflect.ValueOf(envelope)
	for index := range value.NumField() {
		fields[value.Type().Field(index).Tag.Get("json")] = value.Field(index).Interface()
	}
	return CanonicalEncode(fields)
}

func TestDeviceViewEnvelopeFixedInspectionKeepsRejections(t *testing.T) {
	_, original := validationEnvelopeFixture(t)
	body, err := CanonicalEncode(original)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := ordinaryEnvelopeEncoding(original)
	if err != nil || !bytes.Equal(body, ordinary) {
		t.Fatal("fixed Envelope inspection changed canonical bytes", err)
	}
	limits := ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}
	changes := []struct {
		name   string
		change func(*DeviceViewEnvelope)
	}{
		{"invalid View", func(v *DeviceViewEnvelope) { v.View.Schema = 0 }},
		{"required View collection", func(v *DeviceViewEnvelope) { v.View.Services = nil }},
		{"required frontier", func(v *DeviceViewEnvelope) { v.FactFrontier = nil }},
		{"required proof collection", func(v *DeviceViewEnvelope) { v.ControlProof.Successors = nil }},
		{"optional DNS collection", func(v *DeviceViewEnvelope) { v.View.DNSRecords = []DNSRecord{} }},
		{"optional public trust", func(v *DeviceViewEnvelope) { v.View.PublicTrust = []PublicTrust{} }},
		{"nested UTF8", func(v *DeviceViewEnvelope) { v.View.RuntimeProfile.Config += string([]byte{0xff}) }},
		{"signature UTF8", func(v *DeviceViewEnvelope) { v.Signature += string([]byte{0xff}) }},
		{"signature newline", func(v *DeviceViewEnvelope) { v.Signature = "\n" + v.Signature }},
		{"signature padding", func(v *DeviceViewEnvelope) { v.Signature += "=" }},
		{"signature bits", func(v *DeviceViewEnvelope) {
			signature, _ := base64.RawURLEncoding.DecodeString(v.Signature)
			signature[0] ^= 1
			v.Signature = base64.RawURLEncoding.EncodeToString(signature)
		}},
		{"digest", func(v *DeviceViewEnvelope) { v.ViewDigest = ReleaseDigest([]byte("demo-other-view")) }},
		{"changed View", func(v *DeviceViewEnvelope) { v.View.Name = "Demo changed access" }},
		{"changed View and digest", func(v *DeviceViewEnvelope) {
			v.View.Name = "Demo changed access"
			v.ViewDigest, _ = DeviceViewDigest(v.View)
		}},
		{"nested signature", func(v *DeviceViewEnvelope) { v.ControlProof.Genesis.Signature = "demo-invalid" }},
		{"issuer", func(v *DeviceViewEnvelope) { v.IssuerControlID = "demo-other-control" }},
		{"issuer key", func(v *DeviceViewEnvelope) { v.IssuerKeyID = ReleaseDigest([]byte("demo-other-key")) }},
		{"frontier key", func(v *DeviceViewEnvelope) {
			v.FactFrontier = []FactFrontier{{KeyID: ReleaseDigest([]byte("demo-unproven-key")), TipMaterialID: v.GenesisDigest}}
		}},
		{"member responsibility", func(v *DeviceViewEnvelope) { v.View.Responsibilities = []string{"access", "control"} }},
	}
	codec := newContractCodec()
	if _, err := codec.encode(original); err != nil {
		t.Fatal(err)
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			var envelope DeviceViewEnvelope
			if err := DecodeCanonical(body, &envelope, limits); err != nil {
				t.Fatal(err)
			}
			change.change(&envelope)
			if envelope.Validate() == nil {
				t.Fatal("public Envelope validation accepted an invalid value")
			}
			if _, err := codec.encode(envelope); err == nil {
				t.Fatal("fixed inspection or reused metadata accepted an invalid Envelope")
			}
			if _, err := ordinaryEnvelopeEncoding(envelope); err == nil {
				t.Fatal("ordinary inspection accepted the rejected Envelope")
			}
		})
	}
	view, err := CanonicalEncode(original.View)
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{
		append(append(bytes.Clone(body[:len(body)-1]), []byte(`,"view":`)...), append(view, '}')...),
		append(bytes.Clone(body[:len(body)-1]), []byte(`,"unknown":0}`)...),
		bytes.Replace(body, view, append(bytes.Clone(view[:len(view)-1]), []byte(`,"unknown":0}`)...), 1),
	} {
		var decoded DeviceViewEnvelope
		if err := DecodeCanonical(malformed, &decoded, limits); err == nil {
			t.Fatal("RawMessage extraction widened the public canonical input schema")
		}
	}
}

func TestDeviceViewEnvelopeKeepsSemanticChecksWithValidSignature(t *testing.T) {
	f, original := validationEnvelopeFixture(t)
	body, err := CanonicalEncode(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name   string
		change func(*DeviceViewEnvelope)
	}{
		{"unproven frontier", func(v *DeviceViewEnvelope) {
			v.FactFrontier = []FactFrontier{{KeyID: ReleaseDigest([]byte("demo-unproven-key")), Sequence: 1, TipMaterialID: v.GenesisDigest}}
		}},
		{"unproven endpoint owner", func(v *DeviceViewEnvelope) {
			v.View.Endpoints = []EndpointGeneration{{ID: "demo-device-endpoint", Generation: 1, OwnerControlID: "demo-unproven-control",
				Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: ReleaseDigest([]byte("demo-spki")),
				CertificateDigest: ReleaseDigest([]byte("demo-certificate")), Modes: []string{"device"}, State: "serving"}}
		}},
		{"unproven control responsibility", func(v *DeviceViewEnvelope) {
			v.View.Responsibilities = []string{"access", "control"}
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			var envelope DeviceViewEnvelope
			if err := DecodeCanonical(body, &envelope, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
				t.Fatal(err)
			}
			change.change(&envelope)
			var err error
			envelope.View.Routes, envelope.View.RuntimeProfile, err = ProjectAccessRuntime(envelope.View)
			if err != nil || envelope.View.Validate() != nil {
				t.Fatal("semantic rejection fixture has an invalid inner View", err)
			}
			envelope.ViewDigest, err = DeviceViewDigest(envelope.View)
			if err != nil {
				t.Fatal(err)
			}
			unsigned, err := CanonicalEncode(envelope.unsigned())
			if err != nil {
				t.Fatal(err)
			}
			// Construct the valid cryptographic signature without asking the
			// domain signer to accept the deliberately unauthorized envelope.
			envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.keys[1], append([]byte("loom-device-view-v3\x00"), unsigned...)))
			if envelope.Validate() == nil {
				t.Fatal("a valid signature replaced membership, frontier or endpoint authority checks")
			}
			if _, err := CanonicalEncode(envelope); err == nil {
				t.Fatal("fixed inspection skipped the semantic envelope rejection")
			}
		})
	}
}

func BenchmarkDeviceViewEnvelopeValidation(b *testing.B) {
	_, envelope := validationEnvelopeFixture(b)
	body, err := CanonicalEncode(envelope)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("demo fixture: %s, %d canonical bytes", ReleaseDigest(body), len(body))
	b.Run("Validate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := envelope.Validate(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("CanonicalEncode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := CanonicalEncode(envelope); err != nil {
				b.Fatal(err)
			}
		}
	})
}
