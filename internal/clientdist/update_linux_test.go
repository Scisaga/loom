package clientdist

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestAutomaticPackageChangesOnlyAcceptedExpectedComponents(t *testing.T) {
	current := Manifest{Arch: "amd64", Version: "demo-original", Loom: Component{SHA256: strings.Repeat("a", 64)}, SingBox: Component{Version: "demo-plane", SHA256: strings.Repeat("b", 64)}}
	next := current
	next.Version = "demo-next"
	next.Loom.SHA256 = strings.Repeat("c", 64)
	view := control.DeviceView{ExpectedComponents: []control.ComponentReadback{manifestComponents(next)[0]}}
	if err := packageMatchesExpected(next, &current, view); err != nil {
		t.Fatal(err)
	}
	changedPlane := next
	changedPlane.SingBox.SHA256 = strings.Repeat("d", 64)
	if err := packageMatchesExpected(changedPlane, &current, view); err == nil {
		t.Fatal("unrequested data-plane change accepted")
	}
	view.ExpectedComponents = manifestComponents(next)
	if err := packageMatchesExpected(changedPlane, &current, view); err == nil {
		t.Fatal("independent data-plane expectation ignored")
	}
	view.ExpectedComponents = append(view.ExpectedComponents, view.ExpectedComponents[0])
	if err := packageMatchesExpected(next, &current, view); err == nil {
		t.Fatal("ambiguous expected component accepted")
	}
	view.ExpectedComponents = nil
	if err := packageMatchesExpected(next, &current, view); err == nil {
		t.Fatal("empty expectation authorized installation")
	}
}

func TestDeliveryOriginalSignaturesAndCatalogBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	public := key.Public().(ed25519.PublicKey)
	// The existing contract fixture supplies a valid immutable manifest; this
	// test checks metadata signatures before the separately verified full body.
	loom, plane := buildClientFixtures(t)
	artifact, err := buildWithInspect(BuildInput{Generation: 8, Loom: loom, SingBox: plane, PrivateKey: key, AllowDirty: true}, fixtureSingBox, fixtureSources)
	if err != nil {
		t.Fatal(err)
	}
	manifest := artifact.Manifest
	body, err := control.CanonicalEncode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, append([]byte(signatureDomain+"\x00"), body...))
	entry := control.ReleaseEntry{ComponentID: "linux-client-bootstrap", Platform: "linux-amd64", ManifestDigest: control.ReleaseDigest(body), Artifact: control.ReleaseArtifact{Name: "loom-client-linux-amd64.tar.gz", Digest: control.ReleaseDigest([]byte("demo archive")), Size: 12, MediaType: "application/gzip", Audience: "public"}}
	cat, catSig, err := control.SignReleaseCatalog(control.ReleaseCatalog{Schema: 3, Generation: 8, Entries: []control.ReleaseEntry{entry}}, key)
	if err != nil {
		t.Fatal(err)
	}
	view := control.DeviceView{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", Name: "Demo device", DevicePublicKey: base64.RawURLEncoding.EncodeToString(public), Platform: "linux", Responsibilities: []string{"control"}, PolicyIDs: []string{}, Services: []control.Service{}, Policies: []control.NetworkPolicy{}, Resources: []control.TransportResource{}, Links: []control.NetworkLink{}, Endpoints: []control.EndpointGeneration{}, DNSServers: []string{}, BusinessProbeTargets: []control.ServiceProbeTargets{}, Routes: []control.RouteCandidate{}, InboundCredentials: []control.InboundCredential{}, ExpectedComponents: manifestComponents(manifest)}
	digest, err := control.DeviceViewDigest(view)
	if err != nil {
		t.Fatal(err)
	}
	delivery := control.DeviceReleaseDelivery{Schema: 3, Platform: "linux-amd64", ViewDigest: digest, CatalogBody: string(cat), CatalogSignature: base64.RawURLEncoding.EncodeToString(catSig), ManifestBody: string(body), ManifestSignature: base64.RawURLEncoding.EncodeToString(sig)}
	if _, got, err := verifyDelivery(delivery, public, view); err != nil || got != entry {
		t.Fatal("original signed delivery failed", err)
	}
	for _, test := range []struct {
		name   string
		change func(*control.DeviceReleaseDelivery)
	}{
		{"catalog signature", func(d *control.DeviceReleaseDelivery) {
			d.CatalogSignature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
		}},
		{"manifest signature", func(d *control.DeviceReleaseDelivery) {
			d.ManifestSignature = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 64))
		}},
		{"other platform", func(d *control.DeviceReleaseDelivery) { d.Platform = "linux-arm64" }},
		{"other accepted View", func(d *control.DeviceReleaseDelivery) {
			d.ViewDigest = control.ReleaseDigest([]byte("demo other View"))
		}},
		{"catalog reference differs", func(d *control.DeviceReleaseDelivery) {
			changed := entry
			changed.ManifestDigest = control.ReleaseDigest([]byte("demo other manifest"))
			changedBody, changedSig, signErr := control.SignReleaseCatalog(control.ReleaseCatalog{Schema: 3, Generation: 8, Entries: []control.ReleaseEntry{changed}}, key)
			if signErr != nil {
				t.Fatal(signErr)
			}
			d.CatalogBody, d.CatalogSignature = string(changedBody), base64.RawURLEncoding.EncodeToString(changedSig)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := delivery
			test.change(&d)
			if _, _, err := verifyDelivery(d, public, view); err == nil {
				t.Fatal("invalid original release binding accepted")
			}
		})
	}
}
