package control

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"strings"
	"testing"
)

func demoReleaseCatalog() ReleaseCatalog {
	return ReleaseCatalog{Schema: 3, Generation: 7, Entries: []ReleaseEntry{{ComponentID: "linux-client-bootstrap", Platform: "linux-amd64", ManifestDigest: ReleaseDigest([]byte("demo manifest")), Artifact: ReleaseArtifact{Name: "loom-client-linux-amd64.tar.gz", Digest: ReleaseDigest([]byte("demo package")), Size: 9, MediaType: "application/gzip", Audience: "public"}}}}
}

func TestReleaseCatalogCanonicalRoundTrip(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4b}, ed25519.SeedSize))
	value := demoReleaseCatalog()
	body, signature, err := SignReleaseCatalog(value, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyReleaseCatalog(body, signature, key.Public().(ed25519.PublicKey))
	if err != nil || !reflect.DeepEqual(got, value) {
		t.Fatal("release catalog round trip", err)
	}
	again, againSignature, err := SignReleaseCatalog(got, key)
	if err != nil || !bytes.Equal(again, body) || !bytes.Equal(againSignature, signature) {
		t.Fatal("release catalog encoding or signing is not deterministic")
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7d}, ed25519.SeedSize))
	if _, err := VerifyReleaseCatalog(body, signature, wrong.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("wrong catalog trust accepted")
	}
	for name, changed := range map[string][]byte{
		"legacy schema":           bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":1`), 1),
		"numeric generation":      bytes.Replace(body, []byte(`"generation":"7"`), []byte(`"generation":7`), 1),
		"duplicate generation":    bytes.Replace(body, []byte(`"generation":"7"`), []byte(`"generation":"7","generation":"7"`), 1),
		"unknown field":           append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"extra":false}`)...),
		"noncanonical whitespace": append([]byte(" "), body...),
	} {
		t.Run(name, func(t *testing.T) {
			signed := ed25519.Sign(key, append([]byte(ReleaseCatalogDomain), changed...))
			if _, err := VerifyReleaseCatalog(changed, signed, key.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("signed but invalid catalog accepted")
			}
		})
	}
}

func TestReleaseCatalogRejectsAmbiguousCoordinates(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*ReleaseCatalog)
	}{
		{"zero generation", func(v *ReleaseCatalog) { v.Generation = 0 }},
		{"no entries", func(v *ReleaseCatalog) { v.Entries = []ReleaseEntry{} }},
		{"duplicate mapping", func(v *ReleaseCatalog) { v.Entries = append(v.Entries, v.Entries[0]) }},
		{"unknown component", func(v *ReleaseCatalog) { v.Entries[0].ComponentID = "demo-undefined" }},
		{"wrong platform", func(v *ReleaseCatalog) { v.Entries[0].Platform = "windows-amd64" }},
		{"wrong media", func(v *ReleaseCatalog) { v.Entries[0].Artifact.MediaType = "application/zip" }},
		{"private artifact", func(v *ReleaseCatalog) { v.Entries[0].Artifact.Audience = "private" }},
		{"path escape", func(v *ReleaseCatalog) { v.Entries[0].Artifact.Name = "../demo.gz" }},
		{"missing digest domain", func(v *ReleaseCatalog) { v.Entries[0].ManifestDigest = strings.Repeat("a", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := demoReleaseCatalog()
			test.edit(&value)
			if _, err := CanonicalEncode(value); err == nil {
				t.Fatal("ambiguous release coordinates accepted")
			}
		})
	}
}
