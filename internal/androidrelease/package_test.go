package androidrelease

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"hash/adler32"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

var testAPK = flag.String("android-apk", "", "optional exact signed APK integration input")
var testAAR = flag.String("android-aar", "", "optional original AAR integration input")
var testSDK = flag.String("android-sdk", "", "optional pinned SDK integration input")

func demoManifest() Manifest {
	return Manifest{Schema: 3, Kind: Kind, Generation: 1, ApplicationID: PackageID, VersionCode: 1, VersionName: "demo-version", SourceCommit: strings.Repeat("a", 40), AARSHA256: strings.Repeat("b", 64), SingBoxVersion: "demo-native",
		Artifact:        control.ReleaseArtifact{Name: Name, Digest: "sha256:" + strings.Repeat("d", 64), Size: 100, MediaType: MediaType, Audience: "public"},
		NativeLibraries: []NativeLibrary{{Arch: "amd64", Path: libraryPath("amd64"), SHA256: strings.Repeat("e", 64), Size: 10}, {Arch: "arm64", Path: libraryPath("arm64"), SHA256: strings.Repeat("f", 64), Size: 11}}}
}

func TestApplicationManifestRoundTripAndDistinctRuntimeBoundaries(t *testing.T) {
	m := demoManifest()
	body, err := control.CanonicalEncode(m)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Manifest
	if err = control.DecodeCanonical(body, &decoded, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 12, MaxItems: 1024}); err != nil {
		t.Fatal(err)
	}
	again, err := control.CanonicalEncode(decoded)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("application manifest did not retain original bytes")
	}
	components := decoded.Components()
	if len(components) != 4 || components[0].ArtifactDigest != m.Artifact.Digest || components[1].ArtifactDigest != m.Artifact.Digest || components[0].Version != m.SourceCommit || components[2].ArtifactDigest != "sha256:"+m.NativeLibraries[0].SHA256 || components[3].ArtifactDigest != "sha256:"+m.NativeLibraries[1].SHA256 || components[2].Version != m.SingBoxVersion {
		t.Fatal("application and loaded library coordinates were conflated")
	}
	for _, bad := range [][]byte{
		append([]byte(" "), body...),
		bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":1`), 1),
		bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":3,"schema":3`), 1),
		append([]byte(`{"unknown":true,`), body[1:]...),
		bytes.ReplaceAll(body, []byte(`"android-application"`), []byte(`"android-unknown"`)),
	} {
		if err := control.DecodeCanonical(bad, &decoded, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 12, MaxItems: 1024}); err == nil {
			t.Fatal("noncanonical application manifest accepted")
		}
	}
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.NativeLibraries[0].Arch = "arm64" },
		func(m *Manifest) { m.NativeLibraries[0].Path = "../libbox.so" },
		func(m *Manifest) { m.NativeLibraries[0].SHA256 = strings.Repeat("E", 64) },
		func(m *Manifest) { m.SourceCommit = "devel" },
		func(m *Manifest) { m.VersionCode = 0 },
		func(m *Manifest) { m.Artifact.Name = "demo-other.apk" },
		func(m *Manifest) { m.Artifact.Audience = "private" },
	} {
		bad := m
		bad.NativeLibraries = slices.Clone(m.NativeLibraries)
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid application coordinates accepted")
		}
	}
}

func TestOfficialApplicationArtifactBindings(t *testing.T) {
	if *testAPK == "" || *testAAR == "" || *testSDK == "" {
		t.Skip("requires an explicit signed APK, original AAR and SDK")
	}
	apk, err := os.ReadFile(*testAPK)
	if err != nil {
		t.Fatal(err)
	}
	aar, err := os.ReadFile(*testAAR)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := AuditAPK(ctx, *testSDK, apk); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	m, body, signature, err := Build(apk, aar, 1, key)
	if err != nil {
		t.Fatal(err)
	}
	_, again, signedAgain, err := Build(apk, aar, 1, key)
	if err != nil || !bytes.Equal(body, again) || !bytes.Equal(signature, signedAgain) {
		t.Fatal("same application bytes did not produce the same signed manifest")
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	if _, err := Verify(body, signature, apk, wrong.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("wrong platform trust accepted")
	}
	changed := bytes.Clone(apk)
	changed[len(changed)/2] ^= 1
	if _, err := Verify(body, signature, changed, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("changed APK accepted")
	}
	if _, _, _, err := Build(apk, append(bytes.Clone(aar), 0), 1, key); err == nil {
		t.Fatal("another AAR accepted for this APK")
	}
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.SourceCommit = strings.Repeat("1", 40) },
		func(m *Manifest) { m.VersionCode++ },
		func(m *Manifest) { m.SingBoxVersion = "demo-other-native" },
		func(m *Manifest) { m.NativeLibraries[0].SHA256 = m.NativeLibraries[1].SHA256 },
	} {
		bad := m
		bad.NativeLibraries = slices.Clone(m.NativeLibraries)
		change(&bad)
		badBody, err := control.CanonicalEncode(bad)
		if err != nil {
			t.Fatal(err)
		}
		badSignature := ed25519.Sign(key, append([]byte(signatureDomain), badBody...))
		if _, err := Verify(badBody, badSignature, apk, key.Public().(ed25519.PublicKey)); err == nil {
			t.Fatal("signed metadata not matching actual package bytes accepted")
		}
	}
}

func FuzzBuildConfigBounds(f *testing.F) {
	f.Add([]byte("dex\n039\x00"))
	f.Add(bytes.Repeat([]byte{0xff}, 112))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) >= 112 && len(body) <= 64<<20 {
			body = bytes.Clone(body)
			copy(body, []byte("dex\n039\x00"))
			binary.LittleEndian.PutUint32(body[32:], uint32(len(body)))
			binary.LittleEndian.PutUint32(body[36:], 112)
			binary.LittleEndian.PutUint32(body[40:], 0x12345678)
			sum := sha1.Sum(body[32:])
			copy(body[12:], sum[:])
			binary.LittleEndian.PutUint32(body[8:], adler32.Checksum(body[12:]))
		}
		_, _ = readBuildConfig(body)
	})
}
