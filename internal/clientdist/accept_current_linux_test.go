package clientdist

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestCurrentAcceptanceBindsOriginalsWithoutDecodingOldFloor(t *testing.T) {
	floor := []byte("{\"schema\":1,\"generation\":128,\"opaque_original\":true}")
	unit := []byte("demo original unit")
	id := strings.Repeat("a", 64)
	candidate := VerifiedDirectory{ID: id, Manifest: Manifest{Arch: "amd64", Generation: 104}}
	identity := control.DeviceIdentityReadback{NetworkID: "demo-network", GenesisDigest: "sha256:" + strings.Repeat("b", 64), DeviceID: "demo-device", DevicePublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), Joined: true, Platform: "linux"}
	value := CurrentAcceptance{Schema: 3, FloorDigest: control.ReleaseDigest(floor), UnitDigest: control.ReleaseDigest(unit), ManifestDigest: "sha256:" + id, NetworkID: identity.NetworkID, GenesisDigest: identity.GenesisDigest, DeviceID: identity.DeviceID, DevicePublicKey: identity.DevicePublicKey, CurrentPath: installRoot + "/releases/" + strings.Repeat("c", 64)}
	for _, test := range []struct {
		name   string
		change func(*CurrentAcceptance, *control.DeviceIdentityReadback)
		valid  bool
	}{
		{"approved exact current", func(*CurrentAcceptance, *control.DeviceIdentityReadback) {}, true},
		{"different floor", func(v *CurrentAcceptance, _ *control.DeviceIdentityReadback) { v.FloorDigest = "sha256:" + id }, false},
		{"different manifest", func(v *CurrentAcceptance, _ *control.DeviceIdentityReadback) {
			v.ManifestDigest = "sha256:" + strings.Repeat("d", 64)
		}, false},
		{"different original unit", func(v *CurrentAcceptance, _ *control.DeviceIdentityReadback) { v.UnitDigest = "sha256:" + id }, false},
		{"different Device", func(_ *CurrentAcceptance, i *control.DeviceIdentityReadback) { i.DeviceID = "demo-other-device" }, false},
		{"different key", func(_ *CurrentAcceptance, i *control.DeviceIdentityReadback) {
			i.DevicePublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
		}, false},
		{"different anchor", func(_ *CurrentAcceptance, i *control.DeviceIdentityReadback) { i.GenesisDigest = "sha256:" + id }, false},
		{"not joined", func(_ *CurrentAcceptance, i *control.DeviceIdentityReadback) { i.Joined = false }, false},
		{"different platform", func(_ *CurrentAcceptance, i *control.DeviceIdentityReadback) { i.Platform = "windows" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, i := value, identity
			test.change(&v, &i)
			before := bytes.Clone(floor)
			if (currentAcceptanceMatches(v, candidate, i, floor, unit) == nil) != test.valid {
				t.Fatal("unexpected original binding acceptance")
			}
			if !bytes.Equal(before, floor) {
				t.Fatal("original floor changed")
			}
		})
	}
	if !bytes.Equal(floor, []byte("{\"schema\":1,\"generation\":128,\"opaque_original\":true}")) {
		t.Fatal("old format was rewritten")
	}
	if os.Geteuid() != 0 {
		return
	}
	path := filepath.Join(t.TempDir(), "demo-acceptance.json")
	body, err := control.CanonicalEncode(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCurrentAcceptance(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(bytes.Clone(body), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCurrentAcceptance(path); err == nil {
		t.Fatal("noncanonical operation accepted")
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readCurrentAcceptance(path); err == nil {
		t.Fatal("unprotected approval input accepted")
	}
}

func TestCurrentAcceptancePreservesActualCLIInputs(t *testing.T) {
	current := installRoot + "/releases/" + strings.Repeat("a", 64)
	options := InstallOptions{State: defaultInstallState, Capture: "mixed", ResourceInputs: "/etc/demo/resources.json"}
	for _, test := range []struct {
		name  string
		args  []string
		valid bool
	}{
		{"deployed defaults", []string{"-capture", "mixed", "-resource-inputs", options.ResourceInputs}, true},
		{"explicit same files", []string{"-state", options.State, "-sing-box", current + "/sing-box", "-capture", "mixed", "-resource-inputs", options.ResourceInputs}, true},
		{"another identity", []string{"-state", "/var/lib/demo-other/state.json", "-resource-inputs", options.ResourceInputs}, false},
		{"another data plane", []string{"-sing-box", "/opt/demo-unverified/sing-box", "-resource-inputs", options.ResourceInputs}, false},
		{"another preference file", []string{"-runtime-state", "/var/lib/demo-other/runtime.json", "-resource-inputs", options.ResourceInputs}, false},
		{"different capture", []string{"-capture", "tun", "-resource-inputs", options.ResourceInputs}, false},
		{"missing resource inputs", []string{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if (checkAcceptanceArguments(test.args, current, options) == nil) != test.valid {
				t.Fatal("actual execution input mapping changed")
			}
		})
	}
}
