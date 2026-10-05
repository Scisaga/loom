package clientdist

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallExplicitModes(t *testing.T) {
	base := InstallOptions{PackageRoot: "/opt/demo-package", State: defaultInstallState, Capture: "mixed", Upgrade: true}
	for _, test := range []struct {
		name  string
		edit  func(*InstallOptions)
		valid bool
	}{
		{"upgrade", func(*InstallOptions) {}, true},
		{"invitation stdin", func(o *InstallOptions) { o.Upgrade = false; o.InviteStdin = true }, true},
		{"cache", func(o *InstallOptions) { o.Upgrade = false; o.NoEnroll = true; o.Capture = "" }, true},
		{"implicit capture", func(o *InstallOptions) { o.Capture = "" }, false},
		{"tun", func(o *InstallOptions) { o.Capture = "tun" }, false},
		{"ambiguous invitation", func(o *InstallOptions) { o.InviteStdin = true }, false},
		{"no operation", func(o *InstallOptions) { o.Upgrade = false }, false},
		{"cache activation", func(o *InstallOptions) { o.Upgrade = false; o.NoEnroll = true }, false},
		{"relative state", func(o *InstallOptions) { o.State = "demo.json" }, false},
		{"unit injection", func(o *InstallOptions) { o.State = "/var/lib/demo\nExecStart=/bin/true" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := base
			test.edit(&o)
			if (o.validate() == nil) != test.valid {
				t.Fatal("unexpected input acceptance")
			}
		})
	}
}

func TestPackageAdvancePreservesAcceptedGeneration(t *testing.T) {
	current := Manifest{Arch: "amd64", Generation: 7}
	id := strings.Repeat("a", 64)
	for _, test := range []struct {
		name  string
		next  Manifest
		id    string
		valid bool
	}{
		{"retry", current, id, true},
		{"forward", Manifest{Arch: "amd64", Generation: 8}, strings.Repeat("b", 64), true},
		{"rollback", Manifest{Arch: "amd64", Generation: 6}, id, false},
		{"equivocation", current, strings.Repeat("b", 64), false},
		{"platform change", Manifest{Arch: "arm64", Generation: 8}, id, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := current
			if (advancePackage("/demo/releases/"+id, &current, VerifiedDirectory{Manifest: test.next, ID: test.id}) == nil) != test.valid {
				t.Fatal("unexpected generation acceptance")
			}
			if current.Generation != before.Generation || current.Arch != before.Arch {
				t.Fatal("comparison changed accepted manifest")
			}
		})
	}
}

func TestInstalledPayloadRejectsMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership contract")
	}
	for _, test := range []struct {
		name   string
		mutate func(string) error
		valid  bool
	}{
		{"exact", func(string) error { return nil }, true},
		{"changed executable", func(root string) error { return os.WriteFile(filepath.Join(root, "sing-box"), []byte("damaged"), 0755) }, false},
		{"writable", func(root string) error { return os.Chmod(filepath.Join(root, "loom"), 0777) }, false},
		{"symlink", func(root string) error {
			path := filepath.Join(root, "loom")
			if err := os.Rename(path, path+".old"); err != nil {
				return err
			}
			return os.Symlink(path+".old", path)
		}, false},
		{"hardlink", func(root string) error { return os.Link(filepath.Join(root, "sing-box"), filepath.Join(root, "extra")) }, false},
		{"missing", func(root string) error { return os.Remove(filepath.Join(root, "loom")) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string][]byte{"loom": []byte("demo loom"), "sing-box": []byte("demo sing-box"), "manifest.json": []byte("demo manifest")}
			for name, body := range files {
				if err := installFile(filepath.Join(root, name), body, packageFileMode(name)); err != nil {
					t.Fatal(err)
				}
			}
			if err := test.mutate(root); err != nil {
				t.Fatal(err)
			}
			if (verifyInstalledPayload(root, VerifiedDirectory{Files: files}) == nil) != test.valid {
				t.Fatal("unexpected installed payload acceptance")
			}
		})
	}
}

func TestReplacedProgramsPreserveSignedEvidence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership contract")
	}
	root := t.TempDir()
	manifest := Manifest{}
	for _, name := range []string{"loom", "sing-box", "manifest.json", "manifest.sig"} {
		body := []byte("demo protected bytes " + name)
		if err := installFile(filepath.Join(root, name), body, packageFileMode(name)); err != nil {
			t.Fatal(err)
		}
		if name == "loom" {
			manifest.Loom = Component{Path: name, SHA256: sha256Hex(body)}
		}
		if name == "sing-box" {
			manifest.SingBox = Component{Path: name, SHA256: sha256Hex(body)}
		}
	}
	for range 2 {
		if err := removeReplacedPrograms(root, manifest); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"manifest.json", "manifest.sig"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(body, []byte("demo protected bytes "+name)) {
			t.Fatal("signed evidence changed")
		}
	}
}

func TestServiceProjectionQuotesLiteralInputs(t *testing.T) {
	state := `/var/lib/demo space %i $DEVICE/state.json`
	body, err := ServiceUnit("/opt/demo-release", state, `/etc/demo %i $INPUT.json`)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`-state "/var/lib/demo space %%i $$DEVICE/state.json"`, `-runtime-state "/var/lib/demo space %%i $$DEVICE/runtime.json"`, `-resource-inputs "/etc/demo %%i $$INPUT.json"`} {
		if !bytes.Contains(body, []byte(required)) {
			t.Fatalf("missing literal argument: %s", required)
		}
	}
}
