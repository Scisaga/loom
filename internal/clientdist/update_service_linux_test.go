package clientdist

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestExplicitUpdaterProjectionMigrationBindsAcceptedSourceAndInputs(t *testing.T) {
	options := InstallOptions{PackageRoot: "/opt/demo-package", State: "/var/lib/demo-device/state.json", ResourceInputs: "/etc/demo/resources.json", Capture: "mixed", Upgrade: true, UpdateUnitMigration: "/opt/demo-proof.json"}
	path := filepath.Join(installRoot, "releases", strings.Repeat("a", 64))
	current := Manifest{Loom: Component{Commit: originalUpdateProjectionCommit, SHA256: strings.Repeat("b", 64)}}
	oldService, oldTimer, err := originalUpdateUnits(options.State, options.ResourceInputs, options.Capture)
	if err != nil {
		t.Fatal(err)
	}
	proof := UpdateUnitMigration{Schema: 3, ManifestDigest: "sha256:" + filepath.Base(path), CurrentPath: path, LoomSHA256: current.Loom.SHA256, LoomCommit: current.Loom.Commit, State: options.State, ResourceInputs: options.ResourceInputs, Capture: options.Capture, ServiceDigest: control.ReleaseDigest(oldService), TimerDigest: control.ReleaseDigest(oldTimer)}
	if options.validate() != nil || proof.Validate() != nil {
		t.Fatal("explicit operation rejected")
	}
	privateUpdate := options
	privateUpdate.ExpectedViewDigest = "sha256:" + strings.Repeat("a", 64)
	if err := privateUpdate.validate(); err != nil {
		t.Fatal("authenticated private update cannot consume explicit migration proof", err)
	}
	service, timer, err := migrationUpdateUnits(proof, options, path, &current)
	if err != nil || !bytes.Equal(service, oldService) || !bytes.Equal(timer, oldTimer) {
		t.Fatal("original projection is not exact", err)
	}
	newService, newTimer, err := UpdateUnits(options.State, options.ResourceInputs, options.Capture)
	if err != nil || bytes.Equal(newService, oldService) || !bytes.Equal(newTimer, oldTimer) {
		t.Fatal("forward execution projection is not distinct", err)
	}
	for _, directive := range []string{"Environment=GOMEMLIMIT=64MiB\n", "MemoryAccounting=yes\n", "MemoryHigh=128M\n", "MemoryMax=256M\n", "MemorySwapMax=0\n", "OOMPolicy=stop\n", "Restart=no\n", "KillMode=control-group\n"} {
		if !bytes.Contains(newService, []byte(directive)) {
			t.Fatal("updater resource or failure boundary is missing", directive)
		}
	}
	for _, test := range []struct {
		name string
		edit func(*UpdateUnitMigration, *InstallOptions, *Manifest, *string)
	}{
		{"different accepted package", func(p *UpdateUnitMigration, _ *InstallOptions, _ *Manifest, _ *string) {
			p.ManifestDigest = "sha256:" + strings.Repeat("c", 64)
		}},
		{"different executable", func(_ *UpdateUnitMigration, _ *InstallOptions, m *Manifest, _ *string) {
			m.Loom.SHA256 = strings.Repeat("c", 64)
		}},
		{"different source projection", func(_ *UpdateUnitMigration, _ *InstallOptions, m *Manifest, _ *string) {
			m.Loom.Commit = strings.Repeat("c", 40)
		}},
		{"dirty source", func(_ *UpdateUnitMigration, _ *InstallOptions, m *Manifest, _ *string) { m.Loom.Dirty = true }},
		{"different current path", func(_ *UpdateUnitMigration, _ *InstallOptions, _ *Manifest, p *string) {
			*p = filepath.Join(installRoot, "releases", strings.Repeat("c", 64))
		}},
		{"different state input", func(_ *UpdateUnitMigration, o *InstallOptions, _ *Manifest, _ *string) {
			o.State = "/var/lib/demo-device/other.json"
		}},
		{"different resources", func(_ *UpdateUnitMigration, o *InstallOptions, _ *Manifest, _ *string) { o.ResourceInputs = "" }},
		{"different capture", func(_ *UpdateUnitMigration, o *InstallOptions, _ *Manifest, _ *string) { o.Capture = "tun" }},
		{"different service bytes", func(p *UpdateUnitMigration, _ *InstallOptions, _ *Manifest, _ *string) {
			p.ServiceDigest = "sha256:" + strings.Repeat("c", 64)
		}},
		{"different timer bytes", func(p *UpdateUnitMigration, _ *InstallOptions, _ *Manifest, _ *string) {
			p.TimerDigest = "sha256:" + strings.Repeat("c", 64)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, o, m, currentPath := proof, options, current, path
			test.edit(&p, &o, &m, &currentPath)
			if _, _, err := migrationUpdateUnits(p, o, currentPath, &m); err == nil {
				t.Fatal("changed migration binding accepted")
			}
		})
	}
	for _, change := range []func(*InstallOptions){func(o *InstallOptions) { o.Upgrade = false; o.InviteStdin = true }, func(o *InstallOptions) { o.AcceptCurrent = "/opt/demo-current.json" }, func(o *InstallOptions) { o.ExpectedViewDigest = "sha256:invalid" }} {
		o := options
		change(&o)
		if o.validate() == nil {
			t.Fatal("migration admitted outside an explicit forward upgrade")
		}
	}
}

func TestUpdateUnitComparisonRejectsChangesAndReplacement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installed ownership requires root")
	}
	for _, test := range []struct {
		name string
		edit func(string) error
	}{
		{"changed bytes", func(p string) error { return os.WriteFile(p, []byte("demo changed unit"), 0644) }},
		{"different inode", func(p string) error {
			next := p + ".next"
			if err := os.WriteFile(next, []byte("demo owned unit"), 0644); err != nil {
				return err
			}
			return os.Rename(next, p)
		}},
		{"different mode", func(p string) error { return os.Chmod(p, 0666) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "demo.service")
			body := []byte("demo owned unit")
			if err := os.WriteFile(path, body, 0644); err != nil {
				t.Fatal(err)
			}
			entry, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			checked := checkedUpdateUnit{entry: entry, body: body}
			if err := compareUpdateUnit(path, checked); err != nil {
				t.Fatal(err)
			}
			if err := test.edit(path); err != nil {
				t.Fatal(err)
			}
			if err := compareUpdateUnit(path, checked); err == nil {
				t.Fatal("changed owned unit accepted for replacement")
			}
		})
	}
}
