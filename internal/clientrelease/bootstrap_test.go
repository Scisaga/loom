package clientrelease

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"loom/internal/control"
)

func demoBootstrapEntries() []control.ReleaseEntry {
	result := []control.ReleaseEntry{}
	for _, arch := range []string{"amd64", "arm64"} {
		result = append(result, control.ReleaseEntry{ComponentID: "linux-client-bootstrap", Platform: "linux-" + arch, ManifestDigest: control.ReleaseDigest([]byte("demo manifest " + arch)), Artifact: control.ReleaseArtifact{Name: "loom-client-linux-" + arch + ".tar.gz", Digest: control.ReleaseDigest([]byte("demo package " + arch)), Size: 12, MediaType: "application/gzip", Audience: "public"}})
	}
	return result
}

func TestBootstrapVerifiesArchiveAcrossMirrorsBeforeSingleInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux shell execution boundary")
	}
	// The real digest and tar readers surround a minimal installer boundary.
	// Production acceptance separately executes the signed native installer.
	installer := []byte("#!/bin/sh\ncat > \"$DEMO_ROOT/invite\"\nprintf 'installed\\n' >> \"$DEMO_ROOT/calls\"\n")
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "loom-client-linux-amd64/install.sh", Mode: 0o700, Size: int64(len(installer))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(installer); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	entries := demoBootstrapEntries()[:1]
	entries[0].Artifact.Digest = control.ReleaseDigest(archive.Bytes())
	entries[0].Artifact.Size = control.U64(archive.Len())
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	body, err := renderBootstrap(entries, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		args []string
		ok   bool
	}{
		{"mirrors", []string{"--base-url", "https://a.example/", "--base-url", "https://b.example/", "--invite-stdin"}, true},
		{"single", []string{"--base-url", "https://b.example/", "--invite-stdin"}, true},
		{"all-wrong", []string{"--base-url", "https://a.example/", "--invite-stdin"}, false},
		{"malformed", []string{"--base-url", "https://b.example/", "--base-url", "--invite-stdin"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			bin, temp := filepath.Join(root, "bin"), filepath.Join(root, "temporary")
			for _, dir := range []string{bin, temp} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			fake := `#!/bin/sh
while [ "$#" -gt 0 ]; do
 case "$1" in https://*) address=$1 ;; -o) shift; output=$1 ;; esac
 shift
done
case "$address" in https://a.example/*) printf 'untrusted archive\n' > "$output" ;; *) cp "$DEMO_ROOT/approved.tar.gz" "$output" ;; esac
`
			for name, contents := range map[string][]byte{"bin/curl": []byte(fake), "bin/id": []byte("#!/bin/sh\necho 0\n"), "bin/uname": []byte("#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n"), "bootstrap.sh": body, "approved.tar.gz": archive.Bytes()} {
				if err := os.WriteFile(filepath.Join(root, name), contents, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("sh", append([]string{filepath.Join(root, "bootstrap.sh")}, test.args...)...)
			command.Stdin = strings.NewReader("demo-private-invite\n")
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+temp, "DEMO_ROOT="+root)
			output, err := command.CombinedOutput()
			if (err == nil) != test.ok || bytes.Contains(output, []byte("demo-private-invite")) {
				t.Fatal("archive verification boundary failed", err)
			}
			calls, callsErr := os.ReadFile(filepath.Join(root, "calls"))
			invite, inviteErr := os.ReadFile(filepath.Join(root, "invite"))
			if test.ok && (callsErr != nil || string(calls) != "installed\n" || inviteErr != nil || string(invite) != "demo-private-invite\n") || !test.ok && (!os.IsNotExist(callsErr) || !os.IsNotExist(inviteErr)) {
				t.Fatal("installer was repeated, consumed different stdin, or ran on failed download")
			}
			if files, err := os.ReadDir(temp); err != nil || len(files) != 0 {
				t.Fatal("temporary archive retained", err)
			}
		})
	}
}

func TestBootstrapBindsOriginalPackagesAndExactScript(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize))
	entries := demoBootstrapEntries()
	one, pkg, err := BuildBootstrap(9, entries, key)
	if err != nil {
		t.Fatal(err)
	}
	two, again, err := BuildBootstrap(9, entries, key)
	if err != nil || !reflect.DeepEqual(one, two) || !reflect.DeepEqual(pkg, again) {
		t.Fatal("bootstrap generation is not deterministic", err)
	}
	command := exec.Command("sh", "-n")
	command.Stdin = bytes.NewReader(one.Body)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v %s", err, output)
	}
	for _, bad := range []Input{{Body: append(bytes.Clone(one.Body), 'x'), Manifest: one.Manifest, Signature: one.Signature}, {Body: one.Body, Manifest: one.Manifest, Signature: bytes.Repeat([]byte{0}, 64)}} {
		if _, err := InspectInput("loom-bootstrap-linux.sh", bad, key.Public().(ed25519.PublicKey)); err == nil {
			t.Fatal("changed signed script accepted")
		}
	}
	set := control.ReleaseSet{Catalog: control.ReleaseCatalog{Schema: 3, Generation: 9, Entries: append([]control.ReleaseEntry{pkg.Entry}, entries...)}, Packages: []control.ReleasePackage{pkg}}
	if err := validateBootstrapBindings(set); err != nil {
		t.Fatal(err)
	}
	set.Catalog.Entries[1].Artifact.Digest = control.ReleaseDigest([]byte("another archive"))
	if err := validateBootstrapBindings(set); err == nil {
		t.Fatal("bootstrap accepted another catalog's package")
	}
	// Identical scripts can have different signed generation metadata. Their
	// removable parse cache must not conflate those two authentic manifests.
	three, next, err := BuildBootstrap(10, entries, key)
	if err != nil || !bytes.Equal(one.Body, three.Body) || pkg.Entry.ManifestDigest == next.Entry.ManifestDigest || packageCacheKey(pkg.Entry) == packageCacheKey(next.Entry) {
		t.Fatal("content-addressed script metadata was conflated", err)
	}
}
