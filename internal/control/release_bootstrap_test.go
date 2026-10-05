package control

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestShellInviteRejectsWrongDownloadedBytesBeforeExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux shell execution boundary")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t, func(value *Invite) { value.Medium = "sh"; value.Responsibilities = []string{"access", "forward"} })
	bootstrap, err := server.bootstrapInvite("demo-enrollment")
	if err != nil {
		t.Fatal(err)
	}
	invite, err := EncodeInvite(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	artifact := ReleaseArtifact{Name: "loom-bootstrap-linux.sh", Digest: ReleaseDigest([]byte("demo approved installer")), Size: 23, MediaType: "text/x-shellscript", Audience: "public"}
	block, err := ShellInviteDelivery([]string{"https://downloads.example/", "https://mirror.example/"}, artifact, invite)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(block, invite) != 1 || !strings.Contains(block, "<<'LOOM_SIGNED_INVITE'\n"+invite+"\nLOOM_SIGNED_INVITE") || strings.Contains(block, "export ") {
		t.Fatal("invitation escaped its single quoted stdin delivery")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	temp := filepath.Join(root, "temporary")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(temp, 0o700); err != nil {
		t.Fatal(err)
	}
	// A substituted HTTPS response is deliberately untrusted. Even an executable
	// body must fail the fixed digest before any part of it can be evaluated.
	fake := `#!/bin/sh
while [ "$#" -gt 0 ]; do
 if [ "$1" = -o ]; then shift; printf '%s\n' '#!/bin/sh' 'touch "$TMPDIR/executed"' > "$1"; exit 0; fi
 shift
done
exit 1
`
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", "-x")
	command.Stdin = strings.NewReader(block)
	command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+temp)
	output, err := command.CombinedOutput()
	if err == nil || bytes.Contains(output, []byte(invite)) {
		t.Fatal("bad response executed or invitation was printed")
	}
	files, err := os.ReadDir(temp)
	if err != nil || len(files) != 0 {
		t.Fatal("failed download executed or left temporary material", err)
	}
	for _, base := range [][]string{nil, {"https://downloads.example/", "https://downloads.example/"}, {"http://downloads.example/"}, {"https://downloads.example/path?value=1"}, {"https://downloads.example/no-directory"}, {"https://downloads.example/%2F/"}} {
		if _, err := ShellInviteDelivery(base, artifact, invite); err == nil {
			t.Fatal("ambiguous public base accepted")
		}
	}
}

func TestShellInviteUsesAnotherVerifiedMirrorWithoutDuplicatingInvite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux shell execution boundary")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t, func(value *Invite) { value.Medium = "sh"; value.Responsibilities = []string{"access", "forward"} })
	bootstrap, err := server.bootstrapInvite("demo-enrollment")
	if err != nil {
		t.Fatal(err)
	}
	invite, err := EncodeInvite(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	script := []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$DEMO_ROOT/args\"\ncat > \"$DEMO_ROOT/invite\"\nprintf 'installed\\n' >> \"$DEMO_ROOT/calls\"\n")
	artifact := ReleaseArtifact{Name: "loom-bootstrap-linux.sh", Digest: ReleaseDigest(script), Size: U64(len(script)), MediaType: "text/x-shellscript", Audience: "public"}
	bases := []string{"https://b.example/", "https://a.example/"}
	block, err := ShellInviteDelivery(bases, artifact, invite)
	if err != nil || bases[0] != "https://b.example/" {
		t.Fatal("delivery mutated inputs", err)
	}
	for _, failure := range []string{"unreachable", "wrong-bytes"} {
		t.Run(failure, func(t *testing.T) {
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
printf '%s\n' "$address" >> "$DEMO_ROOT/downloads"
case "$address" in https://a.example/*)
 [ "$DEMO_FAILURE" != unreachable ] || exit 35
 printf 'exit 99\n' > "$output"; exit 0 ;;
esac
cp "$DEMO_ROOT/approved.sh" "$output"
`
			for name, body := range map[string][]byte{filepath.Join(bin, "curl"): []byte(fake), filepath.Join(root, "approved.sh"): script} {
				if err := os.WriteFile(name, body, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command("sh", "-x")
			command.Stdin = strings.NewReader(block)
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+temp, "DEMO_ROOT="+root, "DEMO_FAILURE="+failure)
			output, err := command.CombinedOutput()
			if err != nil || bytes.Contains(output, []byte(invite)) {
				t.Fatal("mirror delivery failed or exposed invitation", err)
			}
			for name, want := range map[string]string{"invite": invite + "\n", "args": "--base-url\nhttps://a.example/\n--base-url\nhttps://b.example/\n--invite-stdin\n", "calls": "installed\n", "downloads": "https://a.example/bin/" + strings.TrimPrefix(artifact.Digest, "sha256:") + "\nhttps://b.example/bin/" + strings.TrimPrefix(artifact.Digest, "sha256:") + "\n"} {
				body, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(body) != want {
					t.Fatal("delivery boundary mismatch:", name, err)
				}
			}
			if files, err := os.ReadDir(temp); err != nil || len(files) != 0 {
				t.Fatal("temporary delivery material retained", err)
			}
		})
	}
}
