package enrollkey

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStatusAbsent(t *testing.T) {
	m := Manager{PrivatePath: filepath.Join(secureTempDir(t), "nested", "bootstrap")}
	got, err := m.Status()
	if err != nil {
		t.Fatal(err)
	}
	if got.Ready {
		t.Fatal("absent identity reported ready")
	}
	if got.PrivatePath != m.PrivatePath || got.PublicPath != m.PrivatePath+".pub" {
		t.Fatalf("unexpected paths: %#v", got)
	}
	if got.PublicOpenSSH != "" || got.Fingerprint != "" {
		t.Fatalf("absent identity exposed public state: %#v", got)
	}
}

func TestEnsureReusesIdentityAndRejectsUnsafePrivatePermissions(t *testing.T) {
	m := Manager{PrivatePath: filepath.Join(secureTempDir(t), "keys", "bootstrap")}
	first, err := m.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	privateBefore, err := os.ReadFile(m.PrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Ready || !strings.HasPrefix(first.PublicOpenSSH, "ssh-ed25519 ") ||
		!strings.HasSuffix(first.PublicOpenSSH, " "+publicComment) ||
		!strings.HasPrefix(first.Fingerprint, "SHA256:") {
		t.Fatalf("unexpected initial status: %#v", first)
	}

	if err := os.Chmod(m.PrivatePath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(m.publicPath(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(); err == nil || !strings.Contains(err.Error(), "require exactly 0600") {
		t.Fatalf("Ensure error = %v, want strict private-key mode rejection", err)
	}
	if _, err := m.Status(); err == nil || !strings.Contains(err.Error(), "require exactly 0600") {
		t.Fatalf("Status error = %v, want strict private-key mode rejection", err)
	}
	if _, err := m.PublicOpenSSH(); err == nil || !strings.Contains(err.Error(), "require exactly 0600") {
		t.Fatalf("PublicOpenSSH error = %v, want strict private-key mode rejection", err)
	}
	if err := os.Chmod(m.PrivatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := m.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	privateAfter, err := os.ReadFile(m.PrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateBefore, privateAfter) {
		t.Fatal("Ensure replaced an existing private identity")
	}
	if first.PublicOpenSSH != second.PublicOpenSSH || first.Fingerprint != second.Fingerprint {
		t.Fatalf("identity changed: first=%#v second=%#v", first, second)
	}
	assertMode(t, m.PrivatePath, 0o600)
	assertMode(t, m.publicPath(), 0o644)

	public, err := m.PublicOpenSSH()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := m.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	status, err := m.Status()
	if err != nil {
		t.Fatal(err)
	}
	if public != first.PublicOpenSSH || fingerprint != first.Fingerprint || status != second {
		t.Fatalf("public APIs disagree: public=%q fingerprint=%q status=%#v", public, fingerprint, status)
	}
}

func TestEnsureConcurrentCallersShareOneIdentity(t *testing.T) {
	m := Manager{PrivatePath: filepath.Join(secureTempDir(t), "bootstrap")}
	const callers = 32
	start := make(chan struct{})
	results := make(chan Status, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status, err := m.Ensure()
			results <- status
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var want Status
	for got := range results {
		if want == (Status{}) {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("concurrent callers observed different identities:\nwant %#v\n got %#v", want, got)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(m.PrivatePath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".loom-bootstrap-") {
			t.Fatalf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestEnsureFailsClosedOnCorruptPrivateKey(t *testing.T) {
	dir := secureTempDir(t)
	m := Manager{PrivatePath: filepath.Join(dir, "bootstrap")}
	corrupt := []byte("definitely not an OpenSSH private key\n")
	if err := os.WriteFile(m.PrivatePath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.publicPath(), []byte("stale public key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(); err == nil || !strings.Contains(err.Error(), "invalid bootstrap private key") {
		t.Fatalf("Ensure error = %v, want invalid private key", err)
	}
	if _, err := m.Status(); err == nil {
		t.Fatal("Status accepted a corrupt private key")
	}
	got, err := os.ReadFile(m.PrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, corrupt) {
		t.Fatal("corrupt private key was silently replaced")
	}
}

func TestEnsureRecoversMissingAndMismatchedPublicKey(t *testing.T) {
	m := Manager{PrivatePath: filepath.Join(secureTempDir(t), "bootstrap")}
	initial, err := m.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	want := initial.PublicOpenSSH + "\n"

	if err := os.Remove(m.publicPath()); err != nil {
		t.Fatal(err)
	}
	recovered, err := m.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, m.publicPath(), want)
	if recovered.Fingerprint != initial.Fingerprint {
		t.Fatal("fingerprint changed while recovering a missing public key")
	}

	if err := os.WriteFile(m.publicPath(), []byte("ssh-ed25519 AAAA wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err = m.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, m.publicPath(), want)
	assertMode(t, m.publicPath(), 0o644)
	if recovered.PublicOpenSSH != initial.PublicOpenSSH || recovered.Fingerprint != initial.Fingerprint {
		t.Fatal("identity changed while recovering a mismatched public key")
	}
}

func TestEnsureReplacesPublicKeySymlinkWithoutFollowingIt(t *testing.T) {
	dir := secureTempDir(t)
	m := Manager{PrivatePath: filepath.Join(dir, "bootstrap")}
	status, err := m.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "unrelated")
	const untouched = "do not change me\n"
	if err := os.WriteFile(target, []byte(untouched), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.publicPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, m.publicPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(); err != nil {
		t.Fatal(err)
	}
	assertFile(t, target, untouched)
	assertFile(t, m.publicPath(), status.PublicOpenSSH+"\n")
	if info, err := os.Lstat(m.publicPath()); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("public key was not restored as a regular file: info=%v err=%v", info, err)
	}
}

func TestOpenSSHCompatibility(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("ssh-keygen is unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	m := Manager{PrivatePath: filepath.Join(secureTempDir(t), "bootstrap")}
	status, err := m.Ensure()
	if err != nil {
		t.Fatal(err)
	}

	output, err := exec.Command(sshKeygen, "-y", "-f", m.PrivatePath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen could not read private key: %v\n%s", err, output)
	}
	wantFields := strings.Fields(status.PublicOpenSSH)
	gotFields := strings.Fields(string(output))
	if len(gotFields) < 2 || gotFields[0] != wantFields[0] || gotFields[1] != wantFields[1] {
		t.Fatalf("ssh-keygen public key = %q, want %q", output, status.PublicOpenSSH)
	}

	output, err = exec.Command(sshKeygen, "-l", "-E", "sha256", "-f", m.PrivatePath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen could not fingerprint private key: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), status.Fingerprint) {
		t.Fatalf("ssh-keygen fingerprint = %q, want it to contain %q", output, status.Fingerprint)
	}
}

func TestManagerRejectsWritableAndSymlinkedParents(t *testing.T) {
	root := secureTempDir(t)
	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		run  func(Manager) error
	}{
		{name: "Status", run: func(m Manager) error { _, err := m.Status(); return err }},
		{name: "Ensure", run: func(m Manager) error { _, err := m.Ensure(); return err }},
	} {
		t.Run("writable/"+operation.name, func(t *testing.T) {
			err := operation.run(Manager{PrivatePath: filepath.Join(writable, "bootstrap")})
			if err == nil || !strings.Contains(err.Error(), "group/world writable") {
				t.Fatalf("error = %v, want writable-parent rejection", err)
			}
		})
	}

	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := (Manager{PrivatePath: filepath.Join(linkedParent, "bootstrap")}).Ensure(); err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("Ensure error = %v, want parent-symlink rejection", err)
	}

	shared := filepath.Join(root, "shared-sticky")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, err := (Manager{PrivatePath: filepath.Join(shared, "direct-key")}).Status(); err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("Status error = %v, want shared sticky direct-parent rejection", err)
	}
	protected := filepath.Join(shared, "owned-private")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := (Manager{PrivatePath: filepath.Join(protected, "bootstrap")}).Ensure(); err != nil {
		t.Fatalf("secure child beneath sticky ancestor was rejected: %v", err)
	}
}

func TestManagerRejectsPrivateKeyOwnedByAnotherUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing file ownership requires root")
	}
	m := Manager{PrivatePath: filepath.Join(secureTempDir(t), "bootstrap")}
	if _, err := m.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(m.PrivatePath, 65534, -1); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{name: "Status", run: func() error { _, err := m.Status(); return err }},
		{name: "Ensure", run: func() error { _, err := m.Ensure(); return err }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); err == nil || !strings.Contains(err.Error(), "require current euid") {
				t.Fatalf("error = %v, want owner rejection", err)
			}
		})
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// t.TempDir normally has this mode already. Set it explicitly because /tmp
	// itself is a shared sticky directory, not a safe direct key parent.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
