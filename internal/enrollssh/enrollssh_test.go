package enrollssh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConnectionValidation(t *testing.T) {
	valid := []Connection{
		{Host: "demo-new-a", User: "loom-bootstrap", Port: 22},
		{Host: "node.example.net", User: "_loom", Port: 2222},
		{Host: "203.0.113.42", User: "root", Port: 1},
		{Host: "2001:db8::42", User: "ops.user", Port: 65535},
	}
	for _, connection := range valid {
		if err := connection.Validate(); err != nil {
			t.Errorf("Validate(%#v) = %v", connection, err)
		}
	}

	invalid := []Connection{
		{Host: "-oProxyCommand=id", User: "loom", Port: 22},
		{Host: "host.example;id", User: "loom", Port: 22},
		{Host: "host.example\nother", User: "loom", Port: 22},
		{Host: "ssh://host.example", User: "loom", Port: 22},
		{Host: "[2001:db8::1]", User: "loom", Port: 22},
		{Host: "999.1.1.1", User: "loom", Port: 22},
		{Host: "host.example", User: "-oProxyCommand", Port: 22},
		{Host: "host.example", User: "loom@evil", Port: 22},
		{Host: "host.example", User: "0root", Port: 22},
		{Host: "host.example", User: "loom", Port: 0},
		{Host: "host.example", User: "loom", Port: 65536},
	}
	for _, connection := range invalid {
		if err := connection.Validate(); err == nil {
			t.Errorf("Validate(%#v) unexpectedly succeeded", connection)
		}
	}
}

func TestCommandErrorExplainsLocalServiceInterruption(t *testing.T) {
	err := exec.Command("sh", "-c", "kill -TERM $$").Run()
	if err == nil {
		t.Fatal("self-terminated child unexpectedly succeeded")
	}
	got := commandError("SSH preflight", context.Background(), Result{}, err)
	for _, want := range []string{"SSH preflight", "local control service stopped or restarted", "retry"} {
		if got == nil || !strings.Contains(got.Error(), want) {
			t.Fatalf("interruption error %q is missing %q", got, want)
		}
	}
	if strings.Contains(got.Error(), "signal: terminated") {
		t.Fatalf("raw process signal leaked into operator copy: %v", got)
	}
}

func TestScannerUsesFixedArgvAndComputesOpenSSHFingerprint(t *testing.T) {
	encoded := testHostBlob(7)
	wantFingerprint := testFingerprint(encoded)
	var invocation Invocation
	runner := RunnerFunc(func(_ context.Context, got Invocation) (Result, error) {
		invocation = got
		return Result{Stdout: []byte("# banner\n[203.0.113.42]:2222 ssh-ed25519 " + encoded + " scanner-comment\n")}, nil
	})
	connection := Connection{Host: "203.0.113.42", User: "loom", Port: 2222}
	got, err := (Scanner{Runner: runner, Timeout: 1500 * time.Millisecond}).Scan(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{"-T", "2", "-p", "2222", "-t", "ed25519", "203.0.113.42"}
	if invocation.Program != "ssh-keyscan" || !reflect.DeepEqual(invocation.Args, wantArgs) {
		t.Fatalf("invocation = %q %#v, want ssh-keyscan %#v", invocation.Program, invocation.Args, wantArgs)
	}
	if len(invocation.Stdin) != 0 || invocation.StdoutLimit != defaultOutputLimit || invocation.StderrLimit != defaultOutputLimit {
		t.Fatalf("unexpected scan invocation bounds: %#v", invocation)
	}
	if got.Algorithm != "ssh-ed25519" || got.PublicKey != encoded || got.Fingerprint != wantFingerprint {
		t.Fatalf("host key = %#v", got)
	}
}

func TestScannerRejectsAmbiguousAndInvalidOutput(t *testing.T) {
	connection := Connection{Host: "host.example", User: "loom", Port: 22}
	for name, output := range map[string]string{
		"two keys":     "host ssh-ed25519 " + testHostBlob(1) + "\nhost ssh-ed25519 " + testHostBlob(2) + "\n",
		"no ed25519":   "host ssh-rsa AAAA\n",
		"invalid blob": "host ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte("not a wire key")) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			runner := RunnerFunc(func(context.Context, Invocation) (Result, error) {
				return Result{Stdout: []byte(output)}, nil
			})
			if _, err := (Scanner{Runner: runner}).Scan(context.Background(), connection); err == nil {
				t.Fatal("Scan unexpectedly accepted invalid output")
			}
		})
	}
}

func TestScannerRejectsConnectionBeforeRunner(t *testing.T) {
	called := false
	runner := RunnerFunc(func(context.Context, Invocation) (Result, error) {
		called = true
		return Result{}, nil
	})
	_, err := (Scanner{Runner: runner}).Scan(context.Background(), Connection{
		Host: "-oProxyCommand=touch /tmp/pwned", User: "loom", Port: 22,
	})
	if err == nil || called {
		t.Fatalf("Scan error=%v runnerCalled=%v", err, called)
	}
}

func TestConfirmKnownHostFailsClosedWhenKeyChanges(t *testing.T) {
	dir := secureSSHTestDir(t)
	path := filepath.Join(dir, "known_hosts")
	original := []byte("other.example ssh-ed25519 " + testHostBlob(3) + "\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	expected, err := hostKeyForBlob(testHostBlob(1))
	if err != nil {
		t.Fatal(err)
	}
	runner := RunnerFunc(func(context.Context, Invocation) (Result, error) {
		return Result{Stdout: []byte("host.example ssh-ed25519 " + testHostBlob(2) + "\n")}, nil
	})
	store := KnownHostsStore{Path: path, Scanner: Scanner{Runner: runner}}
	_, err = store.ConfirmKnownHost(context.Background(), Connection{Host: "host.example", User: "loom", Port: 22}, expected)
	if err == nil || !strings.Contains(err.Error(), "changed after confirmation") {
		t.Fatalf("ConfirmKnownHost error = %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("known_hosts changed on mismatch: %q", got)
	}
}

func TestConfirmKnownHostAtomicallyPreservesOtherEntries(t *testing.T) {
	dir := secureSSHTestDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	oldTarget := testHostBlob(4)
	other := testHostBlob(5)
	existing := "other.example ssh-ed25519 " + other + "\nhost.example ssh-ed25519 " + oldTarget + "\n"
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	confirmed, err := hostKeyForBlob(testHostBlob(6))
	if err != nil {
		t.Fatal(err)
	}
	runner := RunnerFunc(func(context.Context, Invocation) (Result, error) {
		return Result{Stdout: []byte("host.example ssh-ed25519 " + confirmed.PublicKey + "\n")}, nil
	})
	store := KnownHostsStore{Path: path, Scanner: Scanner{Runner: runner}}
	gotKey, err := store.ConfirmKnownHost(context.Background(), Connection{Host: "host.example", User: "loom", Port: 22}, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	if !sameHostKey(gotKey, confirmed) {
		t.Fatalf("committed key = %#v, want %#v", gotKey, confirmed)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"other.example ssh-ed25519 " + other,
		"host.example ssh-ed25519 " + confirmed.PublicKey,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("known_hosts missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, oldTarget) {
		t.Fatalf("old target key was retained:\n%s", text)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts mode = %v", info.Mode())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".loom-known-hosts-") {
			t.Fatalf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestAtomicMergeKnownHostsSerializesConcurrentWriters(t *testing.T) {
	dir := secureSSHTestDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	const writers = 24
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 1; i <= writers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			pattern := fmt.Sprintf("host-%d.example", i)
			errs <- atomicMergeKnownHosts(path, pattern, pattern+" ssh-ed25519 "+testHostBlob(byte(i)))
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePersistentKnownHosts(body); err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for i := 1; i <= writers; i++ {
		want := fmt.Sprintf("host-%d.example ssh-ed25519 %s\n", i, testHostBlob(byte(i)))
		if !strings.Contains(text, want) {
			t.Errorf("concurrent merge lost %q", strings.TrimSpace(want))
		}
	}
	assertFileMode(t, path+".lock", 0o600)
}

func TestAtomicMergeKnownHostsSerializesProcesses(t *testing.T) {
	if os.Getenv("LOOM_ENROLLSSH_MERGE_HELPER") == "1" {
		fill, err := strconv.Atoi(os.Getenv("LOOM_ENROLLSSH_MERGE_FILL"))
		if err != nil {
			t.Fatal(err)
		}
		path := os.Getenv("LOOM_ENROLLSSH_MERGE_PATH")
		pattern := fmt.Sprintf("process-%d.example", fill)
		if err := atomicMergeKnownHosts(path, pattern, pattern+" ssh-ed25519 "+testHostBlob(byte(fill))); err != nil {
			t.Fatal(err)
		}
		return
	}

	dir := secureSSHTestDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	const processes = 10
	type mergeProcess struct {
		cmd    *exec.Cmd
		output *bytes.Buffer
	}
	commands := make([]mergeProcess, 0, processes)
	for i := 1; i <= processes; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAtomicMergeKnownHostsSerializesProcesses$")
		cmd.Env = append(os.Environ(),
			"LOOM_ENROLLSSH_MERGE_HELPER=1",
			"LOOM_ENROLLSSH_MERGE_PATH="+path,
			"LOOM_ENROLLSSH_MERGE_FILL="+strconv.Itoa(i),
		)
		output := &bytes.Buffer{}
		cmd.Stdout = output
		cmd.Stderr = output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, mergeProcess{cmd: cmd, output: output})
	}
	for _, process := range commands {
		if err := process.cmd.Wait(); err != nil {
			t.Fatalf("merge subprocess failed: %v\n%s", err, process.output.Bytes())
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePersistentKnownHosts(body); err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for i := 1; i <= processes; i++ {
		want := fmt.Sprintf("process-%d.example ssh-ed25519 %s\n", i, testHostBlob(byte(i)))
		if !strings.Contains(text, want) {
			t.Errorf("cross-process merge lost %q", strings.TrimSpace(want))
		}
	}
}

func TestPersistentKnownHostsRejectsNonExactEntries(t *testing.T) {
	validKey := testHostBlob(11)
	for name, line := range map[string]string{
		"hashed":        "|1|hash|hash ssh-ed25519 " + validKey,
		"wildcard":      "*.example ssh-ed25519 " + validKey,
		"marker":        "@cert-authority host.example ssh-ed25519 " + validKey,
		"host list":     "host.example,alias.example ssh-ed25519 " + validKey,
		"other keytype": "host.example ssh-rsa " + validKey,
		"comment":       "# unmanaged entry",
	} {
		t.Run(name, func(t *testing.T) {
			dir := secureSSHTestDir(t)
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "known_hosts")
			if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readKnownHosts(path); err == nil {
				t.Fatalf("readKnownHosts accepted %q", line)
			}
		})
	}
}

func TestAtomicMergeKnownHostsRejectsSymlinkLock(t *testing.T) {
	dir := secureSSHTestDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "known_hosts")
	target := filepath.Join(dir, "unrelated")
	const untouched = "do not lock or modify\n"
	if err := os.WriteFile(target, []byte(untouched), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".lock"); err != nil {
		t.Fatal(err)
	}
	line := "host.example ssh-ed25519 " + testHostBlob(12)
	if err := atomicMergeKnownHosts(path, "host.example", line); err == nil || !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("atomicMergeKnownHosts error = %v, want lock-symlink rejection", err)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != untouched {
		t.Fatalf("lock symlink target changed: body=%q err=%v", body, err)
	}
}

func TestConfirmKnownHostRejectsSymlink(t *testing.T) {
	dir := secureSSHTestDir(t)
	target := filepath.Join(dir, "do-not-touch")
	path := filepath.Join(dir, "known_hosts")
	const untouched = "unrelated\n"
	if err := os.WriteFile(target, []byte(untouched), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	confirmed, err := hostKeyForBlob(testHostBlob(8))
	if err != nil {
		t.Fatal(err)
	}
	runner := RunnerFunc(func(context.Context, Invocation) (Result, error) {
		return Result{Stdout: []byte("host.example ssh-ed25519 " + confirmed.PublicKey + "\n")}, nil
	})
	_, err = ConfirmKnownHost(context.Background(), Scanner{Runner: runner}, path,
		Connection{Host: "host.example", User: "loom", Port: 22}, confirmed)
	if err == nil || !strings.Contains(err.Error(), "symlinks are not accepted") {
		t.Fatalf("ConfirmKnownHost error = %v", err)
	}
	body, readErr := os.ReadFile(target)
	if readErr != nil || string(body) != untouched {
		t.Fatalf("symlink target changed: body=%q err=%v", body, readErr)
	}
}

func TestPreflightUsesHardenedSSHArgvAndParsesOutput(t *testing.T) {
	privateKey, knownHosts := secureTestFiles(t)
	connection := Connection{Host: "203.0.113.42", User: "loom-bootstrap", Port: 2222}
	var invocation Invocation
	runner := RunnerFunc(func(_ context.Context, got Invocation) (Result, error) {
		invocation = got
		return Result{Stdout: []byte(strings.Join([]string{
			"LOOM_PREFLIGHT_V1",
			"hostname=demo-new-a",
			"uname=Linux 6.8.0 x86_64 GNU/Linux",
			"kernel_wireguard=1",
			"wg_command=1",
			"privilege=sudo-nopasswd",
			"ssh_server=192.0.2.18",
			"",
		}, "\n"))}, nil
	})
	client := Client{
		Runner: runner, PrivateKeyPath: privateKey, KnownHostsPath: knownHosts,
		Timeout: 2 * time.Second, ConnectTimeout: 7 * time.Second,
	}
	got, err := client.Preflight(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	want := PreflightResult{
		Hostname:                 "demo-new-a",
		Uname:                    "Linux 6.8.0 x86_64 GNU/Linux",
		KernelWireGuard:          true,
		WGCommand:                true,
		Privilege:                PrivilegeSudo,
		ObservedSSHServerAddress: "192.0.2.18",
	}
	if got != want {
		t.Fatalf("Preflight = %#v, want %#v", got, want)
	}
	assertSSHInvocation(t, invocation, client, connection, PreflightScript, "7")
	if strings.Contains(PreflightScript, connection.Host) || strings.Contains(PreflightScript, connection.User) {
		t.Fatal("operator value was copied into fixed preflight script")
	}
}

func TestEnsureWireGuardToolsUsesFixedIdempotentInstaller(t *testing.T) {
	syntax := exec.Command("/bin/sh", "-n")
	syntax.Stdin = strings.NewReader(InstallWireGuardToolsScript)
	if output, err := syntax.CombinedOutput(); err != nil {
		t.Fatalf("fixed installer shell syntax: %v: %s", err, output)
	}
	privateKey, knownHosts := secureTestFiles(t)
	connection := Connection{Host: "203.0.113.42", User: "loom-bootstrap", Port: 2222}
	var invocation Invocation
	runner := RunnerFunc(func(_ context.Context, got Invocation) (Result, error) {
		invocation = got
		return Result{Stdout: []byte("LOOM_WG_TOOLS_V1\ninstalled=1\n")}, nil
	})
	client := Client{
		Runner: runner, PrivateKeyPath: privateKey, KnownHostsPath: knownHosts,
		InstallTimeout: 2 * time.Second, ConnectTimeout: 7 * time.Second,
	}
	installed, err := client.EnsureWireGuardTools(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("EnsureWireGuardTools did not report the performed installation")
	}
	assertSSHInvocation(t, invocation, client, connection, InstallWireGuardToolsScript, "7")
	for _, want := range []string{"/usr/bin/wg", "wireguard-tools", "apt-get", "dnf", "apk", "sudo -n"} {
		if !strings.Contains(InstallWireGuardToolsScript, want) {
			t.Errorf("fixed installer is missing %q", want)
		}
	}
	if strings.Contains(InstallWireGuardToolsScript, connection.Host) || strings.Contains(InstallWireGuardToolsScript, connection.User) {
		t.Fatal("operator value was copied into the fixed package installer")
	}
}

func TestWireGuardToolsInstallOutputIsStrict(t *testing.T) {
	for name, output := range map[string]string{
		"already present": "LOOM_WG_TOOLS_V1\ninstalled=0\n",
		"installed":       "LOOM_WG_TOOLS_V1\ninstalled=1\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseWireGuardToolsInstall([]byte(output))
			if err != nil {
				t.Fatal(err)
			}
			if got != (name == "installed") {
				t.Fatalf("parsed installed=%v", got)
			}
		})
	}
	for _, output := range []string{
		"LOOM_WG_TOOLS_V1\ninstalled=1\nwarning\n",
		"LOOM_WG_TOOLS_V1\ninstalled=yes\n",
		"package output\nLOOM_WG_TOOLS_V1\ninstalled=1\n",
	} {
		if _, err := parseWireGuardToolsInstall([]byte(output)); err == nil {
			t.Fatalf("accepted invalid installer output %q", output)
		}
	}
}

func TestPrepareWGUsesFixedScriptAndReturnsOnlyAuthenticatedFacts(t *testing.T) {
	privateKey, knownHosts := secureTestFiles(t)
	connection := Connection{Host: "node.example", User: "loom", Port: 22}
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	var invocation Invocation
	runner := RunnerFunc(func(_ context.Context, got Invocation) (Result, error) {
		invocation = got
		return Result{Stdout: []byte("LOOM_WG_PREPARE_V1\nhostname=demo-new-a\nssh_server=192.0.2.18\npublic_key=" + public + "\n")}, nil
	})
	client := Client{Runner: runner, PrivateKeyPath: privateKey, KnownHostsPath: knownHosts}
	got, err := client.PrepareWG(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	want := PrepareWGResult{Hostname: "demo-new-a", ObservedSSHServerAddress: "192.0.2.18", PublicKey: public}
	if got != want {
		t.Fatalf("PrepareWG = %#v, want %#v", got, want)
	}
	assertSSHInvocation(t, invocation, client, connection, PrepareWGScript, "10")
	if strings.Contains(PrepareWGScript, connection.Host) || strings.Contains(PrepareWGScript, connection.User) ||
		strings.Contains(PrepareWGScript, "node.key)") {
		t.Fatal("unexpected dynamic or private-key output in PrepareWG script")
	}
	if strings.Contains(string(invocation.Stdin), "cat \"$key\"") {
		t.Fatal("PrepareWG script prints the private key")
	}
}

func TestPrepareWGRejectsExtraOrPrivateOutput(t *testing.T) {
	privateKey, knownHosts := secureTestFiles(t)
	connection := Connection{Host: "node.example", User: "loom", Port: 22}
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	for name, output := range map[string]string{
		"extra line":       "warning\n" + public + "\n",
		"private key text": "not-base64-private-material\n",
	} {
		t.Run(name, func(t *testing.T) {
			runner := RunnerFunc(func(context.Context, Invocation) (Result, error) {
				return Result{Stdout: []byte(output)}, nil
			})
			client := Client{Runner: runner, PrivateKeyPath: privateKey, KnownHostsPath: knownHosts}
			if got, err := client.PrepareWG(context.Background(), connection); err == nil {
				t.Fatalf("PrepareWG accepted %q as %#v", output, got)
			}
		})
	}
}

func TestSecureSSHInputRequiresExactModeOwnerAndSafeParents(t *testing.T) {
	t.Run("mode", func(t *testing.T) {
		path, _ := secureTestFiles(t)
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := validateSecureInputFile(path, "SSH private key"); err == nil || !strings.Contains(err.Error(), "require exactly 0600") {
			t.Fatalf("validation error = %v, want exact-mode rejection", err)
		}
	})

	t.Run("writable parent", func(t *testing.T) {
		root := secureSSHTestDir(t)
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		parent := filepath.Join(root, "unsafe")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "bootstrap")
		if err := os.WriteFile(path, []byte("identity"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := validateSecureInputFile(path, "SSH private key"); err == nil || !strings.Contains(err.Error(), "group/world writable") {
			t.Fatalf("validation error = %v, want writable-parent rejection", err)
		}
	})

	t.Run("symlinked parent", func(t *testing.T) {
		root := secureSSHTestDir(t)
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		realParent := filepath.Join(root, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(realParent, "bootstrap")
		if err := os.WriteFile(path, []byte("identity"), 0o600); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(root, "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		if err := validateSecureInputFile(filepath.Join(linkedParent, "bootstrap"), "SSH private key"); err == nil || !strings.Contains(err.Error(), "not a symlink") {
			t.Fatalf("validation error = %v, want parent-symlink rejection", err)
		}
		unclean := realParent + "/../real/bootstrap"
		if err := validateSecureInputFile(unclean, "SSH private key"); err == nil || !strings.Contains(err.Error(), "path must be clean") {
			t.Fatalf("validation error = %v, want unclean-path rejection", err)
		}
	})

	if os.Geteuid() == 0 {
		t.Run("owner", func(t *testing.T) {
			path, _ := secureTestFiles(t)
			if err := os.Chown(path, 65534, -1); err != nil {
				t.Fatal(err)
			}
			if err := validateSecureInputFile(path, "SSH private key"); err == nil || !strings.Contains(err.Error(), "require current euid") {
				t.Fatalf("validation error = %v, want owner rejection", err)
			}
		})
	}
}

func TestPreflightRejectsInvalidObservedEndpointAndFields(t *testing.T) {
	for name, output := range map[string]string{
		"DNS is not SSH_CONNECTION address": "LOOM_PREFLIGHT_V1\nhostname=demo-new-a\nuname=Linux\nkernel_wireguard=1\nwg_command=1\nprivilege=root\nssh_server=edge.example\n",
		"duplicate":                         "LOOM_PREFLIGHT_V1\nhostname=demo-new-a\nhostname=demo-new-b\nuname=Linux\nkernel_wireguard=1\nwg_command=1\nprivilege=root\nssh_server=192.0.2.1\n",
		"unknown field":                     "LOOM_PREFLIGHT_V1\nhostname=demo-new-a\nuname=Linux\nkernel_wireguard=1\nwg_command=1\nprivilege=root\nssh_server=192.0.2.1\ndirection=bidirectional\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePreflight([]byte(output)); err == nil {
				t.Fatal("parsePreflight unexpectedly accepted invalid output")
			}
		})
	}
}

func TestCommandsHonorContextAndOutputLimits(t *testing.T) {
	connection := Connection{Host: "host.example", User: "loom", Port: 22}
	runner := RunnerFunc(func(ctx context.Context, _ Invocation) (Result, error) {
		<-ctx.Done()
		return Result{}, ctx.Err()
	})
	_, err := (Scanner{Runner: runner, Timeout: 5 * time.Millisecond}).Scan(context.Background(), connection)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Scan error = %v, want deadline exceeded", err)
	}

	result, err := (ExecRunner{}).Run(context.Background(), Invocation{
		Program: "printf", Args: []string{"12345"}, StdoutLimit: 4, StderrLimit: 4,
	})
	if err == nil || !result.StdoutTruncated || string(result.Stdout) != "1234" {
		t.Fatalf("bounded command result=%#v err=%v", result, err)
	}
}

func assertSSHInvocation(t *testing.T, got Invocation, client Client, connection Connection, script, connectSeconds string) {
	t.Helper()
	if got.Program != "ssh" {
		t.Fatalf("program = %q", got.Program)
	}
	want := []string{
		"-F", "/dev/null",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "HostKeyAlgorithms=ssh-ed25519",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=" + client.KnownHostsPath,
		"-o", "UpdateHostKeys=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "RequestTTY=no",
		"-o", "ConnectTimeout=" + connectSeconds,
		"-i", client.PrivateKeyPath,
		"-p", stringPort(connection.Port),
		"--", connection.User + "@" + connection.Host,
		"/bin/sh", "-s", "--",
	}
	if !reflect.DeepEqual(got.Args, want) {
		t.Fatalf("ssh args:\n got %#v\nwant %#v", got.Args, want)
	}
	if !bytes.Equal(got.Stdin, []byte(script)) {
		t.Fatal("SSH stdin is not the fixed remote script constant")
	}
	for i := 0; i+1 < len(got.Args); i++ {
		if (got.Args[i] == "sh" || got.Args[i] == "/bin/sh") && got.Args[i+1] == "-c" {
			t.Fatal("SSH command invokes sh -c")
		}
	}
}

func secureTestFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := secureSSHTestDir(t)
	privateKey := filepath.Join(dir, "bootstrap")
	knownHosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(privateKey, []byte("test identity placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("host.example ssh-ed25519 "+testHostBlob(9)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return privateKey, knownHosts
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != want {
		t.Fatalf("%s mode = %v, want regular %04o", path, info.Mode(), want)
	}
}

func secureSSHTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// /tmp itself is shared and is not a valid direct parent. The private
	// per-test child is the owner-controlled security boundary.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testHostBlob(fill byte) string {
	var blob bytes.Buffer
	writeWireString(&blob, []byte("ssh-ed25519"))
	writeWireString(&blob, bytes.Repeat([]byte{fill}, 32))
	return base64.StdEncoding.EncodeToString(blob.Bytes())
}

func writeWireString(out *bytes.Buffer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	out.Write(length[:])
	out.Write(value)
}

func testFingerprint(encoded string) string {
	blob, _ := base64.StdEncoding.DecodeString(encoded)
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func stringPort(port int) string {
	const digits = "0123456789"
	if port == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for port > 0 {
		i--
		buf[i] = digits[port%10]
		port /= 10
	}
	return string(buf[i:])
}
