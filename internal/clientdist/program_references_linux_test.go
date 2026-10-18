package clientdist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestReplacedProgramsRetainReferencesAndUnknownReads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership contract")
	}
	for _, source := range []string{"process-inode", "inactive-unit-symlink", "unknown"} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			manifest := Manifest{}
			for _, component := range []*Component{&manifest.Loom, &manifest.SingBox} {
				name := "loom"
				if component == &manifest.SingBox {
					name = "sing-box"
				}
				body := []byte("demo executable " + name)
				if err := installFile(filepath.Join(root, name), body, 0o755); err != nil {
					t.Fatal(err)
				}
				*component = Component{Path: name, SHA256: sha256Hex(body)}
			}
			path := filepath.Join(root, "loom")
			read := func(context.Context) ([]programReference, error) {
				switch source {
				case "process-inode":
					identity, err := os.Stat(path)
					return []programReference{{identity: identity}}, err
				case "inactive-unit-symlink":
					alias := filepath.Join(root, "demo-control")
					if err := os.Symlink(path, alias); err != nil {
						return nil, err
					}
					return []programReference{{path: alias}}, nil
				default:
					return nil, os.ErrPermission
				}
			}
			err := removeReplacedProgramsWithReferences(root, manifest, read)
			if (err != nil) != (source == "unknown") {
				t.Fatal("unknown reference read was not reported", err)
			}
			body, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(body, []byte("demo executable loom")) {
				t.Fatal("referenced or unverifiable executable changed", err)
			}
			_, err = os.Stat(filepath.Join(root, "sing-box"))
			if source == "unknown" && err != nil || source != "unknown" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unreferenced cleanup did not respect the verification result", err)
			}
		})
	}
}

func TestManagedUnitReferencesIncludeDisabledAndInactive(t *testing.T) {
	ctx := context.Background()
	run := func(_ context.Context, program string, args ...string) ([]byte, error) {
		if program != "systemctl" {
			t.Fatal("unexpected command")
		}
		switch args[0] {
		case "list-unit-files":
			return []byte("loom-control.service disabled disabled\nloom-client.service enabled enabled\n"), nil
		case "list-units":
			if !strings.Contains(strings.Join(args, " "), "--all") {
				t.Fatal("inactive units omitted")
			}
			return []byte("loom-client.service loaded inactive dead Demo\nloom-demo-transient.service loaded inactive dead Demo\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
	units, err := managedServiceUnits(ctx, run)
	if err != nil || !reflect.DeepEqual(units, []string{"loom-client.service", "loom-control.service", "loom-demo-transient.service"}) {
		t.Fatal("not all managed execution definitions were considered", units, err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "demo-loom")
	alias := filepath.Join(root, "demo-current")
	if err := os.WriteFile(path, []byte("demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	var calls int
	references, err := serviceProgramReferences(ctx, "loom-control.service", func(_ context.Context, program string, args ...string) ([]byte, error) {
		calls++
		if program == "systemctl" {
			if !reflect.DeepEqual(args, []string{"show", "loom-control.service", "--property=Id", "--value"}) {
				t.Fatal("unexpected unit identity read")
			}
			return []byte("loom-control.service\n"), nil
		}
		if program != "busctl" || args[4] != "/org/freedesktop/systemd1/unit/loom_2dcontrol_2eservice" || !reflect.DeepEqual(args[6:], executionProperties) {
			t.Fatal("execution read did not use explicit typed properties", program, args)
		}
		return executionFixture(t, alias, []string{alias, "control", "serve"}), nil
	})
	if err != nil || calls != 2 {
		t.Fatal(err)
	}
	if found, err := referencesProgram(path, references); err != nil || !found {
		t.Fatal("disabled unit symlink execution reference was lost", err)
	}
	if _, err := decodeExecutionReferences(executionFixture(t, "/bin/sh", []string{"sh", "-c", "exec /opt/demo/loom"})); err == nil {
		t.Fatal("opaque shell execution was treated as proof of no reference")
	}
	if _, err := decodeExecutionReferences([]byte("{}\n")); err == nil {
		t.Fatal("unknown execution representation was accepted")
	}
}

func executionFixture(t *testing.T, path string, arguments []string) []byte {
	t.Helper()
	return executionPropertyFixture(t, "ExecStart", path, arguments)
}

func executionPropertyFixture(t *testing.T, name, path string, arguments []string) []byte {
	t.Helper()
	var body bytes.Buffer
	for _, property := range executionProperties {
		rows := [][]any{}
		if property == name {
			rows = append(rows, []any{path, arguments, false, 0, 0, 0, 0, 0, 0, 0})
		}
		if err := json.NewEncoder(&body).Encode(map[string]any{"type": "a(sasbttttuii)", "data": rows}); err != nil {
			t.Fatal(err)
		}
	}
	return body.Bytes()
}

func TestManagedReloadReferencesAllowOnlyExactClientPID(t *testing.T) {
	for _, test := range []struct {
		name, property, executable string
		arguments                  []string
		accepted                   bool
	}{
		{"client-reload", "ExecReload", "/bin/kill", []string{"/bin/kill", "-HUP", "$MAINPID"}, true},
		{"start", "ExecStart", "/bin/kill", []string{"/bin/kill", "-HUP", "$MAINPID"}, false},
		{"another-program", "ExecReload", "/opt/demo/loom", []string{"/opt/demo/loom", "-HUP", "$MAINPID"}, false},
		{"another-kill-path", "ExecReload", "/usr/bin/kill", []string{"/usr/bin/kill", "-HUP", "$MAINPID"}, false},
		{"another-signal", "ExecReload", "/bin/kill", []string{"/bin/kill", "-TERM", "$MAINPID"}, false},
		{"another-argv-zero", "ExecReload", "/bin/kill", []string{"kill", "-HUP", "$MAINPID"}, false},
		{"another-argument", "ExecReload", "/bin/kill", []string{"/bin/kill", "-HUP", "$MAINPID", "/opt/demo/loom"}, false},
		{"another-variable", "ExecReload", "/bin/kill", []string{"/bin/kill", "-HUP", "$OTHERPID"}, false},
		{"embedded-variable", "ExecReload", "/bin/kill", []string{"/bin/kill", "-HUP", "${MAINPID}"}, false},
		{"specifier", "ExecReload", "/bin/kill", []string{"/bin/kill", "-HUP", "%i"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			references, err := decodeExecutionReferences(executionPropertyFixture(t, test.property, test.executable, test.arguments))
			if (err == nil) != test.accepted {
				t.Fatalf("accepted=%v, want %v: %v", err == nil, test.accepted, err)
			}
			if test.accepted {
				if len(references) == 0 {
					t.Fatal("reload executable reference was lost")
				}
				for _, reference := range references {
					if reference.path != "/bin/kill" {
						t.Fatal("PID substitution became a program reference")
					}
				}
			}
		})
	}
}

func TestProcessReferenceReadUsesInodeAndRejectsUnknown(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "demo-program")
	if err := os.WriteFile(program, []byte("demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1", "2", "3", "4"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(program, filepath.Join(root, "1", "exe")); err != nil {
		t.Fatal(err)
	}
	for name, status := range map[string]string{"2": "Kthread:\t1\n", "3": "State:\tZ (zombie)\nThreads:\t1\n", "4": "State:\tS (sleeping)\nThreads:\t1\n"} {
		if err := os.WriteFile(filepath.Join(root, name, "status"), []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, stat := range map[string][]byte{
		"3": processStatFixture("3", "demo", "Z", "0", "1"),
		"4": processStatFixture("4", "demo) worker", "S", "2097152", "1"),
	} {
		if err := os.WriteFile(filepath.Join(root, name, "stat"), stat, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "3", "task", "3"), 0o700); err != nil {
		t.Fatal(err)
	}
	references, err := processProgramReferences(root)
	if err != nil || len(references) != 1 {
		t.Fatal("process executable observation failed", err)
	}
	if found, err := referencesProgram(program, references); err != nil || !found {
		t.Fatal("actual executable inode was not retained", err)
	}
	if err := os.WriteFile(filepath.Join(root, "3", "status"), []byte("State:\tS (sleeping)\nKthread:\t0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := processProgramReferences(root); err == nil {
		t.Fatal("unknown live process executable was ignored")
	}
}

func processStatFixture(pid, comm, state, flags, threads string) []byte {
	fields := []string{state, "0", "0", "0", "0", "-1", flags, "0", "0", "0", "0", "0", "0", "0", "0", "20", "0", threads, "0", "1"}
	return []byte(pid + " (" + comm + ") " + strings.Join(fields, " ") + "\n")
}

func TestProcessReferenceReadRetainsUnknownExecutableGroups(t *testing.T) {
	for _, test := range []struct {
		name, status string
		stat         []byte
		tasks        []string
	}{
		{"user-named-kernel-thread", "Name:\tkthreadd\nState:\tS (sleeping)\nPPid:\t0\nThreads:\t1\n", processStatFixture("2", "kthreadd", "S", "4194304", "1"), []string{"2"}},
		{"zombie-leader-live-group", "State:\tZ (zombie)\nThreads:\t2\n", processStatFixture("2", "demo", "Z", "0", "2"), []string{"2", "3"}},
		{"dead-leader-live-group", "State:\tX (dead)\nThreads:\t2\n", processStatFixture("2", "demo", "X", "0", "2"), []string{"2", "3"}},
		{"malformed-flags", "State:\tS (sleeping)\n", processStatFixture("2", "demo", "S", "invalid", "1"), nil},
		{"truncated-stat", "State:\tS (sleeping)\n", []byte("2 (demo) S 0 0 0 0 -1 2097152\n"), nil},
		{"different-pid", "State:\tS (sleeping)\n", processStatFixture("3", "demo", "S", "2097152", "1"), nil},
		{"missing-task-evidence", "State:\tZ (zombie)\nThreads:\t1\n", processStatFixture("2", "demo", "Z", "0", "1"), nil},
		{"unexpected-task", "State:\tZ (zombie)\nThreads:\t1\n", processStatFixture("2", "demo", "Z", "0", "1"), []string{"3"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			process := filepath.Join(root, "2")
			if err := os.Mkdir(process, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string][]byte{"status": []byte(test.status), "stat": test.stat} {
				if err := os.WriteFile(filepath.Join(process, name), body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, tid := range test.tasks {
				if err := os.MkdirAll(filepath.Join(process, "task", tid), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := processProgramReferences(root); err == nil {
				t.Fatal("unknown user executable group was ignored")
			}
		})
	}
}

func TestProcessReferenceReadRejectsPermissionDenied(t *testing.T) {
	const fixtureEnvironment = "LOOM_TEST_PROCESS_REFERENCE_ROOT"
	if root := os.Getenv(fixtureEnvironment); root != "" {
		if _, err := os.Stat(filepath.Join(root, "2", "exe")); !errors.Is(err, os.ErrPermission) {
			t.Fatal("fixture executable was not permission denied", err)
		}
		if _, err := processProgramReferences(root); err == nil {
			t.Fatal("permission-denied executable was ignored")
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires a distinct unprivileged process")
	}
	// This permission test needs a directory reachable by another UID,
	// independently of a private TMPDIR used by the surrounding test run.
	root, err := os.MkdirTemp("/tmp", "loom-process-reference-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Mkdir(filepath.Join(root, "2"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "2")} {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(root, "private", "demo-program")
	if err := os.WriteFile(program, []byte("demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(program, filepath.Join(root, "2", "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "2", "status"), []byte("Kthread:\t1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "2", "status"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Go's temporary build directory is private to the test user. Give the
	// unprivileged child an executable copy inside this disposable fixture.
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(root, "demo-reference-test")
	if err := os.WriteFile(child, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(child, 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(child, "-test.run=^TestProcessReferenceReadRejectsPermissionDenied$")
	command.Env = []string{fixtureEnvironment + "=" + root}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
	if body, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged reference read failed: %v\n%s", err, body)
	}
}
