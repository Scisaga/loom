package clientdist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	var body bytes.Buffer
	for _, property := range executionProperties {
		rows := [][]any{}
		if property == "ExecStart" {
			rows = append(rows, []any{path, arguments, false, 0, 0, 0, 0, 0, 0, 0})
		}
		if err := json.NewEncoder(&body).Encode(map[string]any{"type": "a(sasbttttuii)", "data": rows}); err != nil {
			t.Fatal(err)
		}
	}
	return body.Bytes()
}

func TestProcessReferenceReadUsesInodeAndRejectsUnknown(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "demo-program")
	if err := os.WriteFile(program, []byte("demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1", "2", "3"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(program, filepath.Join(root, "1", "exe")); err != nil {
		t.Fatal(err)
	}
	for name, status := range map[string]string{"2": "Kthread:\t1\n", "3": "State:\tZ (zombie)\n"} {
		if err := os.WriteFile(filepath.Join(root, name, "status"), []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
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
