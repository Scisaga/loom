package clientdist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// References are a fresh, disposable observation, never installation authority.
// A process contributes its actual executable inode; a unit contributes all
// execution properties even when disabled or inactive.
type programReference struct {
	path     string
	identity os.FileInfo
}

func referencesProgram(path string, references []programReference) (bool, error) {
	identity, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	for _, reference := range references {
		if reference.identity != nil && os.SameFile(identity, reference.identity) {
			return true, nil
		}
		if reference.path == "" {
			continue
		}
		if reference.path == path {
			return true, nil
		}
		actual, err := os.Stat(reference.path) // follows ExecStart symlinks
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if os.SameFile(identity, actual) {
			return true, nil
		}
	}
	return false, nil
}

func installedProgramReferences(ctx context.Context) ([]programReference, error) {
	references, err := processProgramReferences("/proc")
	if err != nil {
		return nil, err
	}
	units, err := managedServiceUnits(ctx, referenceCommand)
	if err != nil {
		return nil, err
	}
	for _, unit := range units {
		unitReferences, err := serviceProgramReferences(ctx, unit, referenceCommand)
		if err != nil {
			return nil, err
		}
		references = append(references, unitReferences...)
	}
	return references, nil
}

func processProgramReferences(root string) ([]programReference, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var references []programReference
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil || !entry.IsDir() {
			continue
		}
		process := filepath.Join(root, entry.Name())
		identity, err := os.Stat(filepath.Join(process, "exe"))
		if err == nil {
			references = append(references, programReference{identity: identity})
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("a process executable is unreadable")
		}
		// An exited process, zombie or kernel thread has no user executable.
		status, readErr := os.ReadFile(filepath.Join(process, "status"))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil || !processWithoutExecutable(status) {
			return nil, errors.New("a process executable identity is unknown")
		}
	}
	return references, nil
}

func processWithoutExecutable(status []byte) bool {
	for _, line := range strings.Split(string(status), "\n") {
		if line == "Kthread:\t1" || strings.HasPrefix(line, "State:\tZ") || strings.HasPrefix(line, "State:\tX") {
			return true
		}
	}
	return false
}

type referenceRunner func(context.Context, string, ...string) ([]byte, error)

func referenceCommand(ctx context.Context, program string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, program, args...).Output()
}

func managedServiceUnits(ctx context.Context, run referenceRunner) ([]string, error) {
	units := map[string]bool{}
	for _, command := range []string{"list-unit-files", "list-units"} {
		args := []string{command, "--type=service", "--no-legend", "--no-pager", "--plain", "loom-*.service"}
		if command == "list-units" {
			args = append(args, "--all")
		}
		body, err := run(ctx, "systemctl", args...)
		if err != nil {
			return nil, errors.New("managed unit enumeration failed")
		}
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if !strings.HasPrefix(fields[0], "loom-") || !strings.HasSuffix(fields[0], ".service") || strings.ContainsAny(fields[0], "/\\") {
				return nil, errors.New("managed unit enumeration is ambiguous")
			}
			units[fields[0]] = true
		}
	}
	result := make([]string, 0, len(units))
	for unit := range units {
		result = append(result, unit)
	}
	sort.Strings(result)
	return result, nil
}

var executionProperties = []string{"ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"}

func serviceProgramReferences(ctx context.Context, unit string, run referenceRunner) ([]programReference, error) {
	// show loads the installed definition without starting it, so inactive and
	// disabled units are inspected too. Resolve aliases to their canonical Id.
	body, err := run(ctx, "systemctl", "show", unit, "--property=Id", "--value")
	if err != nil {
		return nil, errors.New("managed unit identity is unreadable")
	}
	id := strings.TrimSpace(string(body))
	if id == "" || strings.ContainsAny(id, "\n\r/\\") || !strings.HasSuffix(id, ".service") {
		return nil, errors.New("managed unit identity is ambiguous")
	}
	var object strings.Builder
	object.WriteString("/org/freedesktop/systemd1/unit/")
	for _, b := range []byte(id) {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			object.WriteByte(b)
		} else {
			fmt.Fprintf(&object, "_%02x", b)
		}
	}
	args := []string{"--json=short", "--timeout=5", "get-property", "org.freedesktop.systemd1", object.String(), "org.freedesktop.systemd1.Service"}
	args = append(args, executionProperties...)
	body, err = run(ctx, "busctl", args...)
	if err != nil {
		return nil, errors.New("managed unit execution properties are unreadable")
	}
	return decodeExecutionReferences(body)
}

func decodeExecutionReferences(body []byte) ([]programReference, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	var references []programReference
	for _, propertyName := range executionProperties {
		var property struct {
			Type string            `json:"type"`
			Data []json.RawMessage `json:"data"`
		}
		if err := decoder.Decode(&property); err != nil || property.Type != "a(sasbttttuii)" {
			return nil, errors.New("managed unit execution property is ambiguous")
		}
		for _, row := range property.Data {
			var values []json.RawMessage
			if err := json.Unmarshal(row, &values); err != nil || len(values) != 10 {
				return nil, errors.New("managed unit execution entry is ambiguous")
			}
			var executable string
			var arguments []string
			if json.Unmarshal(values[0], &executable) != nil || json.Unmarshal(values[1], &arguments) != nil || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
				return nil, errors.New("managed unit execution path is ambiguous")
			}
			references = append(references, programReference{path: executable})
			// The signed client unit reloads its already running process. This
			// exact PID argument cannot name another executable. All other
			// substitutions remain unknown execution references.
			clientReload := propertyName == "ExecReload" && executable == "/bin/kill" && len(arguments) == 3 && arguments[0] == "/bin/kill" && arguments[1] == "-HUP" && arguments[2] == "$MAINPID"
			for index, argument := range arguments {
				if clientReload && index == 2 {
					continue
				}
				if strings.ContainsAny(argument, "%$") {
					return nil, errors.New("managed unit execution arguments have unresolved substitutions")
				}
				if filepath.IsAbs(argument) && filepath.Clean(argument) == argument {
					references = append(references, programReference{path: argument})
				}
			}
			// Shell code and unresolved specifiers cannot prove that no retained
			// program will be executed. Keep the package instead of guessing.
			name := filepath.Base(executable)
			if strings.Contains(executable, "%") || name == "sh" || name == "bash" || name == "dash" || name == "zsh" || name == "env" {
				return nil, errors.New("managed unit has opaque execution references")
			}
		}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("managed unit execution properties contain trailing input")
	}
	return references, nil
}
