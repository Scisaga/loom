package windowsrelease

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("MSI inspection output exceeds its boundary")
	}
	return b.buffer.Write(p)
}

// AuditMSI reads the actual database and extracts its embedded CAB in an
// isolated, bounded tmpfs. No MSI action is executed and no host directory is
// writable or visible except the read-only tool installation and exact input.
// The result is a disposable ProductVersion, not a signed audit receipt.
func AuditMSI(ctx context.Context, artifact, bundle []byte, arch string) (string, error) {
	if runtime.GOOS != "linux" || len(artifact) == 0 || len(artifact) > maxArtifact {
		return "", errors.New("MSI inspection requires the Linux publishing workstation and a bounded artifact")
	}
	files, err := readBundle(bundle, "installed", arch)
	if err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp("", "loom-windows-audit-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	input := filepath.Join(directory, "input.msi")
	if err = os.WriteFile(input, artifact, 0600); err != nil {
		return "", err
	}
	inspect := func(limit int, command ...string) ([]byte, error) {
		args := []string{"--unshare-all", "--new-session", "--die-with-parent", "--cap-drop", "ALL", "--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "LC_ALL", "C", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin", "--proc", "/proc", "--dev", "/dev", "--size", "16777216", "--tmpfs", "/tmp", "--size", "268435456", "--tmpfs", "/extract", "--ro-bind", input, "/input.msi"}
		cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", append(args, command...)...)
		cmd.Env = []string{"PATH=/usr/bin", "LC_ALL=C"}
		output := &boundedOutput{limit: limit}
		cmd.Stdout = output
		if err := cmd.Run(); err != nil {
			return nil, errors.New("isolated MSI inspection failed; requires bubblewrap and msitools")
		}
		return output.buffer.Bytes(), nil
	}
	properties, err := inspect(64<<10, "/usr/bin/msiinfo", "export", "/input.msi", "Property")
	if err != nil {
		return "", err
	}
	rows, err := idtRows(properties, []string{"Property", "Value"})
	if err != nil {
		return "", err
	}
	values := map[string]string{}
	for _, row := range rows {
		if _, exists := values[row[0]]; exists {
			return "", errors.New("MSI has duplicate properties")
		}
		values[row[0]] = row[1]
	}
	version := values["ProductVersion"]
	if values["ProductName"] != "Loom" || values["Manufacturer"] != "Loom" || values["UpgradeCode"] != "{A2C983CA-D7B2-4ED0-A4F1-7D399513F2B4}" || values["ALLUSERS"] != "1" || !installerVersion(version) {
		return "", errors.New("MSI product identity or version differs")
	}
	summary, err := inspect(64<<10, "/usr/bin/msiinfo", "suminfo", "/input.msi")
	if err != nil {
		return "", err
	}
	template := "x64;1033"
	if arch == "arm64" {
		template = "Arm64;1033"
	}
	if bytes.Count(summary, []byte("Template: ")) != 1 || !bytes.Contains(summary, []byte("\nTemplate: "+template+"\n")) {
		return "", errors.New("MSI target architecture differs")
	}
	media, err := inspect(64<<10, "/usr/bin/msiinfo", "export", "/input.msi", "Media")
	if err != nil {
		return "", err
	}
	rows, err = idtRows(media, []string{"DiskId", "LastSequence", "DiskPrompt", "Cabinet", "VolumeLabel", "Source"})
	if err != nil || len(rows) != 1 || strings.Join(rows[0], "\t") != "1\t13\t\t#cab1.cab\t\t" {
		return "", errors.New("MSI requires exactly the embedded application cabinet")
	}
	actions, err := inspect(64<<10, "/usr/bin/msiinfo", "export", "/input.msi", "CustomAction")
	if err != nil {
		return "", err
	}
	rows, err = idtRows(actions, []string{"Action", "Type", "Source", "Target", "ExtendedType"})
	if err != nil || len(rows) != 1 || strings.Join(rows[0], "\t") != "SetLOOM_OPERATOR_SID\t51\tLOOM_OPERATOR_SID\t[UserSID]\t" {
		return "", errors.New("MSI custom action set differs from the application installer")
	}
	extracted, err := inspect(maxArtifact, "/bin/sh", "-c", "msiextract -C /extract /input.msi >/dev/null && tar -C /extract -cf - .")
	if err != nil {
		return "", err
	}
	if err := compareExtracted(extracted, files, arch); err != nil {
		return "", err
	}
	return version, nil
}

func idtRows(body []byte, header []string) ([][]string, error) {
	lines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n"), "\n")
	if len(lines) < 3 || lines[0] != strings.Join(header, "\t") || len(strings.Split(lines[1], "\t")) != len(header) {
		return nil, errors.New("MSI table output is invalid")
	}
	rows := [][]string{}
	for _, line := range lines[3:] {
		row := strings.Split(line, "\t")
		if len(row) != len(header) {
			return nil, errors.New("MSI table row is ambiguous")
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func compareExtracted(body []byte, files map[string][]byte, arch string) error {
	wanted := map[string][]byte{}
	directories := map[string]bool{".": true}
	for name, value := range files {
		if name == payloadNames("installed", arch)[0] {
			name = "loom-client.exe"
		}
		name = "PFiles64/Loom/" + name
		wanted[name] = value
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			directories[dir] = true
		}
	}
	reader := tar.NewReader(bytes.NewReader(body))
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("MSI extraction is incomplete")
		}
		name := strings.TrimPrefix(header.Name, "./")
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
			if name == "" {
				name = "."
			}
		}
		if seen[name] || path.Clean(name) != name {
			return errors.New("MSI extraction contains an ambiguous path")
		}
		seen[name] = true
		if header.Typeflag == tar.TypeDir && directories[name] {
			continue
		}
		value, found := wanted[name]
		if !found || header.Typeflag != tar.TypeReg || header.Size != int64(len(value)) {
			return errors.New("MSI extraction file set differs from its build bundle")
		}
		actual, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || !bytes.Equal(actual, value) {
			return errors.New("MSI payload differs from its build bundle")
		}
		delete(wanted, name)
	}
	if len(wanted) != 0 {
		return errors.New("MSI omitted build bundle files")
	}
	return nil
}
