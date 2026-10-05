package linuxclient

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"loom/internal/control"
	"loom/internal/version"
)

func componentDigest(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("component is not a regular executable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// A process image stays bound to its inode across an on-disk release switch.
// These results belong only to the current runtime generation, never its path
// or the desired components in the authenticated view.
func linuxComponentReadbacks(ctx context.Context, pid int) ([]control.ComponentReadback, error) {
	result := []control.ComponentReadback{}
	var failures error
	self, err := os.Open("/proc/self/exe")
	if err == nil {
		digest, digestErr := componentDigest(self)
		self.Close()
		coordinate := version.Base()
		buildVersion := coordinate.Commit
		if buildVersion == "" || coordinate.Dirty {
			buildVersion = "devel"
		}
		if digestErr == nil {
			result = append(result, control.ComponentReadback{ComponentID: "agent", Platform: "linux-" + runtime.GOARCH, Version: buildVersion, ArtifactDigest: digest})
		}
		err = digestErr
	}
	failures = errors.Join(failures, err)
	if pid == 0 {
		return result, failures
	}
	component, err := runningSingBox(ctx, pid)
	if err == nil {
		result = append(result, component)
	}
	return result, errors.Join(failures, err)
}

func runningSingBox(ctx context.Context, pid int) (control.ComponentReadback, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return control.ComponentReadback{}, err
	}
	defer file.Close()
	build, err := buildinfo.Read(file)
	if err != nil {
		return control.ComponentReadback{}, err
	}
	var osName, arch string
	for _, setting := range build.Settings {
		switch setting.Key {
		case "GOOS":
			osName = setting.Value
		case "GOARCH":
			arch = setting.Value
		}
	}
	if osName != "linux" || arch != runtime.GOARCH {
		return control.ComponentReadback{}, errors.New("data-plane image platform differs from its runtime")
	}
	digest, err := componentDigest(file)
	if err != nil {
		return control.ComponentReadback{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Execute the already opened image, including after unlink/rename. Reopening
	// the configured path could measure a different program than the live child.
	command := exec.CommandContext(bounded, "/proc/self/fd/3", "version")
	command.ExtraFiles = []*os.File{file}
	output, err := command.Output()
	if err != nil {
		return control.ComponentReadback{}, errors.New("running sing-box version readback failed")
	}
	first, _, _ := strings.Cut(string(output), "\n")
	fields := strings.Fields(first)
	if len(fields) != 3 || fields[0] != "sing-box" || fields[1] != "version" {
		return control.ComponentReadback{}, errors.New("running sing-box version output is invalid")
	}
	value := control.ComponentReadback{ComponentID: "sing-box", Platform: osName + "-" + arch, Version: strings.TrimPrefix(fields[2], "v"), ArtifactDigest: digest}
	return value, value.Validate()
}
