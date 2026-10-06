package clientdist

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

const defaultInstallState = "/var/lib/loom-device/state.json"

func installPath(value string) bool {
	return value != "" && len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func unitPath(value string) string     { return strconv.Quote(strings.ReplaceAll(value, "%", "%%")) }
func unitArgument(value string) string { return unitPath(strings.ReplaceAll(value, "$", "$$")) }

// ServiceUnit is a pure projection of explicit installation inputs. The paths
// identify files; they never create a Device or alter its certified permission.
func ServiceUnit(release, state, resourceInputs, capture string) ([]byte, error) {
	return serviceUnit(systemdService, release, state, resourceInputs, capture)
}

func serviceUnit(template, release, state, resourceInputs, capture string) ([]byte, error) {
	if capture != "mixed" && capture != "tun" {
		return nil, errors.New("service capture must be explicitly mixed or tun")
	}
	if !installPath(release) || !installPath(state) || resourceInputs != "" && !installPath(resourceInputs) {
		return nil, errors.New("service paths must be absolute canonical paths without control characters")
	}
	resources := ""
	if resourceInputs != "" {
		resources = " -resource-inputs " + unitArgument(resourceInputs)
	}
	directory := filepath.Dir(state)
	capabilities, devices, namespaceFD := "", "", ""
	if capture == "tun" {
		capabilities = " CAP_SYS_ADMIN"
		devices = "DeviceAllow=/dev/net/tun rw\n"
		namespaceFD = "OpenFile=/proc/1/ns/net:loom-initial-network:read-only\n"
	}
	return []byte(strings.NewReplacer("@LOOM@", unitArgument(filepath.Join(release, "loom")), "@SING_BOX@", unitArgument(filepath.Join(release, "sing-box")), "@STATE@", unitArgument(state), "@LOCAL_STATE@", unitArgument(filepath.Join(directory, "runtime.json")), "@STATE_DIRECTORY@", unitPath(directory), "@RESOURCE_INPUTS@", resources, "@CAPTURE@", capture, "@CAPTURE_CAPABILITIES@", capabilities, "@CAPTURE_DEVICES@", devices, "@INITIAL_NETNS_FD@", namespaceFD).Replace(template)), nil
}
