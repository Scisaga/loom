//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"loom/internal/clientcomponent"
	"loom/internal/control"
	"loom/internal/version"
)

// Hold verified files across process creation and measurement. Windows sharing
// rules prevent replacing them while this generation can still execute them.
func openWindowsComponent(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("running component file could not be held read-only")
	}
	file := os.NewFile(uintptr(handle), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("running component is not a regular file")
	}
	return file, nil
}

func windowsComponentDigest(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func pinWindowsRuntimeComponents(paths clientcomponent.RuntimePaths) (map[string]*os.File, error) {
	files := map[string]*os.File{}
	for _, item := range []struct{ id, path, digest string }{
		{"sing-box", paths.SingBox, paths.Manifest.SingBox.SHA256},
		{"wintun", paths.Wintun, paths.Manifest.Wintun.SHA256},
	} {
		file, err := openWindowsComponent(item.path)
		if err == nil {
			files[item.id] = file
			actual, readErr := windowsComponentDigest(file)
			err = readErr
			if err == nil && actual != "sha256:"+item.digest {
				err = errors.New("runtime component changed after package verification")
			}
		}
		if err != nil {
			for _, held := range files {
				held.Close()
			}
			return nil, err
		}
	}
	return files, nil
}

func windowsProcessImage(pid int) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(process)
	if state, err := windows.WaitForSingleObject(process, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		return "", errors.New("component process is no longer running")
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

func windowsLoadedWintun(pid int) (string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
	for err = windows.Module32First(snapshot, &entry); err == nil; err = windows.Module32Next(snapshot, &entry) {
		if strings.EqualFold(windows.UTF16ToString(entry.Module[:]), "wintun.dll") {
			return windows.UTF16ToString(entry.ExePath[:]), nil
		}
	}
	if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return "", nil
	}
	return "", err
}

func measuredWindowsComponent(id, path string, file *os.File, component clientcomponent.Component) (control.ComponentReadback, error) {
	var zero control.ComponentReadback
	if file == nil {
		return zero, errors.New("component has no held verified file")
	}
	held, err := file.Stat()
	actual, actualErr := os.Stat(path)
	if err != nil || actualErr != nil || !os.SameFile(held, actual) {
		return zero, errors.New("loaded component differs from the held verified file")
	}
	digest, err := windowsComponentDigest(file)
	if err != nil || digest != "sha256:"+component.SHA256 {
		return zero, errors.New("loaded component digest differs from its verified manifest")
	}
	value := control.ComponentReadback{ComponentID: id, Platform: "windows-" + runtime.GOARCH,
		Version: strings.TrimPrefix(component.Version, "v"), ArtifactDigest: digest}
	return value, value.Validate()
}

func windowsComponentReadbacks(pid int, paths clientcomponent.RuntimePaths, held map[string]*os.File) ([]control.ComponentReadback, error) {
	result := []control.ComponentReadback{}
	var failures error
	path, err := windowsProcessImage(os.Getpid())
	if err == nil {
		file, openErr := openWindowsComponent(path)
		err = openErr
		if err == nil {
			digest, readErr := windowsComponentDigest(file)
			file.Close()
			err = readErr
			coordinate := version.Base()
			buildVersion := coordinate.Commit
			if buildVersion == "" || coordinate.Dirty {
				buildVersion = "devel"
			}
			if err == nil {
				result = append(result, control.ComponentReadback{ComponentID: "agent", Platform: "windows-" + runtime.GOARCH, Version: buildVersion, ArtifactDigest: digest})
			}
		}
	}
	failures = errors.Join(failures, err)
	if pid == 0 {
		return result, failures
	}
	path, err = windowsProcessImage(pid)
	if err != nil {
		return result, errors.Join(failures, err)
	}
	component, err := measuredWindowsComponent("sing-box", path, held["sing-box"], paths.Manifest.SingBox)
	if err == nil {
		result = append(result, component)
	}
	failures = errors.Join(failures, err)
	path, err = windowsLoadedWintun(pid)
	if err == nil && path != "" {
		component, err = measuredWindowsComponent("wintun", path, held["wintun"], paths.Manifest.Wintun)
		if err == nil {
			result = append(result, component)
		}
	}
	return result, errors.Join(failures, err)
}
