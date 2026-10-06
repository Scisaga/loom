package linuxclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const tunUnderlayReference = "/proc/self/fd/3"

// withTUNUnderlay is a one-way platform projection. No local namespace reference
// is accepted from an authenticated profile, persisted as authority, or reported.
func withTUNUnderlay(config string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	outbounds, ok := document["outbounds"].([]any)
	if !ok {
		return "", errors.New("TUN runtime has no outbounds")
	}
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok || outbound["netns"] != nil {
			return "", errors.New("TUN runtime contains an untrusted namespace reference")
		}
		switch outbound["type"] {
		case "direct", "hysteria2", "trojan":
			// Detoured connections are created by the referenced outbound.
			if outbound["detour"] == nil {
				outbound["netns"] = tunUnderlayReference
			}
		case "block", "dns", "selector":
		default:
			return "", errors.New("TUN underlay transport has no reviewed socket projection")
		}
	}
	route, ok := document["route"].(map[string]any)
	if !ok {
		return "", errors.New("TUN runtime has no route projection")
	}
	delete(route, "auto_detect_interface")
	body, err := json.Marshal(document)
	return string(body), err
}

// ExecTUNWorker runs only in the newly cloned network namespace. The underlay
// reference is inherited before exec, never selected from a mutable path.
func ExecTUNWorker(program, config string, check bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Exec may run on a different Go thread than the fork's initial thread;
	// Pdeathsig is per-thread and must be installed again on this exec thread.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return err
	}
	parent := []unix.PollFd{{Fd: 4, Events: unix.POLLIN}}
	if n, err := unix.Poll(parent, 0); err != nil || n != 0 {
		return errors.New("TUN supervisor exited before data-plane exec")
	}
	unix.Close(4)
	if kind, err := unix.IoctlRetInt(5, unix.NS_GET_NSTYPE); err != nil || kind != unix.CLONE_NEWNET {
		return errors.New("TUN worker has no pinned initial network namespace")
	}
	if err := requireDifferentNetworkNamespace("/proc/thread-self/ns/net", "/proc/self/fd/5"); err != nil {
		return err
	}
	unix.Close(5)
	underlay := os.NewFile(3, "underlay-network")
	if underlay == nil {
		return errors.New("TUN worker has no inherited underlay")
	}
	if kind, err := unix.IoctlRetInt(3, unix.NS_GET_NSTYPE); err != nil || kind != unix.CLONE_NEWNET {
		return errors.New("TUN worker underlay is not a network namespace")
	}
	original, err := underlay.Stat()
	current, currentErr := os.Stat("/proc/thread-self/ns/net")
	if err != nil || currentErr != nil || os.SameFile(original, current) {
		return errors.New("TUN worker did not isolate its network")
	}
	if err := isolateHostControlSockets(6); err != nil {
		return err
	}
	unix.Close(6)
	if !filepath.IsAbs(program) || filepath.Clean(program) != program || !filepath.IsAbs(config) || filepath.Clean(config) != config {
		return errors.New("TUN worker requires exact executable and configuration paths")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		return errors.New("TUN worker namespace is not empty")
	}
	if err := exec.Command("/usr/sbin/ip", "link", "set", "lo", "up").Run(); err != nil {
		return fmt.Errorf("enable isolated loopback: %w", err)
	}
	mode := "run"
	if check {
		mode = "check"
	}
	// The data plane opens its persistent DNS cache relative to this directory.
	if err := os.Chdir(filepath.Dir(config)); err != nil {
		return err
	}
	return unix.Exec(program, []string{program, mode, "-c", config}, os.Environ())
}

func tunCommand(options Options, check bool) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	program, err := filepath.Abs(options.SingBox)
	if err != nil {
		return nil, err
	}
	config, err := filepath.Abs(options.Config)
	if err != nil {
		return nil, err
	}
	underlay, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, err
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		underlay.Close()
		return nil, err
	}
	parent := os.NewFile(uintptr(pidfd), "TUN-supervisor")
	initial, err := initialCaptureNamespace()
	if err != nil {
		underlay.Close()
		parent.Close()
		return nil, err
	}
	mount, err := os.Open("/proc/thread-self/ns/mnt")
	if err != nil {
		underlay.Close()
		parent.Close()
		initial.Close()
		return nil, err
	}
	args := []string{"client", "_tun-worker", program, config}
	if check {
		args = append(args, "check")
	}
	command := exec.Command(self, args...)
	command.ExtraFiles = []*os.File{underlay, parent, initial, mount}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = options.Log, options.Log
	return command, nil
}

// systemd opens this same nsfs object before applying the service's capability
// boundary. An ordinary root CLI obtains it directly. Neither path can replace
// the identity check with a caller-provided namespace name or a regular file.
func initialCaptureNamespace() (*os.File, error) {
	var file *os.File
	var err error
	if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" || os.Getenv("LISTEN_FDNAMES") != "" {
		if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != "loom-initial-network" {
			return nil, errors.New("unexpected service namespace descriptor delivery")
		}
		unix.CloseOnExec(3)
		var descriptor int
		descriptor, err = unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 6)
		if err == nil {
			file = os.NewFile(uintptr(descriptor), "initial-network")
		}
	} else {
		file, err = os.Open("/proc/1/ns/net")
	}
	if err != nil {
		return nil, fmt.Errorf("pin initial network namespace: %w", err)
	}
	if kind, err := unix.IoctlRetInt(int(file.Fd()), unix.NS_GET_NSTYPE); err != nil || kind != unix.CLONE_NEWNET {
		file.Close()
		return nil, errors.New("initial network namespace reference is not nsfs")
	}
	return file, nil
}

func captureNamespace(ctx context.Context, command *exec.Cmd, program string, initialReference *os.File, exited <-chan error) (*os.File, error) {
	wanted, err := os.Stat(program)
	if err != nil {
		return nil, err
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		actual, err := os.Stat(fmt.Sprintf("/proc/%d/exe", command.Process.Pid))
		if err == nil && os.SameFile(wanted, actual) {
			namespace, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", command.Process.Pid))
			if err != nil {
				return nil, err
			}
			isolated, nsErr := namespace.Stat()
			original, hostErr := os.Stat("/proc/thread-self/ns/net")
			initial, initErr := initialReference.Stat()
			if nsErr != nil || hostErr != nil || initErr != nil || os.SameFile(isolated, original) || os.SameFile(isolated, initial) {
				namespace.Close()
				return nil, errors.New("data plane is not in its dedicated namespace")
			}
			return namespace, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-exited:
			return nil, errors.New("isolated data plane exited before executable readback")
		case <-deadline.C:
			return nil, errors.New("isolated data plane executable readback timed out")
		case <-ticker.C:
		}
	}
}
