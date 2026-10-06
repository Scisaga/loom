package linuxclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func isolateHostControlSockets(parentMountFD int) error {
	if kind, err := unix.IoctlRetInt(parentMountFD, unix.NS_GET_NSTYPE); err != nil || kind != unix.CLONE_NEWNS {
		return errors.New("capture has no pinned supervisor mount namespace")
	}
	parent, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", parentMountFD))
	current, currentErr := os.Stat("/proc/thread-self/ns/mnt")
	if err != nil || currentErr != nil || os.SameFile(parent, current) {
		return errors.New("capture mount namespace is not isolated")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("isolate capture mounts: %w", err)
	}
	// Network namespaces do not isolate pathname Unix sockets. resolvectl can
	// otherwise send a TUN's ifindex to the host's resolved/networkd instance.
	for _, path := range []string{"/run/dbus", "/run/systemd/netif", "/run/NetworkManager"} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() {
			return errors.New("host control socket directory is not canonical")
		}
		if err := unix.Mount("tmpfs", path, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=000,size=4096"); err != nil {
			return fmt.Errorf("isolate host control sockets: %w", err)
		}
	}
	// Keep the resolver's data files: /etc/resolv.conf may be a symlink there.
	// Mask its IPC endpoints and the service manager socket, not that data path.
	for _, path := range []string{"/run/systemd/private", "/run/systemd/resolve/io.systemd.Resolve", "/run/systemd/resolve/io.systemd.Resolve.Monitor"} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			return errors.New("host control socket is not canonical")
		}
		if err := unix.Mount("/dev/null", path, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("isolate host control socket: %w", err)
		}
	}
	return nil
}

// Numeric single-family dialing keeps socket creation on the locked thread;
// domain resolution is explicitly performed through the capture DNS separately.
func namespaceDialer(namespace *os.File) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (connection net.Conn, retErr error) {
		host, port, err := net.SplitHostPort(address)
		ip, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || ip.Zone() != "" || network != "tcp" && network != "udp" && network != "tcp4" && network != "tcp6" && network != "udp4" && network != "udp6" {
			return nil, errors.New("namespace dialing requires a numeric TCP or UDP destination")
		}
		family := "4"
		if ip.Is6() {
			family = "6"
		}
		if len(network) == 4 && network[3:] != family {
			return nil, errors.New("namespace destination family differs")
		}
		err = inNetworkNamespace(namespace, func() error {
			var err error
			connection, err = (&net.Dialer{Timeout: 5 * time.Second, FallbackDelay: -1}).DialContext(ctx, network[:3]+family, net.JoinHostPort(ip.String(), port))
			return err
		})
		if err != nil && connection != nil {
			_ = connection.Close()
			connection = nil
		}
		return connection, err
	}
}

// inNetworkNamespace confines setns to a disposable locked thread. A failed
// restore destroys that thread rather than returning it to the Go scheduler.
// Callers must create numeric-address sockets synchronously in operation; a
// goroutine started by operation would not inherit its thread's namespace.
func inNetworkNamespace(namespace *os.File, operation func() error) error {
	if namespace == nil {
		return errors.New("network namespace reference is missing")
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		restored := true
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		original, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			done <- err
			return
		}
		defer original.Close()
		if err = unix.Setns(int(namespace.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		restored = false
		// Also restore during panic unwinding; a panic remains a process failure.
		defer func() {
			if !restored {
				restored = unix.Setns(int(original.Fd()), unix.CLONE_NEWNET) == nil
			}
		}()
		err = operation()
		restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET)
		restored = restoreErr == nil
		done <- errors.Join(err, restoreErr)
	}()
	return <-done
}
