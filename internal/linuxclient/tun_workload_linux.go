package linuxclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The abstract socket and anonymous namespace are kernel resources, not a
// persistent registry. A crashed owner leaves no reusable pathname or PID file.
func captureAddress(config string) (*net.UnixAddr, error) {
	path, err := filepath.Abs(config)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(path))
	return &net.UnixAddr{Name: fmt.Sprintf("@loom-capture-%d-%x", os.Geteuid(), digest), Net: "unixpacket"}, nil
}

func capturePeer(connection *net.UnixConn, verifyExecutable bool) (*unix.Ucred, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credentials *unix.Ucred
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || socketErr != nil {
		return nil, errors.Join(err, socketErr)
	}
	if credentials.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("capture peer has a different owner")
	}
	if !verifyExecutable {
		// Root explicitly authorizes this application. A bounded service must
		// not gain CAP_SYS_PTRACE merely to inspect its more privileged caller.
		return credentials, nil
	}
	self, selfErr := os.Stat("/proc/self/exe")
	peer, peerErr := os.Stat(fmt.Sprintf("/proc/%d/exe", credentials.Pid))
	if selfErr != nil || peerErr != nil || !os.SameFile(self, peer) {
		return nil, errors.New("capture peer is not the same exact Loom executable")
	}
	return credentials, nil
}

func sendCaptureFiles(connection *net.UnixConn, marker byte, files ...*os.File) error {
	fds := make([]int, len(files))
	for i, file := range files {
		fds[i] = int(file.Fd())
	}
	n, _, err := connection.WriteMsgUnix([]byte{marker}, unix.UnixRights(fds...), nil)
	if err != nil || n != 1 {
		return errors.Join(err, errors.New("capture descriptor delivery failed"))
	}
	return nil
}

func receiveCaptureFiles(connection *net.UnixConn, marker byte, count int) ([]*os.File, error) {
	body := make([]byte, 2)
	ancillary := make([]byte, unix.CmsgSpace(16*4))
	n, oobn, flags, _, err := connection.ReadMsgUnix(body, ancillary)
	messages, parseErr := unix.ParseSocketControlMessage(ancillary[:oobn])
	var files []*os.File
	for _, message := range messages {
		fds, fdErr := unix.ParseUnixRights(&message)
		parseErr = errors.Join(parseErr, fdErr)
		for _, fd := range fds {
			unix.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "capture-reference"))
		}
	}
	if err != nil || parseErr != nil || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || n != 1 || body[0] != marker || len(files) != count {
		for _, file := range files {
			file.Close()
		}
		return nil, errors.New("capture descriptor message is invalid")
	}
	return files, nil
}

func captureDNSFile(config string) (*os.File, error) {
	// Linux cannot bind-mount an anonymous memfd or unlinked inode. This is a
	// disposable resolver projection beside the runtime config, never host DNS.
	path := config + ".resolv.conf"
	if err := writeConfig(path, "nameserver 172.19.0.2\noptions timeout:2 attempts:2\n"); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func closeCaptureDNS(file *os.File) error {
	defer file.Close()
	owned, err := file.Stat()
	actual, readErr := os.Lstat(file.Name())
	if err != nil || readErr != nil || !os.SameFile(owned, actual) {
		return errors.New("capture resolver ownership changed before cleanup")
	}
	return os.Remove(file.Name())
}

type captureWorkloads struct {
	listener            *net.UnixListener
	namespace, resolver *os.File
	ctx                 context.Context
	cancel              context.CancelFunc
	wait                sync.WaitGroup
	once                sync.Once
	mu                  sync.Mutex
	err                 error
}

func serveCaptureWorkloads(ctx context.Context, config string, namespace *os.File) (*captureWorkloads, error) {
	address, err := captureAddress(config)
	if err != nil {
		return nil, err
	}
	resolver, err := captureDNSFile(config)
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenUnix("unixpacket", address)
	if err != nil {
		_ = closeCaptureDNS(resolver)
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	service := &captureWorkloads{listener: listener, namespace: namespace, resolver: resolver, ctx: ctx, cancel: cancel}
	service.wait.Add(1)
	go func() {
		defer service.wait.Done()
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			service.wait.Add(1)
			go func() {
				defer service.wait.Done()
				defer connection.Close()
				service.serve(connection)
			}()
		}
	}()
	return service, nil
}

func (service *captureWorkloads) serve(connection *net.UnixConn) {
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	peer, err := capturePeer(connection, false)
	if err != nil {
		return
	}
	if service.ctx.Err() != nil || sendCaptureFiles(connection, 'N', service.namespace, service.resolver) != nil {
		return
	}
	files, err := receiveCaptureFiles(connection, 'P', 1)
	if err != nil {
		return
	}
	defer files[0].Close()
	pidfd := int(files[0].Fd())
	if err := verifyCaptureWorkload(files[0], peer); err != nil {
		return
	}
	defer func() {
		if err := stopCaptureWorkload(pidfd); err != nil {
			service.mu.Lock()
			service.err = errors.Join(service.err, err)
			service.mu.Unlock()
		}
	}()
	if service.ctx.Err() != nil {
		return
	}
	if _, err := connection.Write([]byte{'R'}); err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	disconnected := make(chan struct{})
	go func() { _, _ = connection.Read(make([]byte, 1)); close(disconnected) }()
	select {
	case <-service.ctx.Done():
	case <-disconnected:
	}
	connection.Close()
}

func verifyCaptureWorkload(file *os.File, peer *unix.Ucred) error {
	if err := unix.PidfdSendSignal(int(file.Fd()), 0, nil, 0); err != nil {
		return err
	}
	info, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", file.Fd()))
	if err != nil {
		return err
	}
	pid := 0
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Pid:" {
			pid, _ = strconv.Atoi(fields[1])
		}
	}
	if pid <= 1 {
		return errors.New("capture process reference is not live")
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return err
	}
	owned, isolated, sameUser := false, false, false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "PPid:" {
			parent, _ := strconv.Atoi(fields[1])
			owned = int32(parent) == peer.Pid
		}
		if len(fields) >= 3 && fields[0] == "NSpid:" {
			isolated = fields[len(fields)-1] == "1"
		}
		if len(fields) == 5 && fields[0] == "Uid:" {
			uid := strconv.FormatUint(uint64(peer.Uid), 10)
			sameUser = fields[1] == uid && fields[2] == uid && fields[3] == uid && fields[4] == uid
		}
	}
	if !owned || !isolated || !sameUser {
		return errors.New("capture process is not the caller's isolated process tree")
	}
	return nil
}

func stopCaptureWorkload(pidfd int) error {
	if err := unix.PidfdSendSignal(pidfd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("stop capture workload: %w", err)
	}
	for _, delay := range []int{3000, 3000} {
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		if n, err := unix.Poll(fds, delay); err == nil && n > 0 && fds[0].Revents&unix.POLLIN != 0 {
			return nil
		} else if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return err
		}
	}
	return errors.New("capture workload termination was not confirmed")
}

func (service *captureWorkloads) Close() error {
	service.once.Do(func() {
		service.cancel()
		service.listener.Close()
		service.wait.Wait()
		service.err = errors.Join(service.err, closeCaptureDNS(service.resolver))
	})
	return service.err
}

// ExecuteCapture keeps the caller's file access, environment and working
// directory. The service receives only a pidfd for exact lifecycle ownership.
func ExecuteCapture(ctx context.Context, config string, args []string) error {
	if len(args) == 0 || os.Geteuid() != 0 {
		return errors.New("client exec requires root and an explicit command")
	}
	address, err := captureAddress(config)
	if err != nil {
		return err
	}
	connection, err := net.DialUnix("unixpacket", nil, address)
	if err != nil {
		return errors.New("isolated TUN is not accepting applications")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := capturePeer(connection, true); err != nil {
		return err
	}
	files, err := receiveCaptureFiles(connection, 'N', 2)
	if err != nil {
		return err
	}
	defer files[0].Close()
	defer files[1].Close()
	gate, release, err := os.Pipe()
	if err != nil {
		return err
	}
	defer gate.Close()
	defer release.Close()
	self, err := os.Executable()
	if err != nil {
		return err
	}
	parentFD, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return err
	}
	parent := os.NewFile(uintptr(parentFD), "capture-caller")
	defer parent.Close()
	mount, err := os.Open("/proc/thread-self/ns/mnt")
	if err != nil {
		return err
	}
	defer mount.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	command := exec.Command(self, append([]string{"client", "_tun-workload"}, args...)...)
	command.ExtraFiles = []*os.File{files[0], files[1], gate, parent, mount}
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Go's pre-exec parent-PID check cannot cross a newly created PID namespace.
	// The worker installs Pdeathsig and checks this pinned caller before release.
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWPID}
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() { _ = command.Process.Kill(); <-done }()
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		return err
	}
	process := os.NewFile(uintptr(pidfd), "capture-workload")
	defer process.Close()
	if err := sendCaptureFiles(connection, 'P', process); err != nil {
		return err
	}
	var ready [1]byte
	if _, err := io.ReadFull(connection, ready[:]); err != nil || ready[0] != 'R' {
		return errors.New("capture service did not accept workload ownership")
	}
	if _, err := release.Write([]byte{'R'}); err != nil {
		return err
	}
	release.Close()
	_ = connection.SetDeadline(time.Time{})
	stopped := make(chan struct{})
	go func() { _, _ = connection.Read(make([]byte, 1)); close(stopped) }()
	select {
	case err := <-done:
		done <- err // leave Wait's result for the common cleanup path
		return err
	case <-ctx.Done():
		_ = stopCaptureWorkload(pidfd)
		return ctx.Err()
	case <-stopped:
		_ = stopCaptureWorkload(pidfd)
		return errors.New("isolated TUN generation stopped")
	}
}

// RunTUNWorkload is PID 1 of a fresh PID namespace. Killing it kills the entire
// application tree, including daemonized descendants; no caller-supplied PID is used.
func RunTUNWorkload(ctx context.Context, args []string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if len(args) == 0 || os.Getpid() != 1 {
		return errors.New("capture workload needs a dedicated PID namespace")
	}
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("supervise capture init: %w", err)
	}
	parent := []unix.PollFd{{Fd: 6, Events: unix.POLLIN}}
	if n, err := unix.Poll(parent, 0); err != nil || n != 0 {
		return errors.New("capture caller exited before workload supervision")
	}
	unix.Close(6)
	gate := os.NewFile(5, "capture-start")
	var ready [1]byte
	if _, err := io.ReadFull(gate, ready[:]); err != nil || ready[0] != 'R' {
		return errors.New("capture workload was not registered")
	}
	gate.Close()
	before, err := os.Stat("/proc/thread-self/ns/net")
	namespace := os.NewFile(3, "capture-network")
	target, targetErr := namespace.Stat()
	if err != nil || targetErr != nil || os.SameFile(before, target) {
		return errors.New("capture workload network is not isolated")
	}
	if err := unix.Setns(3, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter capture network: %w", err)
	}
	namespace.Close()
	if err := isolateHostControlSockets(7); err != nil {
		return err
	}
	unix.Close(7)
	resolverPath, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		return err
	}
	// Resolve the named file in this mount namespace. A descriptor received
	// from the supervisor still refers to its mount, which cannot be grafted
	// directly into a separately cloned mount namespace.
	resolver := os.NewFile(4, "capture-resolver")
	owned, err := resolver.Stat()
	source, pathErr := os.Readlink("/proc/self/fd/4")
	actual, sourceErr := os.Stat(source)
	if err != nil || pathErr != nil || sourceErr != nil || !os.SameFile(owned, actual) {
		return errors.New("capture resolver no longer matches the supervisor's file")
	}
	if err := unix.Mount(source, resolverPath, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("mount capture resolver: %w", err)
	}
	actual, err = os.Stat(resolverPath)
	if err != nil || !os.SameFile(owned, actual) {
		return errors.New("mounted capture resolver differs from the supervisor's file")
	}
	if err := unix.Mount("", resolverPath, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("protect capture resolver: %w", err)
	}
	resolver.Close()
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount capture process tree: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("disable capture privilege escalation: %w", err)
	}
	// Lock out root's implicit capability regain after exec, then remove every
	// capability. Applications cannot acquire host namespace or network control.
	const noRootLocked = 1<<0 | 1<<1 // Linux uapi securebits.h: NOROOT and NOROOT_LOCKED.
	if err := unix.Prctl(unix.PR_SET_SECUREBITS, noRootLocked, 0, 0, 0); err != nil {
		return fmt.Errorf("disable capture root capabilities: %w", err)
	}
	for capability := 0; capability <= unix.CAP_LAST_CAP; capability++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop capture capability %d: %w", capability, err)
		}
	}
	capabilities := [2]unix.CapUserData{}
	if err := unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &capabilities[0]); err != nil {
		return fmt.Errorf("clear capture capabilities: %w", err)
	}
	command := exec.Command(args[0], args[1:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case err := <-done:
			return err
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			return <-done
		}
	}
}
