package linuxclient

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
)

func TestNetworkNamespaceOperationsStayOnIsolatedThreads(t *testing.T) {
	child := exec.Command("sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	if err := child.Start(); errors.Is(err, syscall.EPERM) {
		t.Skip("kernel does not allow an isolated network namespace")
	} else if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	namespace, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	want, err := namespace.Stat()
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Stat("/proc/self/ns/net")
	if err != nil || os.SameFile(host, want) {
		t.Fatal("test child is not isolated", err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 8; j++ {
				err := inNetworkNamespace(namespace, func() error {
					current, err := os.Stat("/proc/thread-self/ns/net")
					if err != nil || !os.SameFile(current, want) {
						return errors.New("operation ran outside the isolated namespace")
					}
					interfaces, err := net.Interfaces()
					if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
						return errors.New("operation saw host network interfaces")
					}
					return nil
				})
				if err != nil {
					t.Error(err)
					return
				}
				current, err := os.Stat("/proc/thread-self/ns/net")
				if err != nil || !os.SameFile(current, host) {
					t.Error("namespace leaked into the caller's scheduler thread", err)
					return
				}
			}
		}()
	}
	workers.Wait()
	bad, err := os.CreateTemp(t.TempDir(), "demo-not-namespace")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	called := false
	if err := inNetworkNamespace(bad, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("invalid namespace did not fail before operation")
	}
	sentinel := errors.New("demo operation failure")
	if err := inNetworkNamespace(namespace, func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal("operation error was lost", err)
	}
}
