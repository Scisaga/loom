package linuxclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeActivationPreservesExactOwnedAddresses(t *testing.T) {
	const marker = "--native-wg-activation-isolated"
	isolated := false
	for _, arg := range os.Args {
		isolated = isolated || arg == marker
	}
	if !isolated {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(binary, "-test.run=^TestNativeActivationPreservesExactOwnedAddresses$", "-test.v", "--", marker)
		child.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
			UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
			GidMappingsEnableSetgroups: false,
		}
		body, err := child.CombinedOutput()
		if errors.Is(err, syscall.EPERM) {
			t.Skip("kernel does not allow an isolated user/network/mount namespace")
		}
		if err != nil {
			t.Fatalf("isolated native activation: %v\n%s", err, body)
		}
		t.Log(strings.TrimSpace(string(body)))
		return
	}
	if err := requireDifferentNetworkNamespace("/proc/self/ns/net", "/proc/1/ns/net"); err != nil {
		t.Fatal(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("native activation test requires a fresh loopback-only namespace", err)
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runHostCommand(ip, "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	create := func(t *testing.T, label, address string) (*os.File, *wireGuardTransaction) {
		t.Helper()
		sum := sha256.Sum256([]byte("demo-native-activation-" + label))
		token := hex.EncodeToString(sum[:16])
		creation := "lm" + token[:13]
		file, err := os.OpenFile("/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		request, err := unix.NewIfreq(creation)
		if err != nil {
			t.Fatal(err)
		}
		request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, request); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"link", "set", "dev", creation, "addrgenmode", "none"}, {"address", "add", address, "dev", creation}, {"link", "set", "dev", creation, "up"}} {
			if _, err := runHostCommand(ip, args...); err != nil {
				t.Fatal(err)
			}
		}
		peer := "192.0.2.2/32"
		if strings.Contains(address, ":") {
			peer = "2001:db8::2/128"
		}
		owned := wireGuardOwnedLink{native: true, alias: "loom-runtime:" + token, creationName: creation,
			link: wireGuardExecutionLink{Interface: "loom-wg-demo", LocalAddress: address, AllowedIP: peer}}
		return file, &wireGuardTransaction{options: Options{IP: ip, Config: filepath.Join(t.TempDir(), "runtime.json")}, owned: []wireGuardOwnedLink{owned}}
	}
	activate := func(tx *wireGuardTransaction) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return tx.activateNative(ctx, os.Getpid(), make(chan error))
	}
	stop := func(t *testing.T, file *os.File, tx *wireGuardTransaction) {
		t.Helper()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := tx.Cleanup(); err != nil {
			t.Fatal("cleanup after native TUN owner stopped", err)
		}
	}
	for _, item := range []struct{ name, address string }{{"ipv4", "192.0.2.1/32"}, {"ipv6", "2001:db8::1/128"}} {
		t.Run(item.name, func(t *testing.T) {
			file, tx := create(t, item.name, item.address)
			defer stop(t, file, tx)
			if err := activate(tx); err != nil {
				t.Fatal("authorized native management interface did not activate", err)
			}
			if err := verifyNativeHost(tx.options, tx.owned[0]); err != nil {
				t.Fatal("activation did not retain the exact authorized addresses/routes", err)
			}
		})
	}
	t.Run("unknown_extra_address_rejected_before_activation", func(t *testing.T) {
		file, tx := create(t, "unknown", "2001:db8::1/128")
		defer stop(t, file, tx)
		name := tx.owned[0].creationName
		if _, err := runHostCommand(ip, "address", "add", "192.0.2.99/32", "dev", name); err != nil {
			t.Fatal(err)
		}
		if err := activate(tx); err == nil {
			t.Fatal("unknown address was accepted as native interface authority")
		}
		actual, found, err := findWireGuardLink(tx.options, name)
		if err != nil || !found || actual.Alias != "" {
			t.Fatal("unknown address was not rejected before interface activation", err)
		}
		addresses, err := interfaceAddresses(ip, name)
		if err != nil || len(addresses) != 2 {
			t.Fatal("rejected interface addresses were changed", err)
		}
	})
	t.Run("address_restore_failure_closes_then_restarts", func(t *testing.T) {
		file, tx := create(t, "failure", "2001:db8::1/128")
		wrapper := filepath.Join(t.TempDir(), "ip")
		attempt := wrapper + ".attempt"
		script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = address ] && [ \"$2\" = add ]; then printf attempted > '%s'; exit 37; fi\nexec '%s' \"$@\"\n", attempt, ip)
		if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		tx.options.IP = wrapper
		if err := activate(tx); err == nil {
			t.Fatal("failed address restoration was reported as activated")
		}
		if _, err := os.Stat(attempt); err != nil {
			t.Fatal("activation did not attempt to restore the missing authorized address", err)
		}
		stop(t, file, tx)
		file, tx = create(t, "restart", "2001:db8::1/128")
		defer stop(t, file, tx)
		if err := activate(tx); err != nil {
			t.Fatal("fresh generation could not restart after failed owned address restoration", err)
		}
	})
}
