//go:build linux

package linuxclient

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRealReverseWireGuardTransport is intentionally opt-in: it needs root,
// network namespaces, the WireGuard kernel module and socat. Unlike the fake
// command tests, this proves the HostAdapter's initiator/acceptor application
// creates a real tunnel carrying both TCP and UDP traffic.
func TestRealReverseWireGuardTransport(t *testing.T) {
	if os.Getenv("LOOM_REAL_WG_TEST") != "1" {
		t.Skip("set LOOM_REAL_WG_TEST=1 for the privileged network-namespace acceptance test")
	}
	for _, command := range []string{"ip", "wg", "socat"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is unavailable", command)
		}
	}
	suffix := strconv.Itoa(os.Getpid())
	initiatorNS, acceptorNS := "loomwg-i-"+suffix, "loomwg-a-"+suffix
	vethI, vethA := "lwi"+suffix, "lwa"+suffix
	if len(vethI) > 15 {
		vethI, vethA = vethI[:15], vethA[:15]
	}
	run := func(arguments ...string) []byte {
		t.Helper()
		command := exec.Command("ip", arguments...)
		body, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("ip %s: %v: %s", strings.Join(arguments, " "), err, body)
		}
		return body
	}
	run("netns", "add", initiatorNS)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", initiatorNS).Run() })
	run("netns", "add", acceptorNS)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", acceptorNS).Run() })
	run("-n", initiatorNS, "link", "add", vethI, "type", "veth", "peer", "name", vethA, "netns", acceptorNS)
	for _, values := range [][]string{{initiatorNS, vethI, "192.0.2.1/24"}, {acceptorNS, vethA, "192.0.2.2/24"}} {
		run("-n", values[0], "address", "add", values[2], "dev", values[1])
		run("-n", values[0], "link", "set", "dev", values[1], "up")
		run("-n", values[0], "link", "set", "dev", "lo", "up")
	}

	root, err := os.MkdirTemp("/run", "loom-wg-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	makeKey := func(name string) (string, string) {
		t.Helper()
		private, err := exec.Command("wg", "genkey").Output()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("/etc/wireguard", ".loom-real-wg-"+suffix+"-"+name+".key")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(private); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(path) })
		command := exec.Command("wg", "pubkey")
		command.Stdin = bytes.NewReader(private)
		public, err := command.Output()
		if err != nil {
			t.Fatal(err)
		}
		return path, strings.TrimSpace(string(public))
	}
	initiatorKey, initiatorPublic := makeKey("initiator")
	acceptorKey, acceptorPublic := makeKey("acceptor")
	makeWrapper := func(name, namespace, binary string) string {
		t.Helper()
		path := filepath.Join(root, name)
		body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %s.args\nexec /usr/sbin/ip netns exec %s %s \"$@\" 2>>%s.stderr\n",
			path, namespace, binary, path)
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	initiatorOptions := Options{IP: makeWrapper("ip-i", initiatorNS, "/usr/sbin/ip"),
		WireGuard: makeWrapper("wg-i", initiatorNS, "/usr/bin/wg"), WireGuardPrivateKey: initiatorKey, Config: filepath.Join(root, "initiator.json")}
	acceptorOptions := Options{IP: makeWrapper("ip-a", acceptorNS, "/usr/sbin/ip"),
		WireGuard: makeWrapper("wg-a", acceptorNS, "/usr/bin/wg"), WireGuardPrivateKey: acceptorKey, Config: filepath.Join(root, "acceptor.json")}
	const listenPort = 51888 // isolated namespace only; deliberately not a production/public port
	acceptorProfile := &wireGuardExecution{WireGuard: []wireGuardExecutionLink{{
		LinkID: "demo-link", Interface: "wg-demo", LocalAddress: "10.20.0.2/32", PeerID: "demo-i",
		PeerPublicKey: initiatorPublic, AllowedIP: "10.20.0.1/32", Mode: "acceptor", ListenPort: listenPort,
		ProbeTarget: "10.20.0.1",
	}}}
	initiatorProfile := &wireGuardExecution{WireGuard: []wireGuardExecutionLink{{
		LinkID: "demo-link", Interface: "wg-demo", LocalAddress: "10.20.0.1/32", PeerID: "demo-a",
		PeerPublicKey: acceptorPublic, AllowedIP: "10.20.0.2/32", Mode: "initiator",
		Endpoint: "192.0.2.2:51888", PersistentKeepalive: 25, ProbeTarget: "10.20.0.2",
	}}}
	acceptorTransaction, err := applyWireGuard(acceptorProfile, nil,
		&wireGuardIdentity{WGPublicKey: acceptorPublic}, acceptorOptions)
	if err != nil {
		arguments, _ := os.ReadFile(acceptorOptions.WireGuard + ".args")
		stderr, _ := os.ReadFile(acceptorOptions.WireGuard + ".stderr")
		links, _ := exec.Command("ip", "-n", acceptorNS, "-json", "-details", "link", "show").Output()
		routes, _ := exec.Command("ip", "-n", acceptorNS, "-json", "route", "show", "table", "all", "dev", "wg-demo").Output()
		t.Fatalf("%v; wg commands=%q stderr=%q namespace links=%s routes=%s", err, arguments, stderr, links, routes)
	}
	defer acceptorTransaction.Rollback()
	initiatorTransaction, err := applyWireGuard(initiatorProfile, nil,
		&wireGuardIdentity{WGPublicKey: initiatorPublic}, initiatorOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer initiatorTransaction.Rollback()

	waitTunnel := func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			command := exec.Command("ip", "netns", "exec", initiatorNS, "ping", "-n", "-c", "1", "-W", "1", "10.20.0.2")
			if body, pingErr := command.CombinedOutput(); pingErr == nil {
				return
			} else if time.Now().After(deadline) {
				initiatorState, _ := exec.Command("ip", "netns", "exec", initiatorNS, "wg", "show").CombinedOutput()
				acceptorState, _ := exec.Command("ip", "netns", "exec", acceptorNS, "wg", "show").CombinedOutput()
				t.Fatalf("reverse initiator did not establish the tunnel: %v: %s\ninitiator:\n%s\nacceptor:\n%s",
					pingErr, body, initiatorState, acceptorState)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitTunnel()

	roundTrip := func(network, listen, connect, payload string) {
		t.Helper()
		server := exec.Command("ip", "netns", "exec", acceptorNS, "socat", listen, "EXEC:/bin/cat")
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_ = server.Process.Kill()
			_ = server.Wait()
		}()
		var output []byte
		var clientErr error
		for until := time.Now().Add(3 * time.Second); time.Now().Before(until); time.Sleep(50 * time.Millisecond) {
			client := exec.Command("ip", "netns", "exec", initiatorNS, "socat", "-", connect)
			client.Stdin = strings.NewReader(payload)
			output, clientErr = client.Output()
			if clientErr == nil && string(output) == payload {
				return
			}
		}
		t.Fatalf("%s did not traverse reverse WireGuard: output=%q err=%v", network, output, clientErr)
	}
	roundTrip("TCP", "TCP4-LISTEN:18080,bind=10.20.0.2,reuseaddr", "TCP4:10.20.0.2:18080", "tcp-through-wg")
	roundTrip("UDP", "UDP4-RECVFROM:18053,bind=10.20.0.2,reuseaddr", "UDP4:10.20.0.2:18053", "udp-through-wg")

	if err := readbackWireGuard(*initiatorProfile, initiatorOptions); err != nil {
		t.Fatalf("initiator readback: %v", err)
	}
	if err := readbackWireGuard(*acceptorProfile, acceptorOptions); err != nil {
		t.Fatalf("acceptor readback: %v", err)
	}
	initiatorTransaction.Commit()
	acceptorTransaction.Commit()
	beforeInitiator, beforeAcceptor := initiatorTransaction, acceptorTransaction
	beforeLinks := string(run("-n", initiatorNS, "-json", "-details", "link", "show", "dev", "wg-demo"))
	if err := replaceWireGuard(&initiatorTransaction, *initiatorProfile, &wireGuardIdentity{WGPublicKey: initiatorPublic}, initiatorOptions); err != nil {
		t.Fatal("reuse initiator", err)
	}
	if err := replaceWireGuard(&acceptorTransaction, *acceptorProfile, &wireGuardIdentity{WGPublicKey: acceptorPublic}, acceptorOptions); err != nil {
		t.Fatal("reuse acceptor", err)
	}
	if initiatorTransaction != beforeInitiator || acceptorTransaction != beforeAcceptor || beforeLinks != string(run("-n", initiatorNS, "-json", "-details", "link", "show", "dev", "wg-demo")) {
		t.Fatal("unchanged View replaced a real kernel interface")
	}
	roundTrip("TCP after reuse", "TCP4-LISTEN:18082,bind=10.20.0.2,reuseaddr", "TCP4:10.20.0.2:18082", "tcp-after-reuse")
	roundTrip("UDP after reuse", "UDP4-RECVFROM:18055,bind=10.20.0.2,reuseaddr", "UDP4:10.20.0.2:18055", "udp-after-reuse")

	// A committed runtime retains its cleanup handle. Stop it before creating
	// the next generation; a previous profile never permits blind host adoption.
	if err := initiatorTransaction.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := acceptorTransaction.Cleanup(); err != nil {
		t.Fatal(err)
	}
	acceptorRestart, err := applyWireGuard(acceptorProfile, acceptorProfile,
		&wireGuardIdentity{WGPublicKey: acceptorPublic}, acceptorOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer acceptorRestart.Rollback()
	initiatorRestart, err := applyWireGuard(initiatorProfile, initiatorProfile,
		&wireGuardIdentity{WGPublicKey: initiatorPublic}, initiatorOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer initiatorRestart.Rollback()
	waitTunnel()
	roundTrip("TCP after restart", "TCP4-LISTEN:18081,bind=10.20.0.2,reuseaddr", "TCP4:10.20.0.2:18081", "tcp-after-restart")
	roundTrip("UDP after restart", "UDP4-RECVFROM:18054,bind=10.20.0.2,reuseaddr", "UDP4:10.20.0.2:18054", "udp-after-restart")
	initiatorRestart.Commit()
	acceptorRestart.Commit()
	// External crash cleanup consumes only the original public ownership record.
	if err := CleanupWireGuard(initiatorOptions); err != nil {
		t.Fatal("initiator crash cleanup", err)
	}
	if err := CleanupWireGuard(acceptorOptions); err != nil {
		t.Fatal("acceptor crash cleanup", err)
	}
	for _, namespace := range []string{initiatorNS, acceptorNS} {
		if exec.Command("ip", "-n", namespace, "link", "show", "dev", "wg-demo").Run() == nil {
			t.Fatal("crash cleanup retained a real kernel interface")
		}
	}
}
