//go:build linux

package linuxclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This tests the packet boundary with deliberately unrestricted raw sources;
// WireGuard key exchange and formal Service access are verified separately.
func TestRealWireGuardAccessFilter(t *testing.T) {
	if os.Getenv("LOOM_REAL_WG_TEST") != "1" {
		t.Skip("opt-in isolated kernel test")
	}
	self, _ := os.Readlink("/proc/self/ns/net")
	initial, _ := os.Readlink("/proc/1/ns/net")
	mount, _ := os.Readlink("/proc/self/ns/mnt")
	initialMount, _ := os.Readlink("/proc/1/ns/mnt")
	if self == "" || self == initial || mount == "" || mount == initialMount {
		t.Fatal("test requires separate network and mount namespaces")
	}
	for _, name := range []string{"ip", "nft", "socat", "python3"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	suffix := strconv.Itoa(os.Getpid())
	names := []string{"demo-wgf-c-" + suffix, "demo-wgf-s-" + suffix, "demo-wgf-l-" + suffix}
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("kernel test command %s failed: %v: %s", args[0], err, out)
		}
		return out
	}
	for _, ns := range names {
		run("ip", "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		run("ip", "-n", ns, "link", "set", "lo", "up")
	}
	client, server, lan := names[0], names[1], names[2]
	run("ip", "-n", client, "link", "add", "demo-client", "type", "veth", "peer", "name", "demo-wg", "netns", server)
	run("ip", "-n", server, "link", "add", "demo-lan", "type", "veth", "peer", "name", "demo-target", "netns", lan)
	for _, row := range [][]string{{client, "demo-client", "fdab::2/64"}, {client, "demo-client", "fdab::3/64"}, {server, "demo-wg", "fdab::1/64"}, {server, "lo", "fdab::9/128"}, {server, "demo-lan", "fdac::1/64"}, {lan, "demo-target", "fdac::2/64"}, {client, "demo-client", "198.51.100.2/24"}, {server, "demo-wg", "198.51.100.1/24"}} {
		run("ip", "-n", row[0], "address", "add", row[2], "dev", row[1], "nodad")
		run("ip", "-n", row[0], "link", "set", row[1], "up")
	}
	run("ip", "-n", client, "-6", "route", "add", "fdac::/64", "via", "fdab::1")
	run("ip", "-n", client, "-6", "route", "add", "fdab::9/128", "via", "fdab::1")
	run("ip", "-n", lan, "-6", "route", "add", "fdab::/64", "via", "fdac::1")
	run("ip", "netns", "exec", server, "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")
	// A routed data packet does not need neighbor discovery to enter or leave
	// WireGuard. Static neighbors provide that same precondition on this veth.
	for _, row := range [][]string{{client, "fdab::1", "demo-client", server, "demo-wg"}, {server, "fdab::2", "demo-wg", client, "demo-client"}, {server, "fdab::3", "demo-wg", client, "demo-client"}} {
		body := run("ip", "-n", row[3], "-o", "link", "show", row[4])
		fields := strings.Fields(string(body))
		mac := ""
		for i := range fields {
			if fields[i] == "link/ether" && i+1 < len(fields) {
				mac = fields[i+1]
			}
		}
		if mac == "" {
			t.Fatal("veth MAC unavailable")
		}
		run("ip", "-n", row[0], "-6", "neigh", "replace", row[1], "lladdr", mac, "nud", "permanent", "dev", row[2])
	}
	wrapper := filepath.Join(root, "nft")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec /usr/sbin/ip netns exec "+server+" /usr/sbin/nft \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	options := Options{NFT: wrapper}
	peer := wireGuardExecutionLink{LinkID: "demo-resource", Interface: "demo-wg", LocalAddress: "198.51.100.1/32", PeerID: "demo-access", PeerPublicKey: "demo-key", AllowedIP: "fdab::2/128", Mode: "acceptor", ListenPort: 51820, AccessAddress: "fdab::1/128", AccessPort: 18443}
	other := peer
	other.PeerID = "demo-other"
	other.PeerPublicKey = "demo-other-key"
	other.AllowedIP = "fdab::3/128"
	relay := peer
	relay.PeerID = "demo-relay"
	relay.PeerPublicKey = "demo-relay-key"
	relay.AllowedIP = "198.51.100.2/32"
	relay.AccessAddress = ""
	relay.AccessPort = 0
	owned := wireGuardOwnedLink{link: peer, peers: []wireGuardExecutionLink{other, relay}, alias: "loom-runtime:" + strings.Repeat("a", 32)}
	if err := installWireGuardFilter(options, owned); err != nil {
		actual, _, _ := readWireGuardFilter(options, owned)
		wanted := wireGuardFilterObjects(owned)
		for i := range actual {
			if i >= len(wanted) {
				break
			}
			a, _ := json.Marshal(actual[i])
			b, _ := json.Marshal(wanted[i])
			if !bytes.Equal(a, b) {
				t.Logf("actual %s; expected %s", a, b)
				break
			}
		}
		t.Fatal(err)
	}
	if _, err := verifyWireGuardFilter(options, owned); err != nil {
		t.Fatal(err)
	}
	startEcho := func(ns, address string, port int, label string, stream bool) string {
		t.Helper()
		received := filepath.Join(root, label+".received")
		ready := received + ".ready"
		code := `import socket,sys,pathlib
host,port,received,ready,stream=sys.argv[1:]
stream=stream=='true'
s=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_STREAM if stream else socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((host,int(port)))
if stream:s.listen()
pathlib.Path(ready).touch()
while True:
 if stream:
  c,peer=s.accept();data=c.recv(4096)
 else:data,peer=s.recvfrom(4096)
 with open(received,'ab') as f:f.write(data)
 if stream:c.sendall(data);c.close()
 else:s.sendto(data,peer)
`
		command := exec.Command("ip", "netns", "exec", ns, "python3", "-u", "-c", code, address, strconv.Itoa(port), received, ready, strconv.FormatBool(stream))
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(ready); err == nil {
				return received
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("UDP target did not start")
		return ""
	}
	allowed := startEcho(server, "fdab::1", 18443, "demo-allowed", false)
	wrongPort := startEcho(server, "fdab::1", 18053, "demo-other-port", false)
	wrongHost := startEcho(server, "fdab::9", 18443, "demo-other-host", false)
	lanTarget := startEcho(lan, "fdac::2", 18443, "demo-lan", false)
	outputTarget := startEcho(client, "fdab::2", 19000, "demo-output", false)
	trusted := startEcho(server, "198.51.100.1", 18053, "demo-trusted-relay", false)
	wrongProtocol := startEcho(server, "fdab::1", 18443, "demo-tcp", true)
	request := func(ns, source, host string, port int, want bool) {
		t.Helper()
		network := "UDP6"
		destination := "[" + host + "]"
		if !strings.Contains(host, ":") {
			network = "UDP4"
			destination = host
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "socat", "-T1", "-", fmt.Sprintf("%s:%s:%d,bind=%s", network, destination, port, source))
		command.Stdin = strings.NewReader("demo-packet")
		out, err := command.Output()
		if want && (err != nil || !bytes.Equal(out, []byte("demo-packet"))) {
			t.Fatalf("allowed packet failed: %v", err)
		}
		if !want && len(out) != 0 {
			t.Fatal("forbidden packet returned data")
		}
	}
	requestTCP := func(want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "ip", "netns", "exec", client, "socat", "-T1", "-", "TCP6:[fdab::1]:18443,bind=[fdab::2]")
		command.Stdin = strings.NewReader("demo-packet")
		out, err := command.Output()
		if want && (err != nil || !bytes.Equal(out, []byte("demo-packet"))) {
			t.Fatalf("TCP baseline failed: %v", err)
		}
		if !want && len(out) != 0 {
			t.Fatal("TCP crossed UDP-only boundary")
		}
	}
	requestTCP(false)
	request(client, "[fdab::2]", "fdab::1", 18443, true)
	request(client, "[fdab::3]", "fdab::1", 18443, true)
	request(client, "198.51.100.2", "198.51.100.1", 18053, true)
	request(client, "[fdab::2]", "fdab::1", 18053, false)
	request(client, "[fdab::2]", "fdab::9", 18443, false)
	request(client, "[fdab::2]", "fdac::2", 18443, false)
	request(server, "[fdab::1]:19001", "fdab::2", 19000, false)
	// Force the peer destination through the receiver, like a malicious WG
	// client with broader local AllowedIPs. There is no directly shared LAN.
	run("ip", "-n", client, "-6", "route", "add", "fdab::3/128", "via", "fdab::1")
	// Move the other recipient to a separate namespace, with a working return
	// path. It must not be locally delivered in the sender before filtering.
	run("ip", "-n", client, "address", "del", "fdab::3/64", "dev", "demo-client")
	run("ip", "-n", lan, "address", "add", "fdab::3/128", "dev", "lo", "nodad")
	run("ip", "-n", server, "-6", "route", "add", "fdab::3/128", "via", "fdac::2")
	peerTarget := startEcho(lan, "fdab::3", 18443, "demo-peer", false)
	request(client, "[fdab::2]", "fdab::3", 18443, false)
	for _, file := range []string{wrongPort, wrongHost, lanTarget, peerTarget, outputTarget, wrongProtocol} {
		if data, _ := os.ReadFile(file); len(data) != 0 {
			t.Fatal("forbidden packet reached a target")
		}
	}
	for _, file := range []string{allowed, trusted} {
		if data, _ := os.ReadFile(file); len(data) == 0 {
			t.Fatal("legitimate target was not exercised")
		}
	}
	if err := cleanupWireGuardFilter(options, owned); err != nil {
		t.Fatal(err)
	}
	// Prove the rejected workloads and return paths really work without this
	// boundary; a missing listener or ordinary routing failure is not denial.
	request(client, "[fdab::2]", "fdab::1", 18053, true)
	request(client, "[fdab::2]", "fdab::9", 18443, true)
	request(client, "[fdab::2]", "fdac::2", 18443, true)
	request(client, "[fdab::2]", "fdab::3", 18443, true)
	request(server, "[fdab::1]:19001", "fdab::2", 19000, true)
	requestTCP(true)
	if err := installWireGuardFilter(options, owned); err != nil {
		t.Fatal(err)
	}
	// Extra objects invalidate ownership; cleanup must leave the changed table.
	run("ip", "netns", "exec", server, "nft", "add", "rule", "inet", wireGuardFilterName(owned), "input", "counter")
	if _, err := verifyWireGuardFilter(options, owned); err == nil {
		t.Fatal("extra rule was accepted")
	}
	if err := cleanupWireGuardFilter(options, owned); err == nil {
		t.Fatal("changed table was deleted")
	}
	// Namespace destruction owns the modified test table. A separate exact
	// table exercises normal deletion and idempotent crash cleanup.
	clean := owned
	clean.alias = "loom-runtime:" + strings.Repeat("b", 32)
	if err := installWireGuardFilter(options, clean); err != nil {
		t.Fatal(err)
	}
	if err := cleanupWireGuardFilter(options, clean); err != nil {
		t.Fatal(err)
	}
	if err := cleanupWireGuardFilter(options, clean); err != nil {
		t.Fatal(err)
	}
}
