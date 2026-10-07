//go:build linux

package linuxclient

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealWireGuardAccessUpdateFailure(t *testing.T) {
	if os.Getenv("LOOM_REAL_WG_TEST") != "1" {
		t.Skip("opt-in isolated kernel test")
	}
	for _, name := range []string{"net", "mnt"} {
		self, e1 := os.Readlink("/proc/self/ns/" + name)
		initial, e2 := os.Readlink("/proc/1/ns/" + name)
		if e1 != nil || e2 != nil || self == initial {
			t.Fatal("separate network and mount namespaces required")
		}
	}
	type fixture struct {
		Root, Key, Public string
		Peers             []string
	}
	if mode := os.Getenv("LOOM_WG_ACCESS_WORKER"); mode != "" {
		var input fixture
		body, err := os.ReadFile(os.Getenv("LOOM_WG_ACCESS_INPUT"))
		if err != nil || json.Unmarshal(body, &input) != nil {
			t.Fatal("worker input unavailable")
		}
		options := Options{IP: "/usr/sbin/ip", WireGuard: "/usr/bin/wg", NFT: "/usr/sbin/nft", WireGuardPrivateKey: input.Key, Config: filepath.Join(input.Root, "runtime.json")}
		makePeer := func(i int) wireGuardExecutionLink {
			return wireGuardExecutionLink{LinkID: "demo-resource", Interface: "wg-demo", LocalAddress: "198.51.100.1/32", PeerID: []string{"demo-a", "demo-b", "demo-c"}[i], PeerPublicKey: input.Peers[i], AllowedIP: []string{"fdab::2/128", "fdab::3/128", "fdab::4/128"}[i], Mode: "acceptor", ListenPort: 51888, AccessAddress: "fdab::1/128", AccessPort: 18443}
		}
		profile := wireGuardExecution{WireGuard: []wireGuardExecutionLink{makePeer(0), makePeer(1)}}
		identity := &wireGuardIdentity{WGPublicKey: input.Public}
		// An assigned host address must reject before any WG interface/filter exists.
		if err := exec.Command(options.IP, "address", "add", "fdab::2/128", "dev", "lo").Run(); err != nil {
			t.Fatal(err)
		}
		if _, err := applyWireGuard(&profile, nil, identity, options); err == nil {
			t.Fatal("existing local address was stolen")
		}
		if exec.Command(options.IP, "link", "show", "wg-demo").Run() == nil {
			t.Fatal("collision created an interface")
		}
		if err := exec.Command(options.IP, "address", "delete", "fdab::2/128", "dev", "lo").Run(); err != nil {
			t.Fatal(err)
		}
		transaction, err := applyWireGuard(&profile, nil, identity, options)
		if err != nil {
			t.Fatal(err)
		}
		wrapper := filepath.Join(input.Root, "ip-fail")
		action := "exit 1"
		if mode == "crash" {
			action = "kill -KILL \"$PPID\"; exit 1"
		}
		script := "#!/bin/sh\nif [ \"$1\" = route ] && [ \"$2\" = add ] && [ \"$3\" = fdab::4/128 ]; then " + action + "; fi\nexec /usr/sbin/ip \"$@\"\n"
		if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		options.IP = wrapper
		transaction.options = options
		profile.WireGuard = []wireGuardExecutionLink{makePeer(1), makePeer(2)}
		if err := replaceWireGuard(&transaction, profile, identity, options); err == nil {
			t.Fatal("partial update reported success")
		}
		if mode == "crash" {
			t.Fatal("worker survived controlled crash")
		}
		if _, err := os.Stat(options.Config + ".wg-ownership"); !os.IsNotExist(err) {
			t.Fatal("failed update retained cleanup state", err)
		}
		return
	}
	run := func(name string, args ...string) []byte {
		t.Helper()
		body, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("kernel lifecycle command failed: %v", err)
		}
		return body
	}
	baselineRoutes := run("ip", "-json", "route", "show", "table", "all")
	baselineRules := run("ip", "-json", "rule", "show")
	baselineTables := run("nft", "-j", "list", "tables")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"failure", "crash"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			input := fixture{Root: root}
			for i := 0; i < 4; i++ {
				private, err := exec.Command("wg", "genkey").Output()
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("wg", "pubkey")
				cmd.Stdin = bytes.NewReader(private)
				public, err := cmd.Output()
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					file, err := os.CreateTemp("/etc/wireguard", ".loom-demo-access-*")
					if err != nil {
						t.Fatal(err)
					}
					input.Key = file.Name()
					t.Cleanup(func() { _ = os.Remove(input.Key) })
					if _, err := file.Write(private); err != nil {
						t.Fatal(err)
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
					input.Public = strings.TrimSpace(string(public))
				} else {
					input.Peers = append(input.Peers, strings.TrimSpace(string(public)))
				}
			}
			body, _ := json.Marshal(input)
			path := filepath.Join(root, "fixture.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(binary, "-test.run=^TestRealWireGuardAccessUpdateFailure$", "-test.v")
			child.Env = append(os.Environ(), "LOOM_WG_ACCESS_WORKER="+mode, "LOOM_WG_ACCESS_INPUT="+path)
			output, err := child.CombinedOutput()
			if mode == "failure" && err != nil {
				t.Fatalf("failure cleanup: %v: %s", err, output)
			}
			if mode == "crash" {
				if err == nil {
					t.Fatal("worker did not crash")
				}
				var entries []wireGuardCleanupEntry
				if err := readStrict(filepath.Join(root, "runtime.json.wg-ownership"), 1<<20, &entries); err != nil || len(entries) != 1 || len(entries[0].Peers) != 2 {
					t.Fatal("crash lost the prior/new cleanup union", err)
				}
				peers := strings.Fields(string(run("wg", "show", "wg-demo", "peers")))
				if len(peers) != 2 {
					t.Fatal("controlled crash did not follow peer mutation")
				}
				for _, peer := range peers {
					if peer == input.Peers[0] {
						t.Fatal("withdrawn peer remained after mutation")
					}
				}
				if err := CleanupWireGuard(Options{Config: filepath.Join(root, "runtime.json")}); err != nil {
					t.Fatal("crash union could not clean partial routes", err)
				}
			}
			if exec.Command("ip", "link", "show", "wg-demo").Run() == nil {
				t.Fatal("partial update left WG active")
			}
			if !bytes.Equal(baselineRoutes, run("ip", "-json", "route", "show", "table", "all")) || !bytes.Equal(baselineRules, run("ip", "-json", "rule", "show")) || !bytes.Equal(baselineTables, run("nft", "-j", "list", "tables")) {
				t.Fatal("partial update left routes, rules or filtering behind")
			}
		})
	}
}
