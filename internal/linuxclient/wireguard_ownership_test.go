package linuxclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type fakeWireGuardHost struct {
	Link      *ipLinkDocument
	Addresses []string
	Routes    []ipRouteDocument
	Peer      bool
	ExtraPeer bool
	AllowedIP string
	Fail      string
	Calls     [][]string
}

func TestWireGuardRecordedGenerationSurvivesCrashButCannotClaimReplacement(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		options, profile, identity, load, save := wireGuardFixture(t)
		options.Config = filepath.Join(t.TempDir(), "config.json")
		if _, err := applyWireGuard(profile, nil, identity, options); err != nil {
			t.Fatal(err)
		}
		if replaced {
			host := load()
			host.Link.Index++
			save(host)
		}
		err := CleanupWireGuard(options)
		if replaced {
			if !errors.Is(err, ErrWireGuardCleanup) || load().Link == nil {
				t.Fatal("crash cleanup claimed a replacement interface", err)
			}
		} else if err != nil || load().Link != nil {
			t.Fatal("crash cleanup did not remove its exact generation", err)
		}
	}
}

// This subprocess implements only a file-backed command fixture. It never
// invokes ip, wg, a network namespace or another host network command.
func TestWireGuardHostCommand(t *testing.T) {
	separator := -1
	for i, arg := range os.Args {
		if arg == "--wireguard-host-fixture" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return
	}
	root, binary := os.Args[separator+1], os.Args[separator+2]
	args := os.Args[separator+3:]
	path := filepath.Join(root, "host.json")
	var host fakeWireGuardHost
	body, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(body, &host) != nil {
		os.Exit(90)
	}
	host.Calls = append(host.Calls, append([]string{binary}, args...))
	status := 0
	defer func() {
		body, err := json.Marshal(host)
		if err != nil || os.WriteFile(path, body, 0o600) != nil {
			os.Exit(91)
		}
		os.Exit(status)
	}()
	emit := func(value any) { _ = json.NewEncoder(os.Stdout).Encode(value) }
	joined := strings.Join(args, " ")
	if binary == "ip" {
		switch {
		case joined == "-json -details link show":
			links := []ipLinkDocument{}
			if host.Link != nil {
				links = append(links, *host.Link)
			}
			emit(links)
		case strings.HasPrefix(joined, "link add dev "):
			if host.Link != nil {
				status = 1
				return
			}
			host.Link = &ipLinkDocument{Index: 42, Name: args[3], Alias: args[5]}
			host.Link.Info.Kind = "wireguard"
			if host.Fail == "add" {
				status = 1
			}
		case strings.HasPrefix(joined, "link delete dev "):
			if host.Fail == "delete" || host.Fail == "address-delete" {
				status = 1
				return
			}
			if host.Fail == "delete-noop" {
				return
			}
			host.Link, host.Addresses, host.Routes = nil, nil, nil
			host.Peer = false
		case strings.HasPrefix(joined, "address add "):
			if host.Fail == "address" || host.Fail == "address-delete" {
				status = 1
				return
			}
			host.Addresses = []string{args[2]}
		case strings.HasPrefix(joined, "link set dev "):
			if len(args) == 6 && args[4] == "alias" {
				host.Link.Alias = args[5]
			}
			if len(args) == 6 && args[4] == "name" {
				host.Link.Name = args[5]
			}
		case strings.HasPrefix(joined, "route add "):
			host.Routes = []ipRouteDocument{{Destination: args[2], Device: args[4], Protocol: "static", Scope: "link"}}
		case strings.HasPrefix(joined, "-json address show dev "):
			addresses := []map[string]any{}
			for _, address := range host.Addresses {
				parts := strings.Split(address, "/")
				prefix, _ := strconv.Atoi(parts[1])
				addresses = append(addresses, map[string]any{"local": parts[0], "prefixlen": prefix})
			}
			emit([]map[string]any{{"addr_info": addresses}})
		case strings.Contains(joined, "route show"):
			routes := host.Routes
			if routes == nil || strings.Contains(joined, "-6") {
				routes = []ipRouteDocument{}
			}
			emit(routes)
		default:
			status = 92
		}
		return
	}
	const public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	switch {
	case joined == "pubkey", joined == "show wg-demo public-key":
		fmt.Fprintln(os.Stdout, public)
	case strings.HasPrefix(joined, "set wg-demo "):
		host.Peer, host.AllowedIP = true, "192.0.2.2/32"
	case len(args) == 3 && args[0] == "show" && args[1] != "all" && args[2] == "dump":
		fmt.Fprintln(os.Stdout, "fixture-private\t"+public+"\t51820\toff")
		if host.Peer {
			fmt.Fprintf(os.Stdout, "%s\t(none)\t(none)\t%s\t0\t0\t0\toff\n", public, host.AllowedIP)
		}
		if host.ExtraPeer {
			fmt.Fprintln(os.Stdout, "unknown-peer\t(none)\t(none)\t198.51.100.2/32\t0\t0\t0\toff")
		}
	case joined == "show all dump":
		fmt.Fprintln(os.Stdout, "wg-demo\tfixture-private\t"+public+"\t51820\toff")
		if host.Peer {
			fmt.Fprintf(os.Stdout, "wg-demo\t%s\t(none)\t(none)\t%s\t0\t0\t0\toff\n", public, host.AllowedIP)
		}
	default:
		status = 93
	}
}

func wireGuardFixture(t *testing.T) (Options, *wireGuardExecution, *wireGuardIdentity, func() fakeWireGuardHost, func(fakeWireGuardHost)) {
	t.Helper()
	root := t.TempDir()
	load := func() fakeWireGuardHost {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(root, "host.json"))
		var host fakeWireGuardHost
		if err != nil || json.Unmarshal(body, &host) != nil {
			t.Fatal("fixture read failed")
		}
		return host
	}
	save := func(host fakeWireGuardHost) {
		t.Helper()
		body, err := json.Marshal(host)
		if err != nil || os.WriteFile(filepath.Join(root, "host.json"), body, 0o600) != nil {
			t.Fatal("fixture write failed")
		}
	}
	save(fakeWireGuardHost{})
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
	command := func(name string) string {
		path := filepath.Join(root, name)
		script := "#!/bin/sh\nexec " + quote(binary) + " -test.run=^TestWireGuardHostCommand$ -- --wireguard-host-fixture " + quote(root) + " " + quote(name) + " \"$@\"\n"
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key := filepath.Join(root, "node.key")
	if err := os.WriteFile(key, []byte("fixture-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := Options{IP: command("ip"), WireGuard: command("wg"), WireGuardPrivateKey: key}
	profile := &wireGuardExecution{WireGuard: []wireGuardExecutionLink{{
		LinkID: "demo-link", Interface: "wg-demo", LocalAddress: "192.0.2.1/32", PeerID: "demo-peer",
		PeerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", AllowedIP: "192.0.2.2/32", Mode: "acceptor", ListenPort: 51820,
	}}}
	server := &wireGuardIdentity{WGPublicKey: profile.WireGuard[0].PeerPublicKey}
	return options, profile, server, load, save
}

func TestWireGuardEmptyRuntimeDoesNotExecuteHostCommands(t *testing.T) {
	transaction, err := applyWireGuard(nil, nil, nil, Options{})
	if err != nil || transaction.Cleanup() != nil || readbackWireGuard(wireGuardExecution{}, Options{}) != nil {
		t.Fatalf("empty runtime performed host work: %v", err)
	}
}

func TestWireGuardPreviousAuthorizationDoesNotOwnExistingInterface(t *testing.T) {
	options, profile, server, load, save := wireGuardFixture(t)
	host := load()
	host.Link = &ipLinkDocument{Index: 17, Name: "wg-demo", Alias: "another-runtime"}
	host.Link.Info.Kind = "wireguard"
	save(host)
	for _, desired := range []*wireGuardExecution{profile, nil} {
		_, err := applyWireGuard(desired, profile, server, options)
		if !errors.Is(err, ErrWireGuardOwnership) {
			t.Fatalf("existing interface ownership was accepted: %v", err)
		}
	}
	for _, call := range load().Calls {
		if strings.Join(call, " ") != "ip -json -details link show" {
			t.Fatalf("unknown interface was modified or inspected as owned: %v", call)
		}
	}
}

func TestWireGuardCommitRetainsIdempotentCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private-key boundary requires a root-owned fixture")
	}
	options, profile, server, load, _ := wireGuardFixture(t)
	transaction, err := applyWireGuard(profile, nil, server, options)
	if err != nil {
		t.Fatal(err)
	}
	transaction.Commit()
	if err := transaction.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Cleanup(); err != nil || load().Link != nil {
		t.Fatalf("cleanup retained the successful runtime: %v", err)
	}
	for _, call := range load().Calls {
		value := strings.Join(call, " ")
		if strings.Contains(value, "flush") || strings.Contains(value, "syncconf") || strings.Contains(value, "replace") {
			t.Fatalf("cleanup restored or flushed host state: %s", value)
		}
	}
}

func TestWireGuardCleanupRefusesDriftAndReportsDeleteFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private-key boundary requires a root-owned fixture")
	}
	for _, drift := range []string{"alias", "index", "rename", "peer", "address", "route", "delete", "delete-noop"} {
		t.Run(drift, func(t *testing.T) {
			options, profile, server, load, save := wireGuardFixture(t)
			transaction, err := applyWireGuard(profile, nil, server, options)
			if err != nil {
				t.Fatal(err)
			}
			host := load()
			switch drift {
			case "alias":
				host.Link.Alias = "another-runtime"
			case "index":
				host.Link.Index++
			case "rename":
				host.Link.Name = "wg-another"
			case "peer":
				host.ExtraPeer = true
			case "address":
				host.Addresses = append(host.Addresses, "198.51.100.1/32")
			case "route":
				host.Routes = append(host.Routes, ipRouteDocument{Destination: "198.51.100.2/32", Device: "wg-demo"})
			case "delete", "delete-noop":
				host.Fail = drift
			}
			host.Calls = nil
			save(host)
			err = transaction.Cleanup()
			if !errors.Is(err, ErrWireGuardCleanup) || load().Link == nil {
				t.Fatalf("cleanup hid failure or deleted a changed interface: %v", err)
			}
			if !strings.HasPrefix(drift, "delete") {
				if !errors.Is(err, ErrWireGuardOwnership) {
					t.Fatalf("drift lost the ownership error: %v", err)
				}
				for _, call := range load().Calls {
					if strings.Contains(strings.Join(call, " "), "link delete") {
						t.Fatalf("drift was deleted: %v", call)
					}
				}
			}
		})
	}
}

func TestWireGuardApplyFailureRemovesOnlyNewGeneration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private-key boundary requires a root-owned fixture")
	}
	for _, failure := range []string{"add", "address"} {
		t.Run(failure, func(t *testing.T) {
			options, profile, server, load, save := wireGuardFixture(t)
			host := load()
			host.Fail = failure
			save(host)
			_, err := applyWireGuard(profile, nil, server, options)
			if err == nil || errors.Is(err, ErrWireGuardCleanup) || load().Link != nil {
				t.Fatalf("failed apply did not remove the newly created peer: %v", err)
			}
			for _, call := range load().Calls {
				if strings.Contains(strings.Join(call, " "), "syncconf") {
					t.Fatal("failed apply restored a revoked configuration")
				}
			}
		})
	}
}

func TestWireGuardApplyPreservesCleanupFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private-key boundary requires a root-owned fixture")
	}
	options, profile, server, load, save := wireGuardFixture(t)
	host := load()
	host.Fail = "address-delete"
	save(host)
	_, err := applyWireGuard(profile, nil, server, options)
	if !errors.Is(err, ErrWireGuardCleanup) || load().Link == nil {
		t.Fatalf("apply lost the cleanup failure needed to prevent restart: %v", err)
	}
}
