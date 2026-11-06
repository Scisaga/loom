package linuxclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

// Exercise the normal Mixed handshake over access -> forward -> egress. A
// closed final target must never receive a successful SOCKS5 reply from either
// native first-hop protocol. The caller supplies its name to avoid capture's
// optional IP sniff (which can itself acknowledge a SOCKS request on Read).
// HTTP CONNECT's optimistic 200 is not evidence of a downstream dial.
func TestNativeMixedTwoHopConnectWaitsForTarget(t *testing.T) {
	for _, finalTransport := range []string{"wireguard", "hysteria2"} {
		t.Run(finalTransport, func(t *testing.T) { testNativeMixedTwoHopConnectWaitsForTarget(t, finalTransport) })
	}
}

func testNativeMixedTwoHopConnectWaitsForTarget(t *testing.T, finalTransport string) {
	t.Helper()
	executable := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable in an isolated namespace")
	}
	business := isolatedPublicFixtureAddress(t)
	p, keys, input, at := nativeProjectionFixture(t)
	for i := range p.DeviceAuthorizations {
		p.DeviceAuthorizations[i].DNSServers = []string{"127.0.0.1"}
	}
	dns, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal("could not start the isolated authenticated resolver")
	}
	defer dns.Close()
	go func() {
		var buffer [2048]byte
		for {
			n, peer, err := dns.ReadFrom(buffer[:])
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			question := query.Questions[0]
			query.Response, query.RecursionAvailable = true, true
			if question.Name.String() == "demo-target.example." {
				if question.Type == dnsmessage.TypeA {
					query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: business.As4()}}}
				}
			} else {
				query.RCode = dnsmessage.RCodeNameError
			}
			if body, err := query.Pack(); err == nil {
				_, _ = dns.WriteTo(body, peer)
			}
		}
	}()
	var inputs ResourceInputs
	if err := readStrict(input, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	if finalTransport == "hysteria2" {
		p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(resource control.TransportResource) bool {
			return resource.OwnerNodeID == "demo-exit"
		})
		for _, resource := range p.NetworkIntent.Resources {
			if resource.Kind == "hysteria2" {
				var listener ResourceListenerInput
				for _, current := range inputs.Listeners {
					if current.ResourceID == resource.ID {
						listener = current
						break
					}
				}
				if listener.CertificateFile == "" || listener.KeyFile == "" {
					t.Fatal("Hy2 fixture lost its original protected TLS references")
				}
				resource.ID, resource.OwnerNodeID, resource.ListenerID = "demo-exit-hy2", "demo-exit", "demo-exit-hy2"
				p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, resource)
				listener.ResourceID = resource.ID
				inputs.Listeners = append(inputs.Listeners, listener)
				break
			}
		}
		sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
		sort.Slice(inputs.Listeners, func(i, j int) bool { return inputs.Listeners[i].ResourceID < inputs.Listeners[j].ResourceID })
	}
	for i := range p.NetworkIntent.Resources {
		resource := &p.NetworkIntent.Resources[i]
		probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal("could not allocate an isolated transport port")
		}
		resource.DialHost = "127.0.0.1"
		resource.DialPort = probe.LocalAddr().(*net.UDPAddr).Port
		if err := probe.Close(); err != nil {
			t.Fatal(err)
		}
		for j := range inputs.Listeners {
			if inputs.Listeners[j].ResourceID != resource.ID {
				continue
			}
			if resource.Kind == "wireguard" {
				inputs.Listeners[j].ListenPort = resource.DialPort
			} else {
				inputs.Listeners[j].Listen = net.JoinHostPort(resource.DialHost, fmt.Sprint(resource.DialPort))
			}
		}
	}
	if err := atomicJSON(input, inputs); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var source control.DeviceView
	var sourceConfig string
	for _, id := range []string{"demo-exit", "demo-entry", "demo-access"} {
		view, config := startNativeTCPFixtureNode(t, ctx, p, id, input, executable, keys[id], at, id == "demo-access")
		if id == "demo-access" {
			source, sourceConfig = view, config
		}
	}
	selector, err := NewHTTPSelector(sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitSelector(ctx, selector, []string{"access"}); err != nil {
		t.Fatal(err)
	}
	// Match the normal supervisor's permission/description preparation before
	// selecting a path. A successful CAS does not install missing descriptors.
	if err := selector.ApplyRuntimePermissions(ctx, sourceConfig); err != nil {
		t.Fatal("current native permissions were not confirmed", err)
	}
	if ready, err := selector.ReconcileRuntimeResources(ctx, sourceConfig); err != nil || !ready {
		t.Fatal("current native resource descriptions were not confirmed", err)
	}
	execution, err := control.ProjectDeviceCandidates(source, []string{"demo-policy"})
	if err != nil || len(execution.Routes) != 2 {
		t.Fatal("expected exactly two authorized first-hop transports", err)
	}
	routes, graphs, err := clientadapter.AccessRoutingInputs(source, []string{"demo-policy"})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := clientadapter.NativeExecutionSpec(source, routes, graphs, "demo-policy")
	if err != nil {
		t.Fatal("native observation execution binding failed", err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal("could not start the isolated ordinary target")
	}
	defer listener.Close()
	namedTarget := func(address net.Addr) string {
		t.Helper()
		_, port, err := net.SplitHostPort(address.String())
		if err != nil {
			t.Fatal("isolated target address was not canonical")
		}
		return net.JoinHostPort("demo-target.example", port)
	}
	silent, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal("could not start the silent ordinary target")
	}
	defer silent.Close()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			// A target's TCP handshake is enough; it need not send or
			// receive any application byte to confirm the proxy connection.
			go func() { defer conn.Close(); _, _ = io.Copy(io.Discard, conn) }()
		}
	}()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := io.WriteString(conn, "demo-ready\n"); err == nil {
					_, _ = io.Copy(conn, conn)
				}
			}()
		}
	}()
	closed, err := net.Listen("tcp", net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal("could not reserve the unavailable target")
	}
	closedTarget := namedTarget(closed.Addr())
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal("could not construct the ordinary Mixed SOCKS5 caller")
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("ordinary SOCKS5 dial must respect the caller deadline")
	}
	connect := func(target string) (net.Conn, *bufio.Reader, bool) {
		t.Helper()
		dialContext, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		conn, err := contextDialer.DialContext(dialContext, "tcp", target)
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, nil, false
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		return conn, bufio.NewReader(conn), true
	}
	for _, candidate := range execution.Routes {
		choice := protocol.RouteChoice{EntryNodeID: candidate.EntryNodeID, FirstResourceID: candidate.FirstResourceID, FinalExit: candidate.FinalExit}
		if choice.EntryNodeID != "demo-entry" || choice.FinalExit != "demo-exit" {
			t.Fatal("fixture escaped its required forward and fixed final exit")
		}
		previous, err := selector.ReadSelection(ctx, "access")
		if err != nil {
			t.Fatal(err)
		}
		applied, err := selector.ApplySelection(ctx, previous, clientmodel.Selection{Scope: "access", PolicyID: candidate.PolicyID, CandidateID: candidate.ID, Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{candidate.ID: choice}})
		if err != nil {
			t.Fatal("normal complete selection was not accepted", err)
		}
		stream, reader, accepted := connect(namedTarget(listener.Addr()))
		if !accepted {
			t.Fatal("two-hop ordinary connection failed", candidate.FirstResourceID)
		}
		defer stream.Close()
		if banner, err := reader.ReadString('\n'); err != nil || banner != "demo-ready\n" {
			t.Fatal("confirmation waited for application input or consumed its first byte")
		}
		failed, _, accepted := connect(closedTarget)
		if failed != nil {
			failed.Close()
		}
		if accepted {
			t.Fatal("proxy reported success before the final target connected", candidate.FirstResourceID)
		}
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(stream, "demo-still-open\n"); err != nil {
			t.Fatal("failed new dial closed an established connection")
		}
		if reply, err := reader.ReadString('\n'); err != nil || reply != "demo-still-open\n" {
			t.Fatal("existing two-hop connection did not survive another dial failure")
		}
		next, nextReader, accepted := connect(namedTarget(listener.Addr()))
		if !accepted {
			t.Fatal("failed dial closed the shared transport")
		}
		if banner, err := nextReader.ReadString('\n'); err != nil || banner != "demo-ready\n" {
			t.Fatal("subsequent connection lost its confirmation or first byte")
		}
		next.Close()
		silentStream, _, accepted := connect(namedTarget(silent.Addr()))
		if !accepted {
			t.Fatal("connection confirmation required an application response")
		}
		silentStream.Close()
		body, err := selector.ReadNativeObservations(ctx)
		if err != nil {
			t.Fatal("actual native TCP outcomes were not readable", err)
		}
		memory, err := clientmodel.ConfirmSelection(clientmodel.SelectionMemory{PolicyID: candidate.PolicyID, NetworkGeneration: "demo-network"}, applied, 0)
		if err != nil {
			t.Fatal(err)
		}
		memory = clientadapter.BindNativeSelection(memory, applied, "demo-network", spec)
		state := clientadapter.State{Preference: clientmodel.Preference{Schema: 3, PolicyID: candidate.PolicyID}, NetworkGeneration: "demo-network", NativeExecutionSpec: spec, SelectionMemory: map[string]clientmodel.SelectionMemory{"access": memory}}
		observations, err := clientadapter.ConsumeNativeObservations(body, state, routes, time.Now())
		if err != nil {
			t.Fatal("actual TCP results could not enter the shared consumer", err)
		}
		foundSuccess, foundFailure := false, false
		for _, value := range observations {
			if value.CandidateID != candidate.ID || value.Action != "tcp_connect" {
				t.Fatal("TCP outcome was relabeled")
			}
			foundSuccess = foundSuccess || value.Target == namedTarget(listener.Addr()) && value.Result == "available"
			foundFailure = foundFailure || value.Target == closedTarget && value.Result == "unavailable"
		}
		if !foundSuccess || !foundFailure {
			t.Fatal("ordinary success or actual target failure was missing", candidate.FirstResourceID)
		}
	}
}

func startNativeTCPFixtureNode(t *testing.T, ctx context.Context, p control.Projection, id, input, executable, key string, at time.Time, exposeAPI bool) (control.DeviceView, string) {
	t.Helper()
	view, err := control.ProjectDeviceView(p, id)
	if err != nil {
		t.Fatal(id, err)
	}
	executions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(id, err)
	}
	config, err := nodeRuntimeConfig(view, "demo-local-secret", nil, "mixed", executions)
	if err != nil {
		t.Fatal(id, err)
	}
	config, err = appendNativeWireGuard(config, view, fixtureWGReceiver(t, view, executions), nil, key)
	if err != nil {
		t.Fatal(id, err)
	}
	if !exposeAPI {
		// Only access owns this fixture's local diagnostic/API ports.
		var document map[string]json.RawMessage
		var experimental map[string]json.RawMessage
		var inbounds []struct {
			Tag string `json:"tag"`
		}
		var rawInbounds []json.RawMessage
		if json.Unmarshal([]byte(config), &document) != nil || json.Unmarshal(document["experimental"], &experimental) != nil || json.Unmarshal(document["inbounds"], &inbounds) != nil || json.Unmarshal(document["inbounds"], &rawInbounds) != nil {
			t.Fatal("invalid rendered fixture facilities")
		}
		delete(experimental, "clash_api")
		kept := []json.RawMessage{}
		for i, inbound := range inbounds {
			if inbound.Tag != control.LinkProbeInbound {
				kept = append(kept, rawInbounds[i])
			}
		}
		document["experimental"], _ = json.Marshal(experimental)
		document["inbounds"], _ = json.Marshal(kept)
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		config = string(body)
	}
	if err := preflightRuntimeConfig(executable, config); err != nil {
		t.Fatal(id, err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	if exposeAPI {
		if err := writeNativeResourceConfig(path, config); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := writeConfig(path, config); err != nil {
			t.Fatal(err)
		}
	}
	log, err := os.OpenFile(filepath.Join(root, "runtime.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "run", "-c", path)
	command.Dir, command.Stdout, command.Stderr = root, log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(id, err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		if err := stopProcess(command, done); err != nil {
			t.Error("isolated native process termination was not confirmed")
		}
		log.Close()
	})
	if err := waitTransportResources(ctx, view, executions, command.Process.Pid, time.Now, done); err != nil {
		t.Fatal(id, "did not start its actual transport listeners")
	}
	return view, config
}
