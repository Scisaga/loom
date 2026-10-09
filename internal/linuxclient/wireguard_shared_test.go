package linuxclient

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/control"
)

// Two clients choose different exits for the identical original target through
// one entry. Only fixture socket coordinates vary; permissions, WG identities,
// target restoration and routing come from the formal control/runtime chain.
func TestRealSharedWGProjectedConcurrentExits(t *testing.T) {
	binary := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if binary == "" {
		t.Skip("requires an isolated native data-plane build")
	}
	if requireDifferentNetworkNamespace("/proc/self/ns/net", "/proc/1/ns/net") != nil {
		t.Fatal("dedicated network namespace required")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("fresh namespace required")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "add", "demo-underlay", "type", "dummy"}, {"link", "set", "demo-underlay", "up"}, {"route", "add", "default", "dev", "demo-underlay"}, {"address", "add", "192.0.2.10/32", "dev", "lo"}, {"address", "add", "192.0.2.11/32", "dev", "lo"}, {"address", "add", "192.0.2.12/32", "dev", "lo"}, {"address", "add", "192.0.2.13/32", "dev", "lo"}, {"address", "add", "192.0.2.80/32", "dev", "lo"}, {"address", "add", "2001:db8::80/128", "dev", "lo"}, {"address", "add", "2001:db8:1::2/128", "dev", "lo"}, {"address", "add", "2001:db8:1::3/128", "dev", "lo"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture network: %v %s", err, out)
		}
	}
	p, keys, input, at := nativeProjectionFixture(t)
	clientB := p.DeviceAuthorizations[0]
	clientB.ID, clientB.Name = "demo-access-b", "Demo access B"
	seed := sha256.Sum256([]byte("demo-access-b"))
	clientB.DevicePublicKey, clientB.RuntimeKey = base64.RawURLEncoding.EncodeToString(seed[:]), base64.RawURLEncoding.EncodeToString(seed[:])
	p.DeviceAuthorizations = append(p.DeviceAuthorizations, clientB)
	exitB := p.DeviceAuthorizations[2]
	exitB.ID, exitB.Name = "demo-exit-b", "Demo exit B"
	seed = sha256.Sum256([]byte("demo-exit-b"))
	exitB.DevicePublicKey, exitB.RuntimeKey = base64.RawURLEncoding.EncodeToString(seed[:]), base64.RawURLEncoding.EncodeToString(seed[:])
	p.DeviceAuthorizations = append(p.DeviceAuthorizations, exitB)
	seed[0] &= 248
	seed[31] = (seed[31] & 127) | 64
	key, _ := ecdh.X25519().NewPrivateKey(seed[:])
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	address := []string{"192.0.2.53/32"}
	resource := control.TransportResource{ID: "demo-exit-b-wg", Kind: "wireguard", OwnerNodeID: exitB.ID, ListenerID: "demo-exit-b-wg", DialHost: "192.0.2.13", DialPort: 51823, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: &address}}
	p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, resource)
	path := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed[:])), 0600); err != nil {
		t.Fatal(err)
	}
	keys[exitB.ID] = path
	dns, _ := control.WireGuardAccessAddress(resource, "")
	link := p.NetworkIntent.Links[0]
	link.ID = "demo-link-b"
	link.ToNodeID = exitB.ID
	link.ResourceID = resource.ID
	link.ProbeTarget = control.LinkProbeTarget{ResourceID: resource.ID, Host: dns.String(), Port: 53, Action: "wireguard_dns"}
	p.NetworkIntent.Links = append(p.NetworkIntent.Links, link)
	p.NetworkIntent.Policies[0].ExitScope.NodeIDs = []string{"demo-exit", "demo-exit-b"}
	p.NetworkIntent.Services[0].Matchers = append(p.NetworkIntent.Services[0].Matchers, control.ServiceMatcher{Kind: "ip_prefix", Value: "2001:db8::80/128"})
	sort.Slice(p.DeviceAuthorizations, func(i, j int) bool { return p.DeviceAuthorizations[i].ID < p.DeviceAuthorizations[j].ID })
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	label := func(address string) string {
		host, _, _ := net.SplitHostPort(address)
		if host == "127.0.0.2" || host == "2001:db8:1::2" {
			return "demo-exit"
		}
		if host == "127.0.0.3" || host == "2001:db8:1::3" {
			return "demo-exit-b"
		}
		return "demo-unexpected-source"
	}
	for _, host := range []string{"192.0.2.80", "2001:db8::80"} {
		address := net.JoinHostPort(host, "18080")
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, label(r.RemoteAddr)) })}
		go server.Serve(listener)
		t.Cleanup(func() { server.Close() })
		packet, err := net.ListenPacket("udp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { packet.Close() })
		go func() {
			body := make([]byte, 1024)
			for {
				n, remote, err := packet.ReadFrom(body)
				if err != nil {
					return
				}
				packet.WriteTo(append([]byte(label(remote.String())+":"), body[:n]...), remote)
			}
		}()
	}
	root := t.TempDir()
	logs := map[string]string{}
	stops := map[string]func(){}
	views := map[string]control.DeviceView{}
	selectors := map[string]*HTTPSelector{}
	launch := func(id string) {
		t.Helper()
		view, err := control.ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(id, err)
		}
		views[id] = view
		executions, err := prepareHY2Executions(view, input, at)
		if err != nil {
			t.Fatal(err)
		}
		config, err := nodeRuntimeConfig(view, "demo-secret", nil, "mixed", executions)
		if err != nil {
			t.Fatal(err)
		}
		config, err = appendNativeReceivers(config, view, wireGuardExecution{}, nil, keys[id])
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		json.Unmarshal([]byte(config), &document)
		if len(document["endpoints"].([]any)) != 1 {
			t.Fatal(id, "did not share one WG instance")
		}
		experimental := document["experimental"].(map[string]any)
		inbounds := []any{}
		for _, raw := range document["inbounds"].([]any) {
			inbound := raw.(map[string]any)
			if inbound["tag"] == control.LinkProbeInbound {
				continue
			}
			if id == "demo-access-b" && inbound["type"] == "mixed" {
				inbound["listen_port"] = 1081
			}
			inbounds = append(inbounds, inbound)
		}
		document["inbounds"] = inbounds
		if strings.HasPrefix(id, "demo-access") {
			selector, err := NewHTTPSelector(config)
			if err != nil {
				t.Fatal(err)
			}
			if id == "demo-access-b" {
				experimental["clash_api"].(map[string]any)["external_controller"] = "127.0.0.1:61803"
				selector.client.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:61803")
				}}
			}
			selectors[id] = selector
		} else {
			delete(experimental, "clash_api")
		}
		if id == "demo-exit" || id == "demo-exit-b" {
			number := 2
			if id == "demo-exit-b" {
				number = 3
			}
			for _, raw := range document["outbounds"].([]any) {
				out := raw.(map[string]any)
				if out["tag"] == "resource-egress" {
					out["inet4_bind_address"] = fmt.Sprintf("127.0.0.%d", number)
					out["inet6_bind_address"] = fmt.Sprintf("2001:db8:1::%d", number)
				}
			}
		}
		body, _ := json.Marshal(document)
		config, err = withPersistentDNSCache(string(body), filepath.Join(root, id+".state"))
		if err != nil {
			t.Fatal(err)
		}
		if err := preflightRuntimeConfig(binary, config); err != nil {
			t.Fatal(id, err)
		}
		file := filepath.Join(root, id+".json")
		if err := writeConfig(file, config); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(root, id+".log")
		log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatal(err)
		}
		logs[id] = logPath
		command := exec.Command(binary, "run", "-c", file)
		command.Stdout, command.Stderr = log, log
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait(); close(done) }()
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				stopProcess(command, done)
				log.Close()
			}
		}
		stops[id] = stop
		t.Cleanup(stop)
	}
	t.Cleanup(func() {
		if t.Failed() {
			for id, path := range logs {
				body, _ := os.ReadFile(path)
				t.Log(id, string(body))
			}
		}
	})
	for _, id := range []string{"demo-exit", "demo-exit-b", "demo-entry", "demo-access", "demo-access-b"} {
		launch(id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	selectPaths := func() {
		t.Helper()
		for index, id := range []string{"demo-access", "demo-access-b"} {
			selector := selectors[id]
			if err := waitSelector(ctx, selector, []string{"service:demo-service"}); err != nil {
				t.Fatal(err)
			}
			exit := []string{"demo-exit", "demo-exit-b"}[index]
			found := false
			for _, candidate := range views[id].Routes {
				if candidate.FinalExit == exit && candidate.FirstResourceID == "demo-entry-wg" {
					if err := selector.Set(ctx, candidate.Scope, candidate.ID); err != nil {
						t.Fatal(err)
					}
					got, err := selector.Read(ctx, candidate.Scope)
					if err != nil || got != candidate.ID {
						t.Fatal("candidate readback differs", err)
					}
					found = true
					break
				}
			}
			if !found {
				t.Fatal("authorized exit disappeared")
			}
		}
	}
	selectPaths()
	request := func(index int, host string) (string, error) {
		proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", 1080+index))
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		response, err := client.Get("http://" + net.JoinHostPort(host, "18080") + "/demo")
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return "", fmt.Errorf("business HTTP %d", response.StatusCode)
		}
		body, err := io.ReadAll(response.Body)
		return string(body), err
	}
	business := func() {
		t.Helper()
		var workers sync.WaitGroup
		for index := 0; index < 2; index++ {
			for _, host := range []string{"demo-service.loom", "192.0.2.80", "2001:db8::80"} {
				workers.Add(1)
				go func(index int, host string) {
					defer workers.Done()
					want := []string{"demo-exit", "demo-exit-b"}[index]
					got, err := request(index, host)
					if err != nil || got != want {
						t.Errorf("same target TCP chose wrong exit: client=%d target=%s result=%s error=%v", index, host, got, err)
					}
					got, err = sharedWGUDP(1080+index, host)
					if err != nil || got != want+":demo-udp" {
						t.Errorf("same target UDP chose wrong exit: client=%d target=%s result=%s error=%v", index, host, got, err)
					}
				}(index, host)
			}
		}
		workers.Wait()
	}
	business()
	for _, id := range []string{"demo-access", "demo-access-b", "demo-entry", "demo-exit", "demo-exit-b"} {
		stops[id]()
	}
	for _, id := range []string{"demo-exit", "demo-exit-b", "demo-entry", "demo-access", "demo-access-b"} {
		launch(id)
	}
	selectPaths()
	business()
	stops["demo-entry"]()
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-access-b" {
			p.DeviceAuthorizations[i].PolicyIDs = []string{}
		}
	}
	launch("demo-entry")
	// A receiver restart loses volatile WG handshakes. Existing clients must
	// recover by the actual transport retry, without restarting their processes.
	recovered := false
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		if got, err := request(0, "demo-service.loom"); err == nil && got == "demo-exit" {
			recovered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("unrevoked client did not recover its shared peer after receiver restart")
	}
	for _, host := range []string{"demo-service.loom", "192.0.2.80", "2001:db8::80"} {
		if got, err := request(1, host); err == nil && got != "" {
			t.Error("revoked client retained business")
		}
		if got, err := request(0, host); err != nil || got != "demo-exit" {
			t.Error("unrelated client's new connection failed", err)
		}
	}
}

func sharedWGUDP(port int, host string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte{5, 1, 0})
	auth := make([]byte, 2)
	if _, err := io.ReadFull(conn, auth); err != nil || auth[1] != 0 {
		return "", fmt.Errorf("SOCKS authentication failed")
	}
	conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil || head[1] != 0 || head[3] != 1 {
		return "", fmt.Errorf("SOCKS association failed")
	}
	bound := make([]byte, 6)
	if _, err := io.ReadFull(conn, bound); err != nil {
		return "", err
	}
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IP(bound[:4]), Port: int(binary.BigEndian.Uint16(bound[4:]))})
	if err != nil {
		return "", err
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(2 * time.Second))
	packet := []byte{0, 0, 0}
	address, err := netip.ParseAddr(host)
	if err == nil {
		kind := byte(4)
		if address.Is4() {
			kind = 1
		}
		packet = append(packet, kind)
		packet = append(packet, address.AsSlice()...)
	} else {
		packet = append(packet, 3, byte(len(host)))
		packet = append(packet, host...)
	}
	packet = binary.BigEndian.AppendUint16(packet, 18080)
	packet = append(packet, []byte("demo-udp")...)
	if _, err := udp.Write(packet); err != nil {
		return "", err
	}
	body := make([]byte, 2048)
	n, err := udp.Read(body)
	if err != nil {
		return "", err
	}
	if n < 10 {
		return "", fmt.Errorf("short UDP reply")
	}
	offset := 10
	if body[3] == 4 {
		offset = 22
	} else if body[3] == 3 {
		offset = 7 + int(body[4])
	}
	if n < offset {
		return "", fmt.Errorf("short target")
	}
	return string(body[offset:n]), nil
}
