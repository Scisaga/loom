package linuxclient

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestResourceListenerInputsPreserveTLSAndEncodeWGPort(t *testing.T) {
	plain := ResourceInputs{Schema: 3, Listeners: []ResourceListenerInput{{ResourceID: "demo-wg", ListenPort: 45000}}}
	body, err := control.CanonicalEncode(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(`"listen":`)) || bytes.Contains(body, []byte("certificate_file")) || !bytes.Contains(body, []byte(`"listen_port":45000`)) {
		t.Fatal("WG input added an IP or fake TLS material")
	}
	var decoded ResourceInputs
	if err := control.DecodeCanonical(body, &decoded, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 128}); err != nil || decoded.Listeners[0].ListenPort != 45000 {
		t.Fatal(err)
	}
	certificate, key := filepath.Join(t.TempDir(), "node.crt"), filepath.Join(t.TempDir(), "node.key")
	tlsInput := ResourceInputs{Schema: 3, Listeners: []ResourceListenerInput{{ResourceID: "demo-hy2", Listen: "192.0.2.10:443", CertificateFile: certificate, KeyFile: key}}}
	body, err = control.CanonicalEncode(tlsInput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"listen":`)) || bytes.Contains(body, []byte("listen_port")) {
		t.Fatal("Hy2 input changed its existing wire shape")
	}
	for _, invalid := range []ResourceListenerInput{
		{ResourceID: "demo-wg", ListenPort: 0}, {ResourceID: "demo-wg", ListenPort: 65536},
		{ResourceID: "demo-wg", ListenPort: 45000, Listen: "192.0.2.10:45000"},
		{ResourceID: "demo-wg", ListenPort: 45000, CertificateFile: certificate, KeyFile: key},
		{ResourceID: "demo-hy2", Listen: "192.0.2.10:443"},
		{ResourceID: "demo-hy2", Listen: "192.0.2.10:443", CertificateFile: certificate},
		{ResourceID: "demo-hy2", Listen: "192.0.2.10:443", CertificateFile: "node.crt", KeyFile: key},
	} {
		if _, err := control.CanonicalEncode(ResourceInputs{Schema: 3, Listeners: []ResourceListenerInput{invalid}}); err == nil {
			t.Fatal("invalid local input was accepted")
		}
	}
}

// Explicit fixture inputs may initially share the public port; production never
// derives a missing local port from the resource. The differing-port case below
// verifies that these two coordinates remain independent.
func addFixtureWGListeners(t *testing.T, path string, resources []control.TransportResource) {
	t.Helper()
	var inputs ResourceInputs
	if err := readStrict(path, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, input := range inputs.Listeners {
		seen[input.ResourceID] = true
	}
	for _, resource := range resources {
		if resource.Kind == "wireguard" && !seen[resource.ID] {
			inputs.Listeners = append(inputs.Listeners, ResourceListenerInput{ResourceID: resource.ID, ListenPort: resource.DialPort})
		}
	}
	sort.Slice(inputs.Listeners, func(i, j int) bool { return inputs.Listeners[i].ResourceID < inputs.Listeners[j].ResourceID })
	if err := atomicJSON(path, inputs); err != nil {
		t.Fatal(err)
	}
}
func fixtureWGReceiver(t *testing.T, view control.DeviceView, executions []resourceExecution) wireGuardExecution {
	t.Helper()
	port, err := wireGuardListenerPort(view, executions)
	if err != nil {
		t.Fatal(err)
	}
	return wireGuardExecution{WireGuard: []wireGuardExecutionLink{}, ListenPort: port}
}
func fixtureWGExecutions(view control.DeviceView) []resourceExecution {
	values := []resourceExecution{}
	for _, resource := range view.Resources {
		if resource.Kind == "wireguard" && resource.OwnerNodeID == view.DeviceID {
			values = append(values, resourceExecution{resource: resource, input: ResourceListenerInput{ResourceID: resource.ID, ListenPort: resource.DialPort}})
		}
	}
	return values
}

func TestWGLocalPortIsIndependentFromPublicDialAndPeerAddressFamily(t *testing.T) {
	p, keys, input, at := nativeProjectionFixture(t)
	view, err := control.ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	var inputs ResourceInputs
	if err := readStrict(input, 1<<20, &inputs); err != nil {
		t.Fatal(err)
	}
	for i := range inputs.Listeners {
		if inputs.Listeners[i].ResourceID == "demo-exit-wg" {
			inputs.Listeners[i].ListenPort = 45000
		}
	}
	if err := atomicJSON(input, inputs); err != nil {
		t.Fatal(err)
	}
	executions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := projectWireGuard(view, executions)
	if err != nil {
		t.Fatal(err)
	}
	if profile.ListenPort != 45000 || len(profile.WireGuard) != 0 {
		t.Fatal("public port selected the local listener or a relay created host ownership")
	}
	config, _, err := preflightProjectedConfigs(view, "demo-local", "mixed", executions, clientadapter.WebsiteAccess{}, keys[view.DeviceID])
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Endpoints []struct {
			ListenPort  int      `json:"listen_port"`
			System      bool     `json:"system"`
			Name        string   `json:"name"`
			HostSources []string `json:"host_sources"`
			Peers       []struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
			} `json:"peers"`
		} `json:"endpoints"`
	}
	if json.Unmarshal([]byte(config), &document) != nil || len(document.Endpoints) != 1 || document.Endpoints[0].ListenPort != 45000 ||
		document.Endpoints[0].System || document.Endpoints[0].Name != "" || len(document.Endpoints[0].HostSources) != 0 || bytes.Contains([]byte(config), []byte("listen_address")) {
		t.Fatal("preflight did not pass the explicit local WG port")
	}
	found := false
	for _, peer := range document.Endpoints[0].Peers {
		found = found || peer.Address == "192.0.2.11" && peer.Port == 51821
	}
	if !found {
		t.Fatal("local port changed the peer dial coordinate")
	}
	for i := range view.Resources {
		if view.Resources[i].ID == "demo-exit-wg" {
			view.Resources[i].DialPort++
		}
	}
	nextExecutions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := projectWireGuard(view, nextExecutions)
	if err != nil || next.ListenPort != profile.ListenPort || !sameWireGuardHostInputs(profile, next) {
		t.Fatal("public port changed local host ownership", err)
	}
	for i := range view.Resources {
		if view.Resources[i].ID == "demo-entry-wg" {
			view.Resources[i].DialHost = "2001:db8::10"
		}
	}
	config, _, err = preflightProjectedConfigs(view, "demo-local", "mixed", nextExecutions, clientadapter.WebsiteAccess{}, keys[view.DeviceID])
	if err != nil || json.Unmarshal([]byte(config), &document) != nil || len(document.Endpoints) != 1 || document.Endpoints[0].ListenPort != 45000 {
		t.Fatal("peer address family changed the local receiver port", err)
	}
	found = false
	for _, peer := range document.Endpoints[0].Peers {
		found = found || peer.Address == "2001:db8::10" && peer.Port == 51821
	}
	if !found {
		t.Fatal("local receiver port filtered the native peer's IPv6 dial coordinate")
	}
}

func TestWGPortInputsEnforceCertifiedKindOwnerAndWildcardConflicts(t *testing.T) {
	p, _, input, at := nativeProjectionFixture(t)
	view, err := control.ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	var original ResourceInputs
	if err := readStrict(input, 1<<20, &original); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing WG", "WG Hy2 shape", "old WG listen", "Hy2 missing TLS", "Hy2 WG shape", "IPv4 conflict", "IPv6 conflict", "wrong owner"} {
		t.Run(kind, func(t *testing.T) {
			inputs := original
			inputs.Listeners = append([]ResourceListenerInput{}, original.Listeners...)
			for i := range inputs.Listeners {
				value := &inputs.Listeners[i]
				if value.ResourceID != "demo-entry-wg" {
					continue
				}
				switch kind {
				case "missing WG":
					inputs.Listeners = append(inputs.Listeners[:i], inputs.Listeners[i+1:]...)
				case "WG Hy2 shape":
					value.ListenPort = 0
					value.Listen = "192.0.2.10:45000"
					value.CertificateFile, value.KeyFile = "/demo/node.crt", "/demo/node.key"
				case "old WG listen":
					value.ListenPort = 0
					value.Listen = "192.0.2.10:45000"
				case "IPv4 conflict", "IPv6 conflict":
					value.ListenPort = 443
				case "wrong owner":
					value.ResourceID = "demo-unowned-wg"
				}
				break
			}
			for i := range inputs.Listeners {
				value := &inputs.Listeners[i]
				if value.ResourceID != "demo-resource" {
					continue
				}
				switch kind {
				case "Hy2 missing TLS":
					value.CertificateFile, value.KeyFile = "", ""
				case "Hy2 WG shape":
					value.Listen = ""
					value.ListenPort = 443
					value.CertificateFile, value.KeyFile = "", ""
				case "IPv6 conflict":
					value.Listen = "[2001:db8::10]:443"
				}
			}
			sort.Slice(inputs.Listeners, func(i, j int) bool { return inputs.Listeners[i].ResourceID < inputs.Listeners[j].ResourceID })
			path := filepath.Join(t.TempDir(), "inputs.json")
			if kind == "old WG listen" || kind == "Hy2 missing TLS" {
				// Deliberately malformed historical/local bytes must fail at the
				// formal reader, before they can become an execution input.
				body, err := json.Marshal(inputs)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := atomicJSON(path, inputs); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareResourceExecutions(view, path, at); err == nil {
				t.Fatal("invalid kind/owner or shared WG port conflict accepted")
			}
		})
	}
	original.Listeners = append(original.Listeners, ResourceListenerInput{ResourceID: "demo-unused", ListenPort: 443})
	sort.Slice(original.Listeners, func(i, j int) bool { return original.Listeners[i].ResourceID < original.Listeners[j].ResourceID })
	if err := atomicJSON(input, original); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareResourceExecutions(view, input, at); err != nil {
		t.Fatal("unused local input created runtime authority", err)
	}
}

func TestActiveResourceInputDigestChangesWithoutAuthorizationOrUnusedEntries(t *testing.T) {
	p, _, input, at := nativeProjectionFixture(t)
	view, err := control.ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	executions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	before, err := resourceInputsDigest(appliedResourceInputs(executions))
	if err != nil {
		t.Fatal(err)
	}
	var values ResourceInputs
	if err := readStrict(input, 1<<20, &values); err != nil {
		t.Fatal(err)
	}
	for i := range values.Listeners {
		if values.Listeners[i].ResourceID == "demo-entry-wg" {
			values.Listeners[i].ListenPort = 45000
		}
	}
	if err := atomicJSON(input, values); err != nil {
		t.Fatal(err)
	}
	active, err := resourceListenerInputs(view, input)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := resourceInputsDigest(active)
	if err != nil || unchanged != before {
		t.Fatal("unused input changed another node's execution digest", err)
	}
	for i := range values.Listeners {
		if values.Listeners[i].ResourceID == "demo-exit-wg" {
			values.Listeners[i].ListenPort = 45001
		}
	}
	if err := atomicJSON(input, values); err != nil {
		t.Fatal(err)
	}
	active, err = resourceListenerInputs(view, input)
	if err != nil {
		t.Fatal(err)
	}
	after, err := resourceInputsDigest(active)
	if err != nil || after == before {
		t.Fatal("same-View local port change was invisible", err)
	}
}

func TestWGReadbackChecksActualWildcardPortInsteadOfPublicDialPort(t *testing.T) {
	p, _, input, at := nativeProjectionFixture(t)
	view, err := control.ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	var values ResourceInputs
	if err := readStrict(input, 1<<20, &values); err != nil {
		t.Fatal(err)
	}
	for i := range values.Listeners {
		if values.Listeners[i].ResourceID == "demo-exit-wg" {
			values.Listeners[i].ListenPort = socket.LocalAddr().(*net.UDPAddr).Port
		}
	}
	if err := atomicJSON(input, values); err != nil {
		t.Fatal(err)
	}
	executions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	readback, err := readTransportOwnership(view, executions, os.Getpid())
	if err != nil || len(readback) != 1 || readback[0].Listen != socket.LocalAddr().String() {
		t.Fatal("actual socket was replaced by the public port", err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	if !processOwnsUDP(os.Getpid(), net.JoinHostPort("0.0.0.0", strconv.Itoa(port))) {
		t.Fatal("actual receiving socket was not recognized")
	}
	if processOwnsUDP(os.Getpid(), net.JoinHostPort("192.0.2.99", strconv.Itoa(port))) {
		t.Fatal("an arbitrary IP proved false ownership")
	}
}
func TestConnectedUDPSenderDoesNotProvePublicListener(t *testing.T) {
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if processOwnsUDP(os.Getpid(), socket.LocalAddr().String()) {
		t.Fatal("connected sender proved a public listener")
	}
}
