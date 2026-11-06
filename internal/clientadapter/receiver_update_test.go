package clientadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/protocol"
)

func TestInternetTargetAndServiceGrantsArePermissionOnlyUpdates(t *testing.T) {
	for _, scenario := range []string{"remove-target", "grant-existing-policy", "new-service-policy"} {
		t.Run(scenario, func(t *testing.T) {
			view, _, _ := resourceProbeFixture(t)
			view.Services[0].RestrictToProbeTargets = new(true)
			view.Services[0].ProbeURLs = []string{"https://demo-one.example/health", "https://demo-two.example/health"}
			availablePolicies := slices.Clone(view.Policies)
			setPolicies := func(ids []string) {
				view.PolicyIDs = slices.Clone(ids)
				for i := range view.Nodes {
					if view.Nodes[i].ID == view.DeviceID {
						view.Nodes[i].PolicyIDs = slices.Clone(ids)
					}
				}
			}
			if scenario == "grant-existing-policy" {
				setPolicies([]string{"demo-a"})
				view.Policies = slices.Clone(availablePolicies[:1])
			}
			before, err := AccessRuntimeSource(view, "demo-secret")
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "remove-target":
				view.Services[0].ProbeURLs = view.Services[0].ProbeURLs[:1]
			case "grant-existing-policy":
				setPolicies([]string{"demo-a", "demo-b"})
				view.Policies = slices.Clone(availablePolicies[:2])
			case "new-service-policy":
				service := view.Services[0]
				service.ID, service.Name = "demo-z", "Demo additional service"
				view.Services = append(view.Services, service)
				policy := view.Policies[0]
				policy.ID, policy.ServiceID = service.ID, service.ID
				view.Policies = append(view.Policies, policy)
				setPolicies(append(slices.Clone(view.PolicyIDs), policy.ID))
			}
			after, err := AccessRuntimeSource(view, "demo-secret")
			if err != nil {
				t.Fatal(err)
			}
			changes, hot, err := ReceiverChanges(before, after)
			if err != nil || !hot || len(changes) != 1 || changes[0].Tag != control.AccessSelectorScope {
				t.Fatal("a pure Internet permission change rebuilt physical facilities", hot, err)
			}
			next, err := WithReceiverChanges(before, changes)
			var actual, desired any
			if err != nil || json.Unmarshal([]byte(next), &actual) != nil || json.Unmarshal([]byte(after), &desired) != nil || !reflect.DeepEqual(actual, desired) {
				t.Fatal("the complete current projection could not be applied as a permission delta", err)
			}
		})
	}
}

func TestRestrictedLANTargetEditDoesNotChangeStaticCapture(t *testing.T) {
	view, _, _ := resourceProbeFixture(t)
	prefix, err := control.AllocateLocalNetworkPrefix(view.NetworkID, view.Services[0].ID, 0, "192.0.2.0/24", nil)
	if err != nil {
		t.Fatal(err)
	}
	first, second := prefix.Addr().Next().String(), prefix.Addr().Next().Next().String()
	service := &view.Services[0]
	service.Kind, service.RestrictToProbeTargets = "local_network", new(true)
	service.ProbeURLs = []string{"https://" + first + ":8443/health", "https://" + second + ":8443/health"}
	service.LocalNetwork = &control.LocalNetwork{GatewayNodeID: "demo-exit", LocalPrefix: "192.0.2.0/24", VirtualPrefix: prefix.String(), Enabled: true}
	view.Policies[0].ExitScope, view.Policies[0].AllowDirect, view.Policies[0].LocalEgressDevices = nil, nil, nil
	for i := range view.Nodes {
		if view.Nodes[i].ID == "demo-exit" {
			view.Nodes[i].Responsibilities = []string{"forward", "internet_egress"}
		}
	}
	before, err := AccessRuntimeSource(view, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	service.ProbeURLs = service.ProbeURLs[:1]
	after, err := AccessRuntimeSource(view, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	changes, hot, err := ReceiverChanges(before, after)
	if err != nil || !hot || len(changes) != 1 || changes[0].Tag != service.Scope() {
		t.Fatal("LAN target editing changed capture rather than only its scope permission", hot, err)
	}
}

func TestAuthorizationUpdatePreservesPreparedCaptureAndRejectsFacilityChanges(t *testing.T) {
	const before = `{"inbounds":[{"type":"tun","tag":"demo-tun"},{"type":"hysteria2","tag":"demo-receiver","execution":{"policies":["demo-old"]},"users":[{"name":"demo-old"}]}],"outbounds":[{"type":"selector","tag":"access","access":{"policies":["demo-old"],"entries":{},"egress_outbounds":{},"forward_outbounds":{}},"outbounds":["reject"]}],"route":{"final":"reject"}}`
	after := strings.ReplaceAll(before, "demo-old", "demo-current")
	changes, hot, err := ReceiverChanges(before, after)
	if err != nil || !hot || len(changes) != 2 {
		t.Fatal("predicate-only change required replacement", hot, err)
	}
	prepared := strings.Replace(before, `"tag":"demo-tun"`, `"tag":"demo-tun","route_exclude_address":["192.0.2.10/32"]`, 1)
	updated, err := WithReceiverChanges(prepared, changes)
	if err != nil {
		t.Fatal(err)
	}
	expected := strings.ReplaceAll(prepared, "demo-old", "demo-current")
	var a, b any
	if json.Unmarshal([]byte(updated), &a) != nil || json.Unmarshal([]byte(expected), &b) != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("authorization update changed prepared capture or retained old grants")
	}
	for _, changed := range []string{
		strings.Replace(after, `"final":"reject"`, `"final":"direct"`, 1),
		strings.Replace(after, `"type":"tun"`, `"type":"mixed"`, 1),
	} {
		if _, hot, err := ReceiverChanges(before, changed); err != nil || hot {
			t.Fatal("facility change was treated as predicate-only", err)
		}
	}
	if _, hot, err := ReceiverChanges(before, strings.Replace(after, `"outbounds":["reject"]`, `"outbounds":["demo-other"]`, 1)); err == nil || hot {
		t.Fatal("member references gained an outbound absent from the access projection")
	}
	for _, incomplete := range []string{
		strings.Replace(after, `"entries":{},`, "", 1),
		strings.Replace(after, `"forward_outbounds":{}`, `"forward_outbounds":null`, 1),
	} {
		if _, hot, err := ReceiverChanges(before, incomplete); err == nil || hot {
			t.Fatal("an incomplete access projection was treated as a native permission update")
		}
	}
	if _, err := WithReceiverChanges(prepared, []ReceiverChange{{Tag: "demo-absent", Projection: changes[0].Projection}}); err == nil {
		t.Fatal("an absent native scope was accepted")
	}
}

func TestWireGuardSenderPeerUpdatePreservesPreparedRuntime(t *testing.T) {
	const before = `{"endpoints":[{"type":"wireguard","tag":"wg-shared","private_key":"demo-key","address":["2001:db8:1::1/128"],"source_routes":[{"source":"2001:db8:1::1","destination":"2001:db8:2::/64","execution":"2001:db8:3::1"}],"peers":[{"public_key":"demo-peer","address":"192.0.2.10","port":51820,"allowed_ips":["2001:db8:2::/64"]}]}],"route":{"final":"reject"}}`
	after := strings.Replace(before, "192.0.2.10", "192.0.2.11", 1)
	changes, hot, err := ReceiverChanges(before, after)
	if err != nil || !hot || len(changes) != 1 || len(changes[0].Projection) != 1 || changes[0].Projection["wireguard_peers"] == nil {
		t.Fatal("sender peer update required replacement or invented receiving authorization", hot, err)
	}
	prepared := strings.Replace(before, `"final":"reject"`, `"final":"reject","auto_detect_interface":false`, 1)
	updated, err := WithReceiverChanges(prepared, changes)
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected any
	if json.Unmarshal([]byte(updated), &actual) != nil || json.Unmarshal([]byte(strings.Replace(prepared, "192.0.2.10", "192.0.2.11", 1)), &expected) != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("sender peer update changed prepared runtime inputs")
	}
	for _, changed := range []string{
		strings.Replace(after, "demo-key", "demo-other-key", 1),
		strings.Replace(after, "2001:db8:1::1/128", "2001:db8:1::2/128", 1),
	} {
		if _, hot, err := ReceiverChanges(before, changed); err != nil || hot {
			t.Fatal("unimplemented device change was treated as a peer update", err)
		}
	}
}

// Capture is replaced with loopback Mixed/API sockets. WG uses a userspace
// stack; no host TUN, route, resolver or firewall object is created.
func startNativeUpdateRuntime(t *testing.T, executable, configSource string) (context.Context, *HTTPSelector) {
	t.Helper()
	free := func() *net.TCPAddr {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr)
	}
	api, mixed := free(), free()
	var document map[string]any
	if json.Unmarshal([]byte(configSource), &document) != nil {
		t.Fatal("rendered runtime was not JSON")
	}
	// Replace the entire capture surface before starting the process.
	document["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "demo-mixed", "listen": "127.0.0.1", "listen_port": mixed.Port}}
	document["experimental"] = map[string]any{"clash_api": map[string]any{"external_controller": api.String(), "secret": "demo-secret"}}
	body, _ := json.Marshal(document)
	config := filepath.Join(t.TempDir(), "demo-runtime.json")
	if err := os.WriteFile(config, body, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, executable, "run", "-c", config)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	selector, err := NewHTTPSelector(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	selector.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, api.String())
	})
	t.Cleanup(selector.client.CloseIdleConnections)
	if err := WaitSelector(ctx, selector, []string{"access"}); err != nil {
		t.Fatal(err)
	}
	return ctx, selector
}

func TestNativeSourceAuthorizationUpdateConsumesCurrentRenderedProjection(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable")
	}
	view, _, _ := resourceProbeFixture(t)
	before, err := AccessRuntimeSource(view, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	next := view
	next.Policies = slices.Clone(view.Policies)
	next.Policies[0].MaxHops = 1
	after, err := AccessRuntimeSource(next, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	changes, hot, err := ReceiverChanges(before, after)
	if err != nil || !hot || len(changes) != 1 {
		t.Fatal("current permission change was not local", hot, err)
	}
	ctx, selector := startNativeUpdateRuntime(t, executable, before)
	initial, err := selector.ReadSelection(ctx, "access")
	if err != nil {
		t.Fatal(err)
	}
	choice := protocol.RouteChoice{FinalExit: "direct"}
	policy := view.Policies[0]
	id, err := protocol.CandidateID(policy.ServiceID, policy.ID, choice)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selector.ApplySelection(ctx, initial, clientmodel.Selection{Scope: "access", PolicyID: policy.ID, CandidateID: id, Choices: map[string]protocol.RouteChoice{id: choice}, Targets: map[string]string{}})
	if err != nil {
		t.Fatal("current source decision was not consumed", err)
	}
	if err := selector.ApplyReceiverChanges(ctx, changes); err != nil {
		t.Fatal("current authorization delta was not confirmed", err)
	}
	actual, err := selector.ReadSelection(ctx, "access")
	if err != nil || !SameSelection(actual, selected) || actual.Revision == selected.Revision {
		t.Fatal("valid decision was lost or old CAS survived permission update", err)
	}
	if _, err := selector.ApplySelection(ctx, selected, selected); err == nil {
		t.Fatal("old selection CAS survived source authorization replacement")
	}
}

func TestNativeWireGuardPeerUpdateConsumesCurrentRenderedProjection(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable")
	}
	view, _, _ := resourceProbeFixture(t, "wireguard")
	before, err := AccessRuntimeSource(view, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	view.Resources[0].DialHost = "192.0.2.11"
	after, err := AccessRuntimeSource(view, "demo-secret")
	if err != nil {
		t.Fatal(err)
	}
	changes, hot, err := ReceiverChanges(before, after)
	if err != nil || !hot || len(changes) != 1 || changes[0].Tag != "wg-shared" {
		t.Fatal("current sender transport change required a runtime replacement", hot, err)
	}
	ctx, selector := startNativeUpdateRuntime(t, executable, before)
	initial, err := selector.request(ctx, http.MethodGet, "/loom/wireguard-counters", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.ApplyReceiverChanges(ctx, changes); err != nil {
		t.Fatal("current WG peer delta was not applied and read back", err)
	}
	current, err := selector.request(ctx, http.MethodGet, "/loom/wireguard-counters", nil)
	var a, b any
	if err != nil || json.Unmarshal(initial, &a) != nil || json.Unmarshal(current, &b) != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("peer coordinate update changed the WG instance or counters", err)
	}
}

func TestAuthorizationUpdateRequiresItsOwnCompleteNativeReadback(t *testing.T) {
	for _, interleave := range []bool{false, true} {
		t.Run(fmt.Sprint(interleave), func(t *testing.T) {
			gets := 0
			hash := "sha256:" + strings.Repeat("0", 64)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/loom/access/access" || r.Header.Get("Authorization") != "Bearer demo-secret" {
					http.Error(w, "incorrect private update endpoint", http.StatusForbidden)
					return
				}
				revision := "1"
				if r.Method == http.MethodPut {
					var value map[string]any
					if json.NewDecoder(r.Body).Decode(&value) != nil || value["expected_revision"] != "1" {
						http.Error(w, "missing compare-and-swap", http.StatusConflict)
						return
					}
					delete(value, "expected_revision")
					body, _ := json.Marshal(value)
					digest := sha256.Sum256(body)
					hash = "sha256:" + hex.EncodeToString(digest[:])
					revision = "2"
				} else {
					gets++
					if gets > 1 {
						revision = "2"
						if interleave {
							revision = "3"
						}
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"revision": revision, "config_hash": hash})
			}))
			defer server.Close()
			selector, err := NewHTTPSelector(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`)
			if err != nil {
				t.Fatal(err)
			}
			selector.SetDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			})
			err = selector.ApplyReceiverChanges(context.Background(), []ReceiverChange{{Tag: "access", Projection: map[string]any{"access": map[string]any{"policies": []string{"demo-current"}}}}})
			if (err == nil) == interleave {
				t.Fatal("a later native revision was acknowledged as this update", err)
			}
		})
	}
}
