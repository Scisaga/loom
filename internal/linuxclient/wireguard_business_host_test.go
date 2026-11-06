package linuxclient

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"testing"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestRelayResourcesDoNotCreateLinuxHostGeometry(t *testing.T) {
	p, keys, input, at := nativeProjectionFixture(t)
	var later control.TransportResource
	p.NetworkIntent.Resources = slices.DeleteFunc(p.NetworkIntent.Resources, func(resource control.TransportResource) bool {
		if resource.ID == "demo-exit-wg" {
			later = resource
			return true
		}
		return false
	})
	for _, resource := range p.NetworkIntent.Resources {
		if resource.Kind == "hysteria2" {
			resource.ID, resource.OwnerNodeID, resource.ListenerID = "demo-exit-hy2", "demo-exit", "demo-exit-hy2"
			resource.DialHost = "192.0.2.12"
			p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, resource)
			break
		}
	}
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	project := func() (control.DeviceView, wireGuardExecution, string) {
		t.Helper()
		view, err := control.ProjectDeviceView(p, "demo-entry")
		if err != nil {
			t.Fatal(err)
		}
		executions, err := prepareResourceExecutions(view, input, at)
		if err != nil {
			t.Fatal(err)
		}
		profile, identity, err := projectWireGuard(view, executions)
		if err != nil || identity != nil || len(profile.WireGuard) != 0 || profile.ListenPort == 0 {
			t.Fatal("ordinary relay resources manufactured host interfaces or lost the receiving port", err)
		}
		transaction, err := prepareNativeWireGuard(view, profile, Options{IP: "/demo-no-host-command"})
		if err != nil || len(transaction.owned) != 0 || transaction.Cleanup() != nil {
			t.Fatal("ordinary business projection executed a host interface or route command", err)
		}
		config, err := nodeRuntimeConfig(view, "demo-api", nil, "mixed", executions)
		if err != nil {
			t.Fatal(err)
		}
		config, err = appendNativeWireGuard(config, view, profile, nil, keys[view.DeviceID])
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Endpoints []map[string]any `json:"endpoints"`
		}
		if err := json.Unmarshal([]byte(config), &document); err != nil || len(document.Endpoints) != 1 {
			t.Fatal("registered WG endpoint disappeared", err)
		}
		endpoint := document.Endpoints[0]
		if endpoint["system"] == true {
			t.Fatal("ordinary relay resource created a system WG stack")
		}
		for _, field := range []string{"name", "host_sources", "stack_address"} {
			if endpoint[field] != nil {
				t.Fatal("ordinary relay resource created host geometry", field)
			}
		}
		if endpoint["private_key"] == "" || endpoint["listen_port"] != float64(profile.ListenPort) || !reflect.DeepEqual(endpoint["address"], []any{"127.0.0.1/32", "::1/128"}) {
			t.Fatal("resource hydration lost the registered identity, local port or stable userspace stack")
		}
		return view, profile, config
	}
	_, before, config := project()
	p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, later)
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	_, after, updated := project()
	if !sameWireGuardHostInputs(before, after) {
		t.Fatal("a business-only sender addition changed Linux host ownership")
	}
	if _, hot, err := clientadapter.RuntimePermissionChanges(config, updated); err != nil || !hot {
		t.Fatal("a business-only sender addition required native replacement", err)
	}
}
