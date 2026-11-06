package clientruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestWindowsCurrentViewProjectionAcrossCaptureProfiles(t *testing.T) {
	for _, transports := range [][]string{nil, {"wireguard"}, {"hysteria2"}, {"hysteria2", "wireguard"}} {
		view := windowsViewFixture(t, transports...)
		view.DNSServers = []string{"https://192.0.2.53/dns-query", "https://192.0.2.54/dns-query"}
		view.DNSRecords = []control.DNSRecord{{ID: "demo-dns", Name: "demo-dependency.loom", Addresses: []string{"192.0.2.20"}}}
		source, err := clientadapter.AccessRuntimeSource(view, "demo-api")
		if err != nil {
			t.Fatal(err)
		}
		source, err = clientadapter.WithBlockedSelectors(source)
		if err != nil {
			t.Fatal(err)
		}
		original := runtimeDocument(t, []byte(source))
		viewBytes, _ := control.CanonicalEncode(view)
		for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
			config, err := DeriveWindowsRuntimeConfig(view, profile, "demo-api", clientadapter.WebsiteAccess{}, new([]string{}))
			if err != nil {
				t.Fatal(transports, profile, err)
			}
			derived := runtimeDocument(t, config.Bytes())
			if !reflect.DeepEqual(derived["endpoints"], original["endpoints"]) {
				t.Fatal("capture rewrote native WireGuard execution")
			}
			outbounds := derived["outbounds"].([]any)
			if len(outbounds) < len(original["outbounds"].([]any)) || !reflect.DeepEqual(outbounds[:len(original["outbounds"].([]any))], original["outbounds"]) {
				t.Fatal("capture changed native access, transport or Policy permission")
			}
			route, baseRoute := derived["route"].(map[string]any), original["route"].(map[string]any)
			prefix := 2
			if profile != WindowsPortableMixedProfile {
				prefix++
			}
			if route["final"] != "reject" || !reflect.DeepEqual(route["rules"].([]any)[prefix:], baseRoute["rules"]) {
				t.Fatal("capture changed business dispatch or final rejection")
			}
			tunCount := 0
			for _, raw := range derived["inbounds"].([]any) {
				inbound := raw.(map[string]any)
				if inbound["type"] == "tun" {
					tunCount++
				}
				if inbound["type"] == "mixed" && (inbound["listen"] != "127.0.0.1" || inbound["listen_port"] != float64(1080)) {
					t.Fatal("Mixed escaped loopback")
				}
			}
			wantTUN := 1
			if profile == WindowsPortableMixedProfile {
				wantTUN = 0
			}
			if tunCount != wantTUN {
				t.Fatal("wrong capture profile")
			}
			dns := derived["dns"].(map[string]any)
			if dns["final"] != "loom-resolver-0" {
				t.Fatal("certified DNS was lost")
			}
			resolvers, record := 0, false
			for _, raw := range dns["servers"].([]any) {
				server := raw.(map[string]any)
				if server["address"] == "local" {
					t.Fatal("system DNS fallback appeared")
				}
				if server["address"] == view.DNSServers[0] || server["address"] == view.DNSServers[1] {
					resolvers++
					if server["detour"] != "loom-underlay-dns" {
						t.Fatal("resolver left its physical underlay")
					}
				}
				if server["address"] == "loom-static" {
					record = reflect.DeepEqual(server["static_records"].(map[string]any)["demo-dependency.loom"], []any{"192.0.2.20"})
				}
			}
			if resolvers != 2 || !record {
				t.Fatal("certified resolver alternatives or overlay record were lost")
			}
			copy := config.Bytes()
			clear(copy)
			if err := config.validate(); err != nil {
				t.Fatal("a mutable copy changed supervisor input", err)
			}
			if executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE"); executable != "" {
				if err := PreflightWindowsRuntime(context.Background(), executable, config, filepath.Join(t.TempDir(), "runtime")); err != nil {
					t.Fatal(transports, profile, err)
				}
			}
			config.Clear()
			if config.validate() == nil {
				t.Fatal("cleared projection remained executable")
			}
		}
		after, _ := control.CanonicalEncode(view)
		if !bytes.Equal(viewBytes, after) {
			t.Fatal("capture mutated its certified View")
		}
	}
}

func TestWindowsConstructionRejectsInvalidAuthorityAndExecutionInputs(t *testing.T) {
	for _, change := range []func(*control.DeviceView){
		func(v *control.DeviceView) { v.Schema++ },
		func(v *control.DeviceView) { v.Platform = "linux" },
		func(v *control.DeviceView) { v.Responsibilities = []string{} },
		func(v *control.DeviceView) { v.Services[0].RestrictToProbeTargets = nil },
		func(v *control.DeviceView) { v.Services[0].RestrictToProbeTargets = new(true) },
		func(v *control.DeviceView) { v.DNSServers = []string{"demo-resolver.example"} },
	} {
		view := windowsViewFixture(t)
		change(&view)
		if _, err := DeriveWindowsRuntimeConfig(view, WindowsPortableMixedProfile, "demo-api", clientadapter.WebsiteAccess{}, nil); err == nil {
			t.Fatal("invalid View acquired a Windows runtime")
		}
	}
	view := windowsViewFixture(t)
	for _, profile := range []WindowsRuntimeProfile{"", "demo-other"} {
		if _, err := DeriveWindowsRuntimeConfig(view, profile, "demo-api", clientadapter.WebsiteAccess{}, nil); err == nil {
			t.Fatal("unsupported capture profile accepted")
		}
	}
	if _, err := DeriveWindowsRuntimeConfig(view, WindowsPortableMixedProfile, "", clientadapter.WebsiteAccess{}, nil); err == nil {
		t.Fatal("missing local API authentication accepted")
	}
	if (WindowsRuntimeConfig{}).validate() == nil {
		t.Fatal("unconstructed runtime became executable")
	}
}

func TestWindowsWebsiteIsDerivedFromTheCertifiedEntry(t *testing.T) {
	view := windowsViewFixture(t)
	website := clientadapter.WebsiteAccess{Port: 8443, Addresses: []string{"192.0.2.20", "2001:db8::20"}}
	if _, err := DeriveWindowsRuntimeConfig(view, WindowsPortableMixedProfile, "demo-api", website, nil); err == nil {
		t.Fatal("unauthorized website route accepted")
	}
	trust := windowsWebsiteTrust(t)
	view.PublicTrust = []control.PublicTrust{trust}
	view.WebEndpoints = []control.EndpointGeneration{{ID: "demo-web", Generation: 1, OwnerControlID: "demo-control", Host: "192.0.2.20", Port: website.Port, ServerName: "control.loom", WebsiteTrustID: trust.ID, SPKISHA256: "sha256:" + string(bytes.Repeat([]byte{'1'}, 64)), CertificateDigest: "sha256:" + string(bytes.Repeat([]byte{'1'}, 64)), Modes: []string{"web"}, State: "serving"}}
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
		config, err := DeriveWindowsRuntimeConfig(view, profile, "demo-api", website, new([]string{}))
		if err != nil {
			t.Fatal(err)
		}
		document := runtimeDocument(t, config.Bytes())
		rule := document["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
		if !reflect.DeepEqual(rule["domain"], []any{"control.loom"}) || !reflect.DeepEqual(rule["port"], []any{float64(website.Port)}) || rule["network"] != "tcp" || rule["outbound"] != "website-underlay" {
			t.Fatal("website route broadened")
		}
		if profile != WindowsPortableMixedProfile {
			capture := document["inbounds"].([]any)[1].(map[string]any)
			if !reflect.DeepEqual(capture["route_exclude_address"], []any{"192.0.2.20/32", "2001:db8::20/128"}) {
				t.Fatal("website underlay entered TUN")
			}
		}
		config.Clear()
	}
	website.Port++
	if _, err := DeriveWindowsRuntimeConfig(view, WindowsPortableMixedProfile, "demo-api", website, nil); err == nil {
		t.Fatal("changed website port accepted")
	}
}

// The constructor cannot ingest arbitrary native JSON. Unknown native fields
// are still rejected by the exact executor, whose diagnostics stay suppressed.
func TestWindowsNativeCheckRejectsUnknownCurrentFields(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the exact native data-plane executable")
	}
	config, err := DeriveWindowsRuntimeConfig(windowsViewFixture(t), WindowsPortableMixedProfile, "demo-api", clientadapter.WebsiteAccess{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Clear()
	document := runtimeDocument(t, config.Bytes())
	document["outbounds"].([]any)[0].(map[string]any)["demo_unknown_field"] = true
	body, _ := json.Marshal(document)
	if RunSingBoxCheck(context.Background(), executable, body, filepath.Join(t.TempDir(), "runtime")) == nil {
		t.Fatal("unknown native field accepted")
	}
}
