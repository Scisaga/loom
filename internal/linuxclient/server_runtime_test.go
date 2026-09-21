package linuxclient

import (
	"encoding/json"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestRenderServerRuntimeConsumesDerivedUsersAndFailsClosed(t *testing.T) {
	profile := control.ServerRuntimeProfile{Kind: "sing_box", Protocol: "hysteria2", ListenPort: 443,
		Users: []control.ServerRuntimeUser{{Name: "u-demo", Password: strings.Repeat("A", 43)}},
		ACL: []control.ServerRuntimeACL{
			{User: "u-demo", Action: "egress", DNSAddresses: []string{"192.0.2.53"}},
			{User: "u-demo", Action: "egress", DestinationMatchers: []string{"example.com"}},
			{User: "u-demo", Action: "next_hop", NextHost: "192.0.2.20", NextPort: 443, BindInterface: "wg-demo"},
		}}
	body, err := renderServerRuntime(profile, "/etc/loom/tls/node.crt", "/etc/loom/tls/node.key")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Inbounds []struct {
			ListenPort int `json:"listen_port"`
			Users      []struct {
				Name     string `json:"name"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"inbounds"`
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Inbounds) != 1 || document.Inbounds[0].ListenPort != 443 ||
		len(document.Inbounds[0].Users) != 1 || document.Inbounds[0].Users[0].Name != "u-demo" {
		t.Fatalf("server inbound did not consume the certified profile: %+v", document.Inbounds)
	}
	if len(document.Route.Rules) != 4 || document.Route.Final != "loom-server-block" {
		t.Fatalf("server ACL is not fail closed: %+v", document.Route)
	}
	if got := document.Route.Rules[0]; got["port"].([]any)[0].(float64) != 53 || len(got["ip_cidr"].([]any)) != 1 {
		t.Fatalf("certified DNS egress was not narrowed to its address and port: %+v", got)
	}
}

func TestMergeServerRuntimeKeepsAccessControlAndAddsInboundACL(t *testing.T) {
	access := `{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"route:demo:direct"}],"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-secret"}}}`
	profile := control.ServerRuntimeProfile{Kind: "sing_box", Protocol: "hysteria2", ListenPort: 443,
		Users: []control.ServerRuntimeUser{{Name: "u-demo", Password: strings.Repeat("A", 43)}},
		ACL: []control.ServerRuntimeACL{{User: "u-demo", Action: "egress",
			DestinationMatchers: []string{"example.com"}}}}
	body, err := mergeServerRuntime(access, profile, "/etc/loom/tls/node.crt", "/etc/loom/tls/node.key")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Inbounds     []map[string]any `json:"inbounds"`
		Outbounds    []map[string]any `json:"outbounds"`
		Experimental map[string]any   `json:"experimental"`
		Route        struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Inbounds) != 2 || len(document.Outbounds) != 3 || len(document.Route.Rules) != 2 || document.Experimental == nil {
		t.Fatalf("hybrid runtime lost an access or server section: %+v", document)
	}
}

func TestAttachDataPlaneCAUpdatesOnlyTLSDataPlaneOutbounds(t *testing.T) {
	config := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"hysteria2","tag":"exit","tls":{"enabled":true,"server_name":"exit.example"}}]}`
	body, err := attachDataPlaneCA(config, "/run/loom-client/data-plane-ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Outbounds []struct {
			Type string         `json:"type"`
			TLS  map[string]any `json:"tls"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	if document.Outbounds[0].TLS != nil || document.Outbounds[1].TLS["certificate_path"] != "/run/loom-client/data-plane-ca.crt" {
		t.Fatalf("data-plane CA binding is wrong: %+v", document.Outbounds)
	}
}

func TestLinuxAccessRuntimeDerivesThePlatformTUNWithoutChangingAuthority(t *testing.T) {
	config := `{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"direct","tag":"direct"}]}`
	body, err := deriveLinuxAccessRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Inbounds []struct {
			Address []string `json:"address"`
			Stack   string   `json:"stack"`
		} `json:"inbounds"`
		Route struct {
			AutoDetectInterface bool `json:"auto_detect_interface"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Inbounds) != 1 || len(document.Inbounds[0].Address) != 1 ||
		document.Inbounds[0].Address[0] != "172.19.0.1/30" || document.Inbounds[0].Stack != "system" ||
		!document.Route.AutoDetectInterface {
		t.Fatalf("Linux platform TUN derivation is incomplete: %+v", document)
	}
	if _, err := deriveLinuxAccessRuntime(`{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true,"address":["192.0.2.1/30"]}]}`); err == nil {
		t.Fatal("conflicting signed TUN address was overwritten")
	}
}
