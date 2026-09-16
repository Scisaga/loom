package clientruntime

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func windowsPrivateWireGuardConfig(t *testing.T) singBoxConfig {
	t.Helper()
	var config singBoxConfig
	raw := strings.NewReplacer("${secret:vault:cred/win01}", "demo-password", "${secret:api/win01}", "demo-api").Replace(validWindowsConfig("warn"))
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatal(err)
	}
	config.Endpoints = []singBoxWireGuardEndpoint{{Type: "wireguard", Tag: "private-control-wg", MTU: 1280,
		Address: []string{"10.250.0.2/32"}, PrivateKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), Detour: "cand:auto:edge",
		Peers: []singBoxWireGuardPeer{{Address: "192.0.2.34", Port: 51820,
			PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32)), AllowedIPs: []string{"10.250.0.1/32"}, PersistentKeepaliveInterval: 25}}}}
	config.Route.Rules = append([]singBoxRule{{IPCIDR: []string{"10.250.0.1/32"}, Outbound: "private-control-wg"}}, config.Route.Rules...)
	return config
}

func TestWindowsRuntimeProfilesPreservePrivateWireGuard(t *testing.T) {
	config := windowsPrivateWireGuardConfig(t)
	source, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableMixedProfile, WindowsPortableTUNProfile} {
		t.Run(string(profile), func(t *testing.T) {
			derived, err := DeriveWindowsRuntimeConfig(source, profile, WindowsInstalledCAPath)
			if err != nil {
				t.Fatal(err)
			}
			var actual singBoxConfig
			if err := json.Unmarshal(derived, &actual); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(config.Endpoints, actual.Endpoints) {
				t.Fatal("本地接管模式改变了已认证私有控制 endpoint")
			}
			matched := 0
			for _, rule := range actual.Route.Rules {
				if rule.Outbound == "private-control-wg" {
					matched++
					if len(rule.Inbound) != 0 || !reflect.DeepEqual(rule.IPCIDR, []string{"10.250.0.1/32"}) {
						t.Fatal("控制路由被修改或错误依赖 TUN")
					}
				}
			}
			if matched != 1 {
				t.Fatal("私有控制路由丢失或重复")
			}
		})
	}
}

func TestWindowsPrivateWireGuardRejectsChangedAuthority(t *testing.T) {
	for name, change := range map[string]func(*singBoxConfig){
		"kernel WG":       func(c *singBoxConfig) { c.Endpoints[0].System = true },
		"wrong key":       func(c *singBoxConfig) { c.Endpoints[0].PrivateKey = "invalid" },
		"global route":    func(c *singBoxConfig) { c.Endpoints[0].Peers[0].AllowedIPs = []string{"0.0.0.0/0"} },
		"uncovered route": func(c *singBoxConfig) { c.Route.Rules[0].IPCIDR = []string{"10.250.1.1/32"} },
		"tun dependent":   func(c *singBoxConfig) { c.Route.Rules[0].Inbound = []string{"tun-in"} },
		"selector detour": func(c *singBoxConfig) { c.Endpoints[0].Detour = "decl:auto" },
		"tag collision":   func(c *singBoxConfig) { c.Endpoints[0].Tag = "block" },
		"no route":        func(c *singBoxConfig) { c.Route.Rules = c.Route.Rules[1:] },
	} {
		t.Run(name, func(t *testing.T) {
			config := windowsPrivateWireGuardConfig(t)
			change(&config)
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateWindowsSingBox(raw); err == nil {
				t.Fatal("接受了无效的私有控制 WireGuard 配置")
			}
		})
	}
}
