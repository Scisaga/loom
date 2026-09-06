package clientruntime

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestWindowsTUNCapturePreservesSignedPolicy(t *testing.T) {
	source := []byte(strings.NewReplacer("${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api").Replace(validWindowsConfig("warn")))
	original := bytes.Clone(source)
	var signed singBoxConfig
	if err := json.Unmarshal(source, &signed); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
		t.Run(string(profile), func(t *testing.T) {
			derived, err := DeriveWindowsRuntimeConfig(source, profile, WindowsInstalledCAPath)
			if err != nil {
				t.Fatal(err)
			}
			var config singBoxConfig
			if err := json.Unmarshal(derived, &config); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(source, original) || !reflect.DeepEqual(config.DNS, signed.DNS) ||
				!reflect.DeepEqual(config.Outbounds, signed.Outbounds) || config.Route.Final != signed.Route.Final {
				t.Fatal("local capture changed the source, DNS resolvers or signed egress policy")
			}
			if profile == WindowsPortableMixedProfile {
				if config.Route.AutoDetectInterface || bytes.Contains(derived, []byte("hijack-dns")) {
					t.Fatal("Mixed acquired TUN capture settings")
				}
				return
			}
			if !config.Route.AutoDetectInterface || !isWindowsTUNDNSRule(config.Route.Rules[0]) {
				t.Fatal("TUN lacks underlay interface binding or DNS dispatch")
			}
			if !reflect.DeepEqual(config.Route.Rules[1:], signed.Route.Rules) || !reflect.DeepEqual(config.Inbounds, signed.Inbounds) {
				t.Fatal("local capture changed signed traffic rules or listeners")
			}
			if err := ValidateWindowsSingBox(derived); err == nil {
				t.Fatal("local capture settings were accepted as a signed policy")
			}
		})
	}
}

func TestWindowsTUNCaptureRejectsBrokenOrBroadenedDispatch(t *testing.T) {
	source := []byte(strings.NewReplacer("${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api").Replace(validWindowsConfig("warn")))
	derived, err := DeriveWindowsRuntimeConfig(source, WindowsInstalledProfile, WindowsInstalledCAPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*singBoxConfig)
	}{
		{"missing interface binding", func(c *singBoxConfig) { c.Route.AutoDetectInterface = false }},
		{"missing DNS dispatch", func(c *singBoxConfig) { c.Route.Rules = c.Route.Rules[1:] }},
		{"DNS after egress", func(c *singBoxConfig) { c.Route.Rules[0], c.Route.Rules[1] = c.Route.Rules[1], c.Route.Rules[0] }},
		{"duplicate DNS dispatch", func(c *singBoxConfig) { c.Route.Rules = append(c.Route.Rules, c.Route.Rules[0]) }},
		{"global DNS dispatch", func(c *singBoxConfig) { c.Route.Rules[0].Inbound = nil }},
		{"mixed DNS dispatch", func(c *singBoxConfig) { c.Route.Rules[0].Inbound = []string{"tun-in", "in-1080"} }},
		{"all ports", func(c *singBoxConfig) { c.Route.Rules[0].Port = nil }},
		{"other port", func(c *singBoxConfig) { c.Route.Rules[0].Port = []int{443} }},
		{"partial domain", func(c *singBoxConfig) { c.Route.Rules[0].Domain = []string{"example.com"} }},
		{"partial address", func(c *singBoxConfig) { c.Route.Rules[0].IPCIDR = []string{"192.0.2.0/24"} }},
		{"DNS outbound override", func(c *singBoxConfig) { c.Route.Rules[0].Outbound = "dns-out" }},
		{"other action", func(c *singBoxConfig) { c.Route.Rules[0].Action = "sniff" }},
		{"extra action", func(c *singBoxConfig) { c.Route.Rules[1].Action = "route" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var config singBoxConfig
			if err := json.Unmarshal(derived, &config); err != nil {
				t.Fatal(err)
			}
			test.mutate(&config)
			body, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateWindowsRuntimeConfig(body, WindowsInstalledProfile, WindowsInstalledCAPath); err == nil {
				t.Fatal("accepted broken or broadened local capture")
			}
		})
	}
}
