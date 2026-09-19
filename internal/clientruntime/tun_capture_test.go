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
			if !bytes.Equal(source, original) || !reflect.DeepEqual(config.DNS.Servers, signed.DNS.Servers) || config.DNS.Strategy != signed.DNS.Strategy ||
				!reflect.DeepEqual(config.Outbounds, signed.Outbounds) || config.Route.Final != signed.Route.Final {
				t.Fatal("local capture changed the source, DNS resolvers or signed egress policy")
			}
			if profile == WindowsPortableMixedProfile {
				if config.Route.AutoDetectInterface || config.DNS.ReverseMapping || bytes.Contains(derived, []byte("hijack-dns")) || bytes.Contains(derived, []byte(`"sniff"`)) {
					t.Fatal("Mixed acquired TUN capture settings")
				}
				return
			}
			if !config.Route.AutoDetectInterface || !config.DNS.ReverseMapping || !isWindowsTUNDNSRule(config.Route.Rules[0]) || !isWindowsTUNSniffRule(config.Route.Rules[1]) {
				t.Fatal("[§7.2.1] TUN 缺少网卡绑定、DNS 接管或域名识别")
			}
			if !reflect.DeepEqual(config.Route.Rules[2:], signed.Route.Rules) || !reflect.DeepEqual(config.Inbounds, signed.Inbounds) {
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
		{"missing DNS domain mapping", func(c *singBoxConfig) { c.DNS.ReverseMapping = false }},
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
		{"missing domain identification", func(c *singBoxConfig) { c.Route.Rules = append(c.Route.Rules[:1], c.Route.Rules[2:]...) }},
		{"domain identification after service", func(c *singBoxConfig) { c.Route.Rules[1], c.Route.Rules[2] = c.Route.Rules[2], c.Route.Rules[1] }},
		{"duplicate domain identification", func(c *singBoxConfig) { c.Route.Rules = append(c.Route.Rules, c.Route.Rules[1]) }},
		{"global domain identification", func(c *singBoxConfig) { c.Route.Rules[1].Rules[0].Inbound = nil }},
		{"mixed domain identification", func(c *singBoxConfig) { c.Route.Rules[1].Rules[0].Inbound = []string{"tun-in", "in-1080"} }},
		{"overwrite known domain", func(c *singBoxConfig) { c.Route.Rules[1].Rules = c.Route.Rules[1].Rules[:1] }},
		{"inverted capture", func(c *singBoxConfig) { c.Route.Rules[1].Invert = true }},
		{"broadened domain condition", func(c *singBoxConfig) { c.Route.Rules[1].Rules[1].DomainRegex = []string{"example"} }},
		{"nested capture action", func(c *singBoxConfig) { c.Route.Rules[1].Rules[0].Action = "sniff" }},
		{"filtered domain identification", func(c *singBoxConfig) { c.Route.Rules[1].Domain = []string{"demo.example"} }},
		{"domain identification outbound", func(c *singBoxConfig) { c.Route.Rules[1].Outbound = "dns-out" }},
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

func TestWindowsTUNRejectsLocalDomainCaptureInSignedSource(t *testing.T) {
	source := []byte(strings.NewReplacer("${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api").Replace(validWindowsConfig("warn")))
	for _, mutate := range []func(*singBoxConfig){
		func(c *singBoxConfig) { c.DNS.ReverseMapping = true },
		func(c *singBoxConfig) { c.Route.Rules[0].DomainRegex = []string{".+"} },
		func(c *singBoxConfig) { c.Route.Rules[0].Invert = true },
		func(c *singBoxConfig) { c.Route.Rules[0].Type = "logical" },
		func(c *singBoxConfig) { c.Route.Rules[0].Mode = "or" },
		func(c *singBoxConfig) { c.Route.Rules[0].Rules = []singBoxRule{{Domain: []string{"demo.example"}}} },
		func(c *singBoxConfig) { c.Route.Rules = append([]singBoxRule{windowsTUNSniffRule()}, c.Route.Rules...) },
	} {
		var config singBoxConfig
		if err := json.Unmarshal(source, &config); err != nil {
			t.Fatal(err)
		}
		mutate(&config)
		body, _ := json.Marshal(config)
		for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
			if _, err := DeriveWindowsRuntimeConfig(body, profile, WindowsInstalledCAPath); err == nil {
				t.Fatal("[§7.2.1] 远端配置越过了本机域名接管的派生边界")
			}
		}
	}
}
