package clientruntime

import (
	"encoding/json"
	"loom/internal/clientadapter"
	"reflect"
	"testing"
)

func TestWindowsWebsiteCaptureAndExactRouteValidation(t *testing.T) {
	website := clientadapter.WebsiteAccess{Port: 8443, Addresses: []string{"192.0.2.20", "2001:db8::20"}}
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
		body, err := DeriveWindowsRuntimeConfig([]byte(validWindowsConfig("")), profile, nil, nil, website)
		if err != nil {
			t.Fatal(profile, err)
		}
		config, err := decodeWindowsConfig(body)
		if err != nil {
			t.Fatal(err)
		}
		if profile != WindowsPortableMixedProfile {
			exclusions, _ := website.Exclusions()
			if !reflect.DeepEqual(config.Inbounds[1].RouteExcludeAddress, exclusions) {
				t.Fatal("website underlay enters TUN")
			}
		}
		for name, change := range map[string]func(*singBoxConfig){
			"other domain": func(v *singBoxConfig) { v.Route.Rules[0].Domain = []string{"demo.example"} },
			"all ports":    func(v *singBoxConfig) { v.Route.Rules[0].Port = nil },
			"UDP":          func(v *singBoxConfig) { v.Route.Rules[0].Network = "udp" },
			"unbound DNS": func(v *singBoxConfig) {
				for index := range v.DNS.Servers {
					if v.DNS.Servers[index].Tag == "loom-overlay-dns" {
						v.DNS.Servers[index].StaticRecords["control.loom"] = nil
					}
				}
			},
			"changed outbound": func(v *singBoxConfig) { v.Outbounds[len(v.Outbounds)-1].BindInterface = "demo-interface" },
		} {
			changed, _ := decodeWindowsConfig(body)
			change(&changed)
			wire, _ := json.Marshal(changed)
			if ValidateWindowsRuntimeConfig(wire, profile) == nil {
				t.Fatal(profile, name, "accepted")
			}
		}
		if profile != WindowsPortableMixedProfile {
			config.Inbounds[1].RouteExcludeAddress = []string{"0.0.0.0/0"}
			wire, _ := json.Marshal(config)
			if ValidateWindowsRuntimeConfig(wire, profile) == nil {
				t.Fatal("broadened website exclusions accepted")
			}
		}
	}
}
