package clientruntime

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestWindowsMixedSniffPreservesDNSAndServiceAuthorization(t *testing.T) {
	source, _ := pathPlanFixture(t)
	signed, _ := decodeWindowsConfig(source)
	for _, profile := range []WindowsRuntimeProfile{WindowsPortableMixedProfile, WindowsInstalledProfile, WindowsPortableTUNProfile} {
		body, err := DeriveWindowsRuntimeConfig(source, profile, []string{"192.0.2.53"})
		if err != nil {
			t.Fatal(err)
		}
		c, _ := decodeWindowsConfig(body)
		prefix := 2
		if profile != WindowsPortableMixedProfile {
			prefix = 3
		}
		if !reflect.DeepEqual(c.Route.Rules[0], windowsDNSRule(profile != WindowsPortableMixedProfile)) || !reflect.DeepEqual(c.Route.Rules[prefix-1], windowsMixedSniffRule()) || !reflect.DeepEqual(c.Route.Rules[prefix:], signed.Route.Rules) {
			t.Fatal("DNS/sniff changed Service authorization")
		}
		for _, change := range []func(*singBoxConfig){
			func(c *singBoxConfig) { c.Route.Rules = c.Route.Rules[1:] },
			func(c *singBoxConfig) { c.Route.Rules[0], c.Route.Rules[1] = c.Route.Rules[1], c.Route.Rules[0] },
			func(c *singBoxConfig) { c.Route.Rules[0].Inbound = nil },
			func(c *singBoxConfig) { c.Route.Rules[0].Port = nil },
			func(c *singBoxConfig) { c.Route.Rules[prefix-1].Rules[0].Inbound = nil },
			func(c *singBoxConfig) { c.Route.Rules[prefix-1].Rules[1].Port = nil },
			func(c *singBoxConfig) { c.Route.Rules[prefix-1].Rules = c.Route.Rules[prefix-1].Rules[:2] },
			func(c *singBoxConfig) { c.Route.Rules[prefix-1].Outbound = "demo-candidate" },
			func(c *singBoxConfig) { c.Route.Rules = append(c.Route.Rules, c.Route.Rules[prefix-1]) },
		} {
			changed, _ := decodeWindowsConfig(body)
			change(&changed)
			bad, _ := json.Marshal(changed)
			if ValidateWindowsRuntimeConfig(bad, profile) == nil {
				t.Fatal("accepted missing, reordered or broadened capture")
			}
		}
	}
}
