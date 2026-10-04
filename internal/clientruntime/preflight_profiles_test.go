package clientruntime

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestWindowsCapturePreservesAuthorizationAndDoesNotInventDNS(t *testing.T) {
	source, _ := pathPlanFixture(t)
	original := bytes.Clone(source)
	signed, _ := decodeWindowsConfig(source)
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableMixedProfile, WindowsPortableTUNProfile} {
		t.Run(string(profile), func(t *testing.T) {
			body, err := DeriveWindowsRuntimeConfig(source, profile, nil)
			if err != nil {
				t.Fatal(err)
			}
			c, _ := decodeWindowsConfig(body)
			prefix := 1
			if profile != WindowsPortableMixedProfile {
				prefix = 2
			}
			if c.DNS != nil || !reflect.DeepEqual(c.Outbounds, signed.Outbounds) || c.Route.Final != "reject" || !reflect.DeepEqual(c.Route.Rules[prefix:], signed.Route.Rules) || !bytes.Equal(source, original) {
				t.Fatal("capture changed authenticated authorization or invented DNS")
			}
			if ValidateWindowsSingBox(body) == nil {
				t.Fatal("derived capture accepted as source")
			}
			if err := ValidateWindowsRuntimeConfig(body, profile); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestWindowsRejectsOldRuntimeFacilities(t *testing.T) {
	source, _ := pathPlanFixture(t)
	for _, change := range []func(*singBoxConfig){
		func(c *singBoxConfig) { c.DNS = &singBoxDNS{Servers: []singBoxDNSServer{{Address: "192.0.2.53"}}} },
		func(c *singBoxConfig) { c.Route.Final = "block" },
		func(c *singBoxConfig) {
			c.Outbounds[1].TLS = &singBoxTLS{Enabled: true, CertificatePath: `C:\demo\ca.crt`}
		},
		func(c *singBoxConfig) { c.Outbounds[1].OverrideAddress = "192.0.2.1" },
		func(c *singBoxConfig) {
			c.Route.Rules = append([]singBoxRule{windowsMixedSniffRule()}, c.Route.Rules...)
		},
	} {
		c, _ := decodeWindowsConfig(source)
		change(&c)
		body, _ := json.Marshal(c)
		if _, err := DeriveWindowsRuntimeConfig(body, WindowsPortableMixedProfile, nil); err == nil {
			t.Fatal("legacy or broadened source accepted")
		}
	}
}
