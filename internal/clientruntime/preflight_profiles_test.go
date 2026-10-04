package clientruntime

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
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

func TestWindowsCapturePreservesHy2TrustAndRelay(t *testing.T) {
	base, _ := pathPlanFixture(t)
	c, _ := decodeWindowsConfig(base)
	// Capture consumes already authenticated authorization. The native live
	// test supplies a real signed View and verifies these CA bytes with Hy2.
	tls := &singBoxTLS{Enabled: true, ServerName: "demo.example", Certificate: []string{"demo CA PEM"}}
	entry := singBoxOutbound{Type: "hysteria2", Tag: "demo-entry", Server: "demo-entry.example", ServerPort: 443,
		Password: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), TLS: tls}
	exit := entry
	exit.Tag, exit.Server, exit.Detour = "demo-candidate", "192.0.2.10", entry.Tag
	c.Outbounds = append(c.Outbounds[:1], entry, exit, c.Outbounds[2])
	source, _ := json.Marshal(c)
	for _, profile := range []WindowsRuntimeProfile{WindowsPortableMixedProfile, WindowsInstalledProfile, WindowsPortableTUNProfile} {
		body, err := DeriveWindowsRuntimeConfig(source, profile, []string{"192.0.2.53"})
		if err != nil {
			t.Fatal(profile, err)
		}
		derived, err := decodeWindowsConfig(body)
		servers := 1
		if profile != WindowsPortableMixedProfile {
			servers++
		}
		if err != nil || !reflect.DeepEqual(derived.Outbounds[:len(c.Outbounds)], c.Outbounds) ||
			len(derived.DNS.Servers) != servers || derived.DNS.Servers[0].Address != "192.0.2.53" {
			t.Fatal("Windows capture changed Hy2 credentials, trust, chain or certified DNS", err)
		}
	}
	for _, change := range []func(*singBoxConfig){
		func(c *singBoxConfig) { c.Outbounds[1].TLS.Insecure = true },
		func(c *singBoxConfig) { c.Outbounds[1].TLS.DisableSNI = true },
		func(c *singBoxConfig) { c.Outbounds[1].TLS.Certificate = nil },
		func(c *singBoxConfig) { c.Outbounds[1].TLS.CertificatePath = "demo-ca.pem" },
		func(c *singBoxConfig) { c.Outbounds[1].BindInterface = "demo-interface" },
		func(c *singBoxConfig) { c.Outbounds[1].Detour = "demo-candidate" },
		func(c *singBoxConfig) { c.Outbounds[2].Detour = "dns-underlay" },
		func(c *singBoxConfig) { c.Outbounds[2].Detour = "service:demo-service" },
	} {
		changed, _ := decodeWindowsConfig(source)
		change(&changed)
		body, _ := json.Marshal(changed)
		if _, err := DeriveWindowsRuntimeConfig(body, WindowsPortableMixedProfile, []string{"192.0.2.53"}); err == nil {
			t.Fatal("accepted broadened or recursive transport")
		}
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
