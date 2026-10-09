package clientruntime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"loom/internal/clientadapter"
)

func TestWindowsCaptureAcceptsOnlyTheExistingLocalRejection(t *testing.T) {
	source, _ := pathPlanFixture(t)
	blocked, err := clientadapter.WithBlockedSelectors(string(source))
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableMixedProfile, WindowsPortableTUNProfile} {
		body, err := DeriveWindowsRuntimeConfig([]byte(blocked), profile, nil, nil)
		if err != nil {
			t.Fatal(profile, err)
		}
		config, err := decodeWindowsConfig(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, outbound := range config.Outbounds {
			if outbound.Type == "selector" && outbound.Default != clientadapter.BlockedSelection {
				t.Fatal("capture derivation lost fail-closed startup")
			}
		}
		// A different unrecognized position cannot borrow the rejection exception.
		invalid := bytes.ReplaceAll(body, []byte(`"reject"`), []byte(`"demo-unknown-block"`))
		if ValidateWindowsRuntimeConfig(invalid, profile) == nil {
			t.Fatal("unknown selector block was accepted")
		}
	}
}

func TestWindowsCapturePreservesAuthorizationAndDoesNotInventDNS(t *testing.T) {
	source, _ := pathPlanFixture(t)
	original := bytes.Clone(source)
	signed, _ := decodeWindowsConfig(source)
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableMixedProfile, WindowsPortableTUNProfile} {
		t.Run(string(profile), func(t *testing.T) {
			body, err := DeriveWindowsRuntimeConfig(source, profile, nil, nil)
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

func TestWindowsCapturePreservesIndependentHy2FirstHop(t *testing.T) {
	base, _ := pathPlanFixture(t)
	c, _ := decodeWindowsConfig(base)
	// Capture consumes already authenticated authorization. The native live
	// test supplies a real signed View and verifies these CA bytes with Hy2.
	tls := &singBoxTLS{Enabled: true, ServerName: "demo.example", Certificate: []string{"demo CA PEM"}}
	entry := singBoxOutbound{Type: "hysteria2", Tag: "demo-entry", Server: "demo-entry.example", ServerPort: 443,
		Password: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), TLS: tls}
	exit := entry
	exit.Tag, exit.Server = "demo-candidate", "192.0.2.10"
	c.Outbounds = append(c.Outbounds[:1], entry, exit, c.Outbounds[2])
	source, _ := json.Marshal(c)
	for _, profile := range []WindowsRuntimeProfile{WindowsPortableMixedProfile, WindowsInstalledProfile, WindowsPortableTUNProfile} {
		body, err := DeriveWindowsRuntimeConfig(source, profile, []string{"192.0.2.53"}, nil)
		if err != nil {
			t.Fatal(profile, err)
		}
		derived, err := decodeWindowsConfig(body)
		servers := 2 // Authenticated underlay plus the closed .loom namespace.
		if profile != WindowsPortableMixedProfile {
			servers++
		}
		if err != nil || !reflect.DeepEqual(derived.Outbounds[:len(c.Outbounds)], c.Outbounds) ||
			len(derived.DNS.Servers) != servers || derived.DNS.Servers[0].Address != "udp://192.0.2.53:53" {
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
		if _, err := DeriveWindowsRuntimeConfig(body, WindowsPortableMixedProfile, []string{"192.0.2.53"}, nil); err == nil {
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
		if _, err := DeriveWindowsRuntimeConfig(body, WindowsPortableMixedProfile, nil, nil); err == nil {
			t.Fatal("legacy or broadened source accepted")
		}
	}
}

func TestWindowsWGAccessPreservesNativeUserSpaceTransportAcrossDeliveries(t *testing.T) {
	source, _ := pathPlanFixture(t)
	c, _ := decodeWindowsConfig(source)
	key := bytes.Repeat([]byte{8}, 32)
	key[31] = 64
	endpoint := singBoxEndpoint{Type: "wireguard", Tag: "wg-shared", System: false,
		Address: []string{"fdab::2/128"}, PrivateKey: base64.StdEncoding.EncodeToString(key),
		SourceRoutes: []singBoxSourceRoute{{Source: "fdab::2", Destination: "fdab:1::/64"}},
		Peers: []singBoxEndpointPeer{{Address: "192.0.2.10", Port: 51820,
			PublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
			AllowedIPs: []string{"fdab:1::/64", "fdab:2::1/128"}}}}
	c.Endpoints = []singBoxEndpoint{endpoint}
	c.Outbounds[1] = singBoxOutbound{Type: "direct", Tag: "demo-candidate", Detour: endpoint.Tag, Inet6BindAddress: "fdab::2"}
	source, _ = json.Marshal(c)
	for _, profile := range []WindowsRuntimeProfile{WindowsPortableMixedProfile, WindowsInstalledProfile, WindowsPortableTUNProfile} {
		body, err := DeriveWindowsRuntimeConfig(source, profile, []string{"192.0.2.53"}, nil)
		if err != nil {
			t.Fatal(profile, err)
		}
		got, err := decodeWindowsConfig(body)
		if err != nil || len(got.Outbounds) < len(c.Outbounds) || !reflect.DeepEqual(got.Outbounds[:len(c.Outbounds)], c.Outbounds) || !reflect.DeepEqual(got.Endpoints, c.Endpoints) {
			t.Fatal("Windows capture changed the independent WG sender", err)
		}
		if executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE"); executable != "" {
			if err := PreflightWindowsRuntime(context.Background(), executable, body, filepath.Join(t.TempDir(), "runtime"), profile); err != nil {
				t.Fatal(profile, err)
			}
		}
	}
	for _, change := range []func(*singBoxConfig){
		func(c *singBoxConfig) { c.Endpoints[0].System = true },
		func(c *singBoxConfig) { c.Endpoints[0].Peers[0].AllowedIPs = []string{"0.0.0.0/0"} },
		func(c *singBoxConfig) { c.Endpoints[0].Address = []string{"fdab::2/64"} },
		func(c *singBoxConfig) { c.Outbounds[1].Detour = "demo-candidate" },
		func(c *singBoxConfig) { c.Outbounds[1].Inet6BindAddress = "fdab::3" },
		func(c *singBoxConfig) { c.Endpoints[0].PrivateKey = "demo-invalid" },
		func(c *singBoxConfig) { c.Outbounds[1].Type = "hysteria2" },
	} {
		bad, _ := decodeWindowsConfig(source)
		change(&bad)
		body, _ := json.Marshal(bad)
		if _, err := DeriveWindowsRuntimeConfig(body, WindowsPortableMixedProfile, nil, nil); err == nil {
			t.Fatal("accepted a host interface, invalid source or nested Hy2")
		}
	}
}
