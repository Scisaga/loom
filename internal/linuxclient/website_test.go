package linuxclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"loom/internal/clientadapter"
	"loom/internal/control"
	"os"
	"reflect"
	"testing"
)

func TestLinuxWebsiteProxyAndTUNUnderlayAreSeparate(t *testing.T) {
	root, err := os.ReadFile("../control/testdata/demo-website-root.pem")
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := pem.Decode(root)
	trust := control.PublicTrust{ID: control.WebsiteTrustID(certificate.Bytes), Purpose: "website", CertificateDER: base64.RawURLEncoding.EncodeToString(certificate.Bytes)}
	_, _, makeView := linuxAcceptanceFixture(t, func(_ uint64, view *control.DeviceView) {
		view.PublicTrust = []control.PublicTrust{trust}
		endpoint := view.Endpoints[0]
		endpoint.ID, endpoint.Host, endpoint.Port, endpoint.ServerName, endpoint.WebsiteTrustID, endpoint.Modes = "demo-website", "192.0.2.20", 8443, "control.loom", trust.ID, []string{"web"}
		view.WebEndpoints = []control.EndpointGeneration{endpoint}
	})
	view := makeView(7, true).View
	before, _ := control.CanonicalEncode(view)
	website, err := clientadapter.WebsiteAccessFor(view, []string{"192.0.2.20"})
	if err != nil {
		t.Fatal(err)
	}
	for _, capture := range []string{"mixed", "tun"} {
		config, server, err := generationConfigs(view, "demo-secret", nil, capture, nil, website)
		if err != nil || server != "" {
			t.Fatal(capture, err)
		}
		var result struct {
			Inbounds []struct {
				Type       string   `json:"type"`
				Exclusions []string `json:"route_exclude_address"`
			} `json:"inbounds"`
			Outbounds []map[string]any `json:"outbounds"`
		}
		if err := json.Unmarshal([]byte(config), &result); err != nil {
			t.Fatal(err)
		}
		mixed, tun := false, false
		for _, inbound := range result.Inbounds {
			mixed = mixed || inbound.Type == "mixed"
			if inbound.Type == "tun" {
				tun = true
				if !reflect.DeepEqual(inbound.Exclusions, []string{"192.0.2.20/32"}) {
					t.Fatal("website underlay entered TUN")
				}
			}
		}
		if !mixed || tun != (capture == "tun") {
			t.Fatal("Linux private website has no explicit proxy or changed capture")
		}
		for _, outbound := range result.Outbounds {
			if capture == "tun" && outbound["tag"] == "website-underlay" && outbound["netns"] != tunUnderlayReference {
				t.Fatal("website socket lost its pinned underlay")
			}
		}
	}
	after, _ := control.CanonicalEncode(view)
	if !bytes.Equal(before, after) {
		t.Fatal("website execution rewrote certified authority")
	}
}
