package loomcore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"loom/internal/control"
	"os"
	"testing"
)

func TestAndroidWebsitePreparationPreservesIdentityAndExcludesUnderlay(t *testing.T) {
	root, err := os.ReadFile("../../internal/control/testdata/demo-website-root.pem")
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := pem.Decode(root)
	trust := control.PublicTrust{ID: control.WebsiteTrustID(certificate.Bytes), Purpose: "website", CertificateDER: base64.RawURLEncoding.EncodeToString(certificate.Bytes)}
	_, body := androidFixture(t, 7, false, func(p *control.Projection) {
		p.NetworkIntent.PublicTrust = []control.PublicTrust{trust}
		endpoint := p.EndpointGenerations[0]
		endpoint.ID, endpoint.Host, endpoint.Port, endpoint.ServerName, endpoint.WebsiteTrustID, endpoint.Modes = "demo-website", "192.0.2.20", 8443, "control.loom", trust.ID, []string{"web"}
		p.EndpointGenerations = append(p.EndpointGenerations, endpoint)
	})
	original := append([]byte{}, body...)
	preview, err := AndroidDeviceProfile(body)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := PrepareAndroidDeviceProfile(body)
	if err != nil {
		t.Fatal(err)
	}
	var prepared, projected androidProfile
	if json.Unmarshal(runtime, &prepared) != nil || json.Unmarshal(preview, &projected) != nil {
		t.Fatal("invalid host profile")
	}
	if !prepared.HasWebsite || !projected.HasWebsite || prepared.ViewDigest != projected.ViewDigest || prepared.NodeID != projected.NodeID {
		t.Fatal("operational website preparation changed authority")
	}
	var config struct {
		Inbounds []struct {
			Exclusions []string `json:"route_exclude_address"`
		} `json:"inbounds"`
		DNS struct {
			Servers []struct {
				Records map[string][]string `json:"static_records"`
			} `json:"servers"`
			Rules []struct {
				Domain []string `json:"domain"`
				Server string   `json:"server"`
			} `json:"rules"`
		} `json:"dns"`
	}
	if err := json.Unmarshal([]byte(prepared.Config), &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, prefix := range config.Inbounds[0].Exclusions {
		found = found || prefix == "192.0.2.20/32"
	}
	if !found {
		t.Fatal("website underlay was captured")
	}
	found = false
	for _, server := range config.DNS.Servers {
		addresses := server.Records["control.loom"]
		found = found || len(addresses) == 1 && addresses[0] == "192.0.2.20"
	}
	if !found {
		t.Fatal("website name lost its actual endpoint address")
	}
	for _, rule := range config.DNS.Rules {
		if rule.Server == "loom-tun-domain" {
			for _, name := range rule.Domain {
				if name == "control.loom" {
					t.Fatal("website acquired a fake IP")
				}
			}
		}
	}
	if !bytes.Equal(original, body) {
		t.Fatal("website execution modified the protected device record")
	}
}
