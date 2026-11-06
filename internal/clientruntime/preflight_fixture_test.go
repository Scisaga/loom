package clientruntime

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"loom/internal/control"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// captureFixtureConfig is only a DNS/capture mechanism fixture, not a View or
// the Windows application's authorization/configuration entry point.
func captureFixtureConfig() string {
	return `{"inbounds":[{"type":"tun","tag":"tun-in","auto_route":true}],"outbounds":[{"type":"block","tag":"reject"},{"type":"direct","tag":"demo-candidate"},{"type":"selector","tag":"service:demo-service","outbounds":["demo-candidate"],"default":"demo-candidate"}],"route":{"rules":[{"type":"logical","mode":"or","rules":[{"domain":["demo-service.example"]}],"outbound":"service:demo-service"}],"final":"reject"},"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"demo-api"}}}`
}

func windowsViewFixture(t *testing.T, transports ...string) control.DeviceView {
	t.Helper()
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	key := base64.RawURLEncoding.EncodeToString(identity.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("1", 64)
	device := control.DeviceAuthorization{ID: "demo-access", Name: "Demo access", Platform: "windows", DevicePublicKey: key,
		Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, DistributionURLs: []string{}, RuntimeKey: key,
		TransactionID: "demo-join", InviteMaterialID: digest, BindingMaterialID: digest}
	any := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
	p := control.Projection{NetworkID: "demo-network", NetworkIntent: control.EmptyNetworkIntent()}
	p.NetworkIntent.Services = []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", RestrictToProbeTargets: new(false)}}
	p.NetworkIntent.Policies = []control.NetworkPolicy{{ID: "demo-policy", ServiceID: "demo-service", Name: "Demo policy", Action: "allow", EntryScope: any, RelayScope: any, ExitScope: new(any), AllowDirect: new(true), LocalEgressDevices: new([]string{})}}
	p.DeviceAuthorizations = []control.DeviceAuthorization{device}
	if len(transports) > 0 {
		owner := device
		owner.ID, owner.Platform, owner.Responsibilities, owner.PolicyIDs = "demo-exit", "linux", []string{"internet_egress"}, []string{}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, owner)
	}
	for _, kind := range transports {
		resource := control.TransportResource{ID: "demo-" + kind, Kind: kind, OwnerNodeID: "demo-exit", ListenerID: "demo-" + kind, DialHost: "192.0.2.10", DialPort: 51820}
		if kind == "wireguard" {
			private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{7}, 32))
			if err != nil {
				t.Fatal(err)
			}
			public := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
			resource.AccessEnabled = true
			resource.Authentication = control.ResourceAuthentication{PublicKey: &public, LocalAddresses: new([]string{"192.0.2.10/32"})}
		} else {
			at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"demo.example"}, NotBefore: at, NotAfter: at.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, identity.Public(), identity)
			if err != nil {
				t.Fatal(err)
			}
			name, trust := "demo.example", []string{base64.RawURLEncoding.EncodeToString(der)}
			resource.DialPort = 443
			resource.Authentication = control.ResourceAuthentication{ServerName: &name, CACertificates: &trust}
		}
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, resource)
	}
	for i := range p.DeviceAuthorizations {
		value := &p.DeviceAuthorizations[i]
		registered, err := control.DerivedWireGuardPublicKey(p.NetworkID, *value)
		if err != nil {
			t.Fatal(err)
		}
		for _, resource := range p.NetworkIntent.Resources {
			if resource.Kind == "wireguard" && resource.OwnerNodeID == value.ID {
				registered = *resource.Authentication.PublicKey
			}
		}
		value.WireGuardPublicKey = registered
	}
	view, err := control.ProjectDeviceView(p, device.ID)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func runtimeDocument(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func windowsWebsiteTrust(t *testing.T) control.PublicTrust {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	_, v4, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6, _ := net.ParseCIDR("::/0")
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: at, NotAfter: at.AddDate(1, 0, 0),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{".loom"}, ExcludedIPRanges: []*net.IPNet{v4, v6}}
	der, err := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return control.PublicTrust{ID: control.WebsiteTrustID(der), Purpose: "website", CertificateDER: base64.RawURLEncoding.EncodeToString(der)}
}
