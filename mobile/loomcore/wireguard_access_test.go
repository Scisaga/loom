package loomcore

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"loom/internal/control"
)

func TestAndroidWGAccessPreservesSharedPrivateRuntime(t *testing.T) {
	seed := sha256.Sum256([]byte("demo-android-wg-ca"))
	signer := ed25519.NewKeyFromSeed(seed[:])
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := ecdh.X25519().NewPrivateKey(seed[:])
	public := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	name, trust := "demo.example", []string{base64.RawURLEncoding.EncodeToString(der)}
	addresses := []string{"198.51.100.1/32"}
	state, body := androidFixture(t, 7, false, func(p *control.Projection) {
		owner := p.DeviceAuthorizations[0]
		owner.ID, owner.Platform, owner.Responsibilities, owner.PolicyIDs = "demo-exit", "linux", []string{"forward", "internet_egress"}, []string{}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, owner)
		p.NetworkIntent.Policies[0].AllowDirect = new(false)
		p.NetworkIntent.Resources = []control.TransportResource{
			{ID: "demo-hy2", Kind: "hysteria2", OwnerNodeID: owner.ID, ListenerID: "demo-hy2", DialHost: "192.0.2.10", DialPort: 443, Authentication: control.ResourceAuthentication{ServerName: &name, CACertificates: &trust}},
			{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: owner.ID, ListenerID: "demo-wg", DialHost: "192.0.2.10", DialPort: 51820, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: &addresses}, AccessEnabled: true},
		}
	})
	profileBody, err := AndroidDeviceProfile(body)
	if err != nil {
		t.Fatal(err)
	}
	var profile androidProfile
	if err := json.Unmarshal(profileBody, &profile); err != nil {
		t.Fatal(err)
	}
	var certified, actual map[string]json.RawMessage
	if json.Unmarshal([]byte(state.LKG.View.RuntimeProfile.Config), &certified) != nil || json.Unmarshal([]byte(profile.Config), &actual) != nil {
		t.Fatal("runtime projection is invalid")
	}
	var before, after any
	_ = json.Unmarshal(certified["outbounds"], &before)
	_ = json.Unmarshal(actual["outbounds"], &after)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if !bytes.Equal(a, b) || len(profile.Routes) != 2 || len(state.LKG.View.WireGuardPeers) != 0 {
		t.Fatal("Android changed WG identity, Hy2 transport or peer privacy")
	}
	var outbounds []struct {
		Type            string `json:"type"`
		SystemInterface bool   `json:"system"`
		PrivateKey      string `json:"private_key"`
	}
	_ = json.Unmarshal(actual["endpoints"], &outbounds)
	count := 0
	for _, outbound := range outbounds {
		if outbound.Type == "wireguard" {
			count++
			if outbound.SystemInterface || outbound.PrivateKey == "" {
				t.Fatal("Android did not retain user-space WG")
			}
		}
	}
	if count != 1 {
		t.Fatal("Android split one shared resource into multiple WG sessions")
	}
}
