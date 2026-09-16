package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMigrationRequestBindsOriginalIdentityNetworkWrappingAndFloor(t *testing.T) {
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityDER, _ := x509.MarshalPKIXPublicKey(&identity.PublicKey)
	wrappingDER, _ := x509.MarshalPKIXPublicKey(&wrapping.PublicKey)
	floor := []byte(`{"generation":17,"payload_sha256":"` + strings.Repeat("a", 64) + `","schema":1,"selected_snapshot":"123456abcdef"}`)
	body := RuntimeDeviceMigrationRequestBodyV1{Schema: 1, DeviceID: "demo-device", Platform: "android",
		PlatformKeyHash: recoveryTestHash("demo-platform"), IdentitySPKIDER: base64.RawURLEncoding.EncodeToString(identityDER),
		WrappingSPKIDER: base64.RawURLEncoding.EncodeToString(wrappingDER), WrappingKeyProfile: "p256-keystore-ecdh-v1", LegacyFloor: floor}
	request, err := SignRuntimeDeviceMigrationRequest(body, identity)
	if err != nil {
		t.Fatal(err)
	}
	identityHash, _ := HashBytes(DomainEnrollmentIdentitySPKI, identityDER)
	if err := VerifyRuntimeDeviceMigrationRequest(&request, identityHash, body.PlatformKeyHash); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RuntimeDeviceMigrationRequestV1){
		"device":   func(r *RuntimeDeviceMigrationRequestV1) { r.Body.DeviceID = "demo-other" },
		"platform": func(r *RuntimeDeviceMigrationRequestV1) { r.Body.Platform = "windows-desktop" },
		"network": func(r *RuntimeDeviceMigrationRequestV1) {
			r.Body.PlatformKeyHash = recoveryTestHash("demo-other-platform")
		},
		"floor":     func(r *RuntimeDeviceMigrationRequestV1) { r.Body.LegacyFloor = []byte(`{"generation":18}`) },
		"wrapping":  func(r *RuntimeDeviceMigrationRequestV1) { r.Body.WrappingSPKIDER = r.Body.IdentitySPKIDER },
		"signature": func(r *RuntimeDeviceMigrationRequestV1) { r.Signature = "" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := request
			mutate(&copy)
			if err := VerifyRuntimeDeviceMigrationRequest(&copy, identityHash, body.PlatformKeyHash); err == nil {
				t.Fatal("changed migration request accepted")
			}
		})
	}
	if err := VerifyRuntimeDeviceMigrationRequest(&request, recoveryTestHash("demo-other-key"), body.PlatformKeyHash); err == nil {
		t.Fatal("request accepted for another registered identity")
	}
	if _, err := SignRuntimeDeviceMigrationRequest(body, wrapping); err == nil {
		t.Fatal("request signed by unrelated key")
	}
}
