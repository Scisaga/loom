package enrollmentv2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"loom/internal/wire"
)

func TestMigrationIssuerRetainsOriginalIdentityAndRejectsChangedRequest(t *testing.T) {
	input, issuer := deviceIssuerFixture(t)
	original, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrapping, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(original.Public())
	wrap, _ := x509.MarshalPKIXPublicKey(wrapping.Public())
	hash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, spki)
	platformHash := wire.HashRaw("demo-original-platform", []byte("demo-key"))
	request, err := wire.SignRuntimeDeviceMigrationRequest(wire.RuntimeDeviceMigrationRequestBodyV1{
		Schema: 1, DeviceID: "demo-existing-device", Platform: "linux-server", PlatformKeyHash: platformHash,
		IdentitySPKIDER: base64.RawURLEncoding.EncodeToString(spki), WrappingSPKIDER: base64.RawURLEncoding.EncodeToString(wrap),
		WrappingKeyProfile: "p256-root-only-pkcs8-ecdh-v1", LegacyFloor: json.RawMessage(`{"schema":1}`)}, original)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := wire.IssuanceLogCoordinateV1{RecoveryEpoch: 2, RaftIndex: 4}
	now, _ := wire.ParseTimeZ(input.Coordinate.CommittedLogicalTime)
	der, err := PrepareMigratedDeviceCertificate(request, hash, platformHash, input.Profile,
		[]string{"use_loom"}, coordinate, now, issuer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := wire.VerifyDeviceCertificateAt(der, &input.Profile, request.Body.DeviceID,
		hash, "linux-server", []string{"use_loom"}, coordinate, now, now)
	if err != nil || !bytes.Equal(certificate.RawSubjectPublicKeyInfo, spki) {
		t.Fatal("migration did not retain original Device identity", err)
	}
	request.Body.DeviceID = "demo-other-device"
	if _, err := PrepareMigratedDeviceCertificate(request, hash, platformHash, input.Profile,
		[]string{"use_loom"}, coordinate, now, issuer, &issuerRandomGuard{t: t}); err == nil {
		t.Fatal("changed migration request reached issuer")
	}
}
