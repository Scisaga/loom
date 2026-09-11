package wire

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func TestEnrollmentResultArtifactBindsCertificateViewAndSecretRefs(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{}, NotBefore: time.Unix(1, 0).UTC(),
		NotAfter: time.Unix(3601, 0).UTC(), BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	membership := EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}}
	grants := EnrollmentDestinationGrantsV1{Schema: 1, Values: []EnrollmentDestinationGrantV1{}}
	membershipHash, _ := HashObject("loom-enrollment-membership-v1", membership)
	responsibilitiesHash, _ := HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	grantsHash, _ := HashObject("loom-enrollment-destination-grants-v1", grants)
	endpointBundle := DeviceEndpointBundleV1{Schema: 1, ClusterID: "cluster", DeviceID: "device-1",
		DeviceGeneration: 1, DataIngressSets: []DeviceDataIngressBindingV1{}}
	endpointHash, _ := DeviceEndpointBundleHash(&endpointBundle)
	secretRefs := []SecretArtifactRefV2{}
	secretRoot, _ := SecretArtifactRefsRoot(secretRefs)
	artifact := EnrollmentResultArtifactV1{
		Schema: 1, ClusterID: "cluster", InviteID: "invite", RequestID: "request",
		DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER),
		InitialDeviceView: DeviceViewPayloadV2{
			Schema: 2, ClusterID: "cluster", DeviceID: "device-1", DeviceGeneration: 1, State: "active",
			Active: &DeviceActiveViewV1{IdentitySPKIHash: HashRaw("result-test", []byte("identity")),
				Membership: membership, MembershipHash: membershipHash, Responsibilities: responsibilities,
				ResponsibilitiesHash: responsibilitiesHash, Grants: grants, GrantsHash: grantsHash,
				EndpointBundle: endpointBundle, EndpointBundleHash: endpointHash,
				ConfigArtifactRefs: []DeviceConfigArtifactRefV1{}, SecretArtifactRefsRoot: secretRoot},
		},
		SecretArtifactRefs: secretRefs,
	}
	first, err := EnrollmentResultArtifactHash(&artifact)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnrollmentResultArtifactHash(&artifact)
	if err != nil || first != second {
		t.Fatalf("result artifact hash 不稳定: first=%s second=%s err=%v", first, second, err)
	}
	tampered := artifact
	tampered.InitialDeviceView = artifact.InitialDeviceView
	tampered.InitialDeviceView.Active = new(DeviceActiveViewV1)
	*tampered.InitialDeviceView.Active = *artifact.InitialDeviceView.Active
	tampered.InitialDeviceView.Active.SecretArtifactRefsRoot = HashRaw("result-test", []byte("other-refs"))
	if _, err := EnrollmentResultArtifactHash(&tampered); err == nil {
		t.Fatal("接受了不匹配 exact secret refs 的 result artifact")
	}
}
