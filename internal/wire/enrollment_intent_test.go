package wire

import "testing"

func TestEnrollmentIntentKeepsForwardAndGrantsWithinPlatformBoundary(t *testing.T) {
	hash := HashRaw("loom-test-enrollment-intent", []byte("profile"))
	valid := DeviceEnrollmentIntentV1{
		Schema: 1, ClusterID: "demo-cluster", InviteID: "demo-invite", DeviceID: "demo-device", Platform: "linux-server",
		DeviceCertificateProfileRef: DeviceCertificateProfileRefV1{ProfileID: "demo-profile", Generation: 1,
			DeviceCertificateProfileIntentHash: hash, DeviceCertificateProfileStateHash: hash},
		WrappingKeyProfiles: []string{"p256-root-only-pkcs8-ecdh-v1"},
		Membership:          EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities:    EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"forward"}},
		Grants:              EnrollmentDestinationGrantsV1{Schema: 1, Values: []EnrollmentDestinationGrantV1{}},
	}
	if err := ValidateEnrollmentIntent(&valid); err != nil {
		t.Fatal(err)
	}
	withGrant := valid
	withGrant.Grants.Values = []EnrollmentDestinationGrantV1{{Kind: "egress", TargetID: "demo-egress"}}
	if err := ValidateEnrollmentIntent(&withGrant); err == nil {
		t.Fatal("forward-only intent accepted a destination grant")
	}
	androidForward := valid
	androidForward.Platform = "android"
	androidForward.WrappingKeyProfiles = []string{"p256-keystore-ecdh-v1"}
	if err := ValidateEnrollmentIntent(&androidForward); err == nil {
		t.Fatal("Android intent accepted forward responsibility")
	}
}
