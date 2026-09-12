package wire

import "testing"

func TestEnrollmentResponsibilitiesEnforceOrdinaryRoleCombinations(t *testing.T) {
	valid := [][]string{
		{"use_loom"},
		{"forward"},
		{"forward", "internet_egress"},
		{"use_loom", "forward"},
		{"use_loom", "forward", "internet_egress"},
	}
	for _, values := range valid {
		candidate := EnrollmentResponsibilitiesV1{Schema: 1, Values: values}
		if err := ValidateEnrollmentResponsibilities(&candidate); err != nil {
			t.Fatalf("valid responsibilities %v rejected: %v", values, err)
		}
	}
	invalid := [][]string{
		{},
		{"internet_egress"},
		{"use_loom", "internet_egress"},
		{"forward", "use_loom"},
		{"control"},
		{"forward", "forward"},
	}
	for _, values := range invalid {
		candidate := EnrollmentResponsibilitiesV1{Schema: 1, Values: values}
		if err := ValidateEnrollmentResponsibilities(&candidate); err == nil {
			t.Fatalf("invalid responsibilities %v accepted", values)
		}
	}
}

func TestDeviceViewRejectsSignedButSemanticallyInvalidResponsibilities(t *testing.T) {
	payload := validDeviceViewPayloadForResponsibilities(t)
	payload.Active.Responsibilities = EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"internet_egress"}}
	payload.Active.ResponsibilitiesHash, _ = HashObject("loom-enrollment-responsibilities-v1",
		payload.Active.Responsibilities)
	if _, err := DeviceViewHash(&payload); err == nil {
		t.Fatal("Device view accepted internet_egress without forward after exact hash recompute")
	}
	payload.Active.Responsibilities = EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"control"}}
	payload.Active.ResponsibilitiesHash, _ = HashObject("loom-enrollment-responsibilities-v1",
		payload.Active.Responsibilities)
	if _, err := DeviceViewHash(&payload); err == nil {
		t.Fatal("Device view accepted self-declared control responsibility after exact hash recompute")
	}
}

func validDeviceViewPayloadForResponsibilities(t *testing.T) DeviceViewPayloadV2 {
	t.Helper()
	membership := EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}}
	grants := EnrollmentDestinationGrantsV1{Schema: 1, Values: []EnrollmentDestinationGrantV1{}}
	membershipHash, _ := HashObject("loom-enrollment-membership-v1", membership)
	responsibilitiesHash, _ := HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	grantsHash, _ := HashObject("loom-enrollment-destination-grants-v1", grants)
	bundle := DeviceEndpointBundleV1{Schema: 1, ClusterID: "cluster", DeviceID: "device",
		DeviceGeneration: 1, DataIngressSets: []DeviceDataIngressBindingV1{}}
	bundleHash, err := DeviceEndpointBundleHash(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	secretRoot, _ := SecretArtifactRefsRoot([]SecretArtifactRefV2{})
	return DeviceViewPayloadV2{Schema: 2, ClusterID: "cluster", DeviceID: "device",
		DeviceGeneration: 1, State: "active", Active: &DeviceActiveViewV1{
			IdentitySPKIHash: HashRaw("responsibilities-test", []byte("identity")),
			Membership:       membership, MembershipHash: membershipHash,
			Responsibilities: responsibilities, ResponsibilitiesHash: responsibilitiesHash,
			Grants: grants, GrantsHash: grantsHash, EndpointBundle: bundle,
			EndpointBundleHash: bundleHash, ConfigArtifactRefs: []DeviceConfigArtifactRefV1{},
			SecretArtifactRefsRoot: secretRoot,
		}}
}
