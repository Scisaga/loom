package enrollmentv2

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestRealDeviceIssuanceFirstResultSurvivesRestartWithoutResigning(t *testing.T) {
	input, key := deviceIssuerFixture(t)
	view := issuerInitialView(t, input)
	path := filepath.Join(t.TempDir(), "first-results.json")
	calls := 0
	service, err := OpenDurableProvisionalService(path,
		func(_ context.Context, _ string, _ VerifiedClaimAttemptV2, record DurableRecord, coordinate EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
			calls++
			input.Reservation, input.Coordinate = record, coordinate
			return PrepareReservedDeviceIssuance(input, view, []wire.SecretArtifactRefV2{}, nil, key, nil)
		})
	if err != nil {
		t.Fatal(err)
	}
	id, err := ProvisionalOperationID(&input.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.PrepareProvisional(context.Background(), id, VerifiedClaimAttemptV2{}, input.Reservation, input.Coordinate)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || wire.VerifyEnrollmentProvisionalIssuance(&first.Issuance, &first.Profile) != nil {
		t.Fatal("真实 CA first-result 不可验证")
	}
	reopened, err := OpenDurableProvisionalService(path,
		func(context.Context, string, VerifiedClaimAttemptV2, DurableRecord, EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
			t.Fatal("重启重复调用了 CA signer")
			return PreparedProvisionalV1{}, errors.New("demo-unreachable")
		})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := reopened.PrepareProvisional(context.Background(), id, VerifiedClaimAttemptV2{}, input.Reservation, input.Coordinate)
	if err != nil || !wire.EqualCanonical(first, replayed) {
		t.Fatalf("重启没有保留 exact certificate/result/issuance: %v", err)
	}
	view.Active.IdentitySPKIHash = wire.EmptyHashV1
	if _, err := PrepareReservedDeviceIssuance(input, view, nil, nil, key, &issuerRandomGuard{t: t}); err == nil {
		t.Fatal("签发器接受 renderer 替换已 admission identity")
	}
}

func issuerInitialView(t *testing.T, input DeviceIssuanceContext) wire.DeviceViewPayloadV2 {
	t.Helper()
	intent := input.Reservation.ClaimEvidence.Opening.DeviceEnrollmentIntent
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", intent.Membership)
	responsibilitiesHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", intent.Responsibilities)
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", intent.Grants)
	endpoints := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: intent.ClusterID, DeviceID: intent.DeviceID,
		DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	endpointHash, _ := wire.DeviceEndpointBundleHash(&endpoints)
	secretRoot, _ := wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{})
	return wire.DeviceViewPayloadV2{Schema: 2, ClusterID: intent.ClusterID, DeviceID: intent.DeviceID,
		DeviceGeneration: 1, State: "active", Active: &wire.DeviceActiveViewV1{
			IdentitySPKIHash: input.Reservation.State.IdentityKeyHash,
			Membership:       intent.Membership, MembershipHash: membershipHash,
			Responsibilities: intent.Responsibilities, ResponsibilitiesHash: responsibilitiesHash,
			Grants: intent.Grants, GrantsHash: grantsHash, EndpointBundle: endpoints, EndpointBundleHash: endpointHash,
			ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{}, SecretArtifactRefsRoot: secretRoot}}
}
