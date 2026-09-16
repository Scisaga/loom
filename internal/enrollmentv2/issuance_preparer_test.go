package enrollmentv2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestRealDeviceIssuanceFirstResultSurvivesRestartWithoutResigning(t *testing.T) {
	input, key := deviceIssuerFixture(t)
	signer := &deviceIssuerHandle{public: key.Public(), sign: key.Sign}
	view := issuerInitialView(t, input)
	path := filepath.Join(t.TempDir(), "first-results.json")
	calls := 0
	service, err := OpenDurableProvisionalService(path,
		func(_ context.Context, _ string, _ VerifiedClaimAttemptV2, record DurableRecord, coordinate EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
			calls++
			input.Reservation, input.Coordinate = record, coordinate
			return PrepareReservedDeviceIssuance(input, view, []wire.SecretArtifactRefV2{}, nil, signer, nil)
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
	if calls != 1 || signer.calls != 2 || wire.VerifyEnrollmentProvisionalIssuance(&first.Issuance, &first.Profile) != nil {
		t.Fatal("真实 CA first-result 不可验证")
	}
	recovered, err := ReadDurableProvisionalResults(path)
	if err != nil || len(recovered) != 1 || !wire.EqualCanonical(recovered[0].Prepared, first) ||
		!wire.EqualCanonical(recovered[0].Reservation, input.Reservation) || !wire.EqualCanonical(recovered[0].Coordinate, input.Coordinate) {
		t.Fatalf("日志尚未落盘时无法恢复首次签发与原 reservation: %v", err)
	}
	// 文件自身被替换或修改不能以“已经签发”为理由跳过 reservation/QC 绑定。
	stored, err := readProvisionalFirstResults(path)
	if err != nil {
		t.Fatal(err)
	}
	stored.Records[0].Reservation.ClaimEvidence.Opening.DeviceEnrollmentIntent.DeviceID = "demo-tampered-device"
	corrupt, _ := wire.MarshalCanonical(stored)
	badPath := filepath.Join(t.TempDir(), "corrupt-first-results.json")
	if err := os.WriteFile(badPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDurableProvisionalResults(badPath); err == nil {
		t.Fatal("接受与首次签发请求不符的 reservation")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDurableProvisionalResults(path); err == nil {
		t.Fatal("读取了权限泄漏的 first-result 文件")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
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
