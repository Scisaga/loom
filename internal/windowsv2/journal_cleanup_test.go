package windowsv2

import (
	"testing"

	"loom/internal/wire"
)

func TestInstalledEnrollmentJournalMatchRequiresExactCompletedClaimAndResult(t *testing.T) {
	core := wire.EnrollmentClaimCoreV2{Schema: 2, ClusterID: "demo-cluster",
		InviteID: "demo-invite", RequestID: "demo-request"}
	artifact := wire.EnrollmentResultArtifactV1{Schema: 1}
	state := &StateV1{Enrollment: EnrollmentInstallationV1{
		ClaimCore: core, ClaimCoreHash: "claim-hash", TransactionStateHash: "transaction-hash",
		ResultArtifactHash: "artifact-hash", ResultArtifact: artifact,
	}}
	journal := &EnrollmentJournalV1{ClaimCore: core, ClaimCoreHash: "claim-hash",
		Result: &wire.EnrollmentClaimResultV2{Status: "completed",
			TransactionStateHash: "transaction-hash", ResultArtifactHash: "artifact-hash",
			ResultArtifact: &artifact}}
	if !installedEnrollmentJournalMatches(state, journal) {
		t.Fatal("拒绝了与正式 LKG 完全一致的 completed journal")
	}

	mutations := []func(*EnrollmentJournalV1){
		func(value *EnrollmentJournalV1) { value.ClaimCoreHash = "other" },
		func(value *EnrollmentJournalV1) { value.ClaimCore.RequestID = "other" },
		func(value *EnrollmentJournalV1) { value.Result.TransactionStateHash = "other" },
		func(value *EnrollmentJournalV1) { value.Result.ResultArtifactHash = "other" },
		func(value *EnrollmentJournalV1) { value.Result.ResultArtifact.Schema = 2 },
		func(value *EnrollmentJournalV1) { value.Result.Status = "reserved" },
	}
	for index, mutate := range mutations {
		candidate := cloneValue(*journal)
		mutate(&candidate)
		if installedEnrollmentJournalMatches(state, &candidate) {
			t.Fatalf("接受了第 %d 个分叉 journal", index)
		}
	}
}
