package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/distribution"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

func TestEnrollmentDistributionWaitsForCertifiedExactMirrors(t *testing.T) {
	body := json.RawMessage(`{"files":{"sing-box/config.json":"{}"},"owner":"demo-device"}`)
	ref, _, err := distribution.PublishDeviceConfigArtifact(t.TempDir(), "android-runtime", "android",
		"application/vnd.loom.config+json", "android-runtime-v1", 1, body)
	if err != nil {
		t.Fatal(err)
	}
	operation := enrollmentv2.ProvisionalIssuanceOperationV1{}
	plan := controlEnrollmentRuntimePlanV1{Schema: 1, InviteID: "demo-invite", OperationID: "demo-operation",
		ClientConfigs: []controlPublishedConfigV1{{Ref: ref, Content: body}}}
	raw, err := wire.MarshalCanonical(plan)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &controlRuntime{}
	runtime.journal.Records = []controlOperationRecordV1{
		{Enrollment: &controlEnrollmentOperationV1{Mutation: enrollmentv2.EnrollmentHeadMutationV1{Preimage: &enrollmentv2.EnrollmentMutationPreimageV1{Schema: 1, Kind: "provisional",
			Provisional: &enrollmentv2.EnrollmentProvisionalPreimageV1{Record: enrollmentv2.DurableRecord{InviteID: "demo-invite"},
				Prepared: enrollmentv2.PreparedProvisionalV1{Operation: operation, RuntimePlan: raw}}}}}},
		{Result: &controlCertifiedOperationResultV1{Schema: 1, Status: "certified"},
			Enrollment: &controlEnrollmentOperationV1{Mutation: enrollmentv2.EnrollmentHeadMutationV1{Preimage: &enrollmentv2.EnrollmentMutationPreimageV1{Schema: 1, Kind: "completion",
				Completion: &enrollmentv2.EnrollmentCompletionPreimageV1{Record: enrollmentv2.DurableRecord{InviteID: "demo-invite", ProvisionalOperation: &operation}}}}}},
	}
	completion := &runtime.journal.Records[1]
	if _, err := runtime.reconcileEnrollmentDistributionRecordLocked(completion); err == nil {
		t.Fatal("未配置认证镜像仍允许 completion 对客户端成功")
	}
	first, second := t.TempDir(), t.TempDir()
	runtime.distribution, err = controlDistributionTarget([]string{first, second}, "")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := runtime.reconcileEnrollmentDistributionRecordLocked(completion)
	if err != nil || len(evidence) != 1 || evidence[0] != ref.ContentHash {
		t.Fatalf("认证镜像发布失败: evidence=%v err=%v", evidence, err)
	}
	objects, _, err := enrollmentDistributionObjects(plan)
	if err != nil {
		t.Fatal(err)
	}
	for path, expected := range objects {
		for _, root := range []string{first, second} {
			actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil || !bytes.Equal(actual, expected) {
				t.Fatalf("镜像没有 exact 制品: %v", err)
			}
		}
	}
	completion.Result = nil
	if _, err := runtime.reconcileEnrollmentDistributionRecordLocked(completion); err == nil {
		t.Fatal("未 certified completion 提前发布配置")
	}
}

func TestControlDistributionTargetRequiresProductionMirrorSet(t *testing.T) {
	if target, err := controlDistributionTarget(nil, ""); err != nil || target != nil {
		t.Fatalf("无分发配置应保持显式禁用: %v", err)
	}
	if _, err := controlDistributionTarget([]string{t.TempDir()}, ""); err == nil {
		t.Fatal("单镜像配置被接受")
	}
	root := t.TempDir()
	if _, err := controlDistributionTarget([]string{root, root}, ""); err == nil {
		t.Fatal("重复镜像配置被接受")
	}
}
