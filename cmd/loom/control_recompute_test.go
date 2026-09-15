package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

func TestControlRecomputeRejectsUnrelatedRootsAndInvalidOperationPreimage(t *testing.T) {
	runtime, adminDir := progressTestRuntime(t)
	endpoint, client, address := progressTestServer(t, runtime, adminDir)
	status, err := fetchControlStatus(context.Background(), endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := newControlPingRequest(adminDir, endpoint, status, "demo-recompute", runtime.now())
	if err != nil {
		t.Fatal(err)
	}
	runtime.checkpoint = func(phase controlplane.Phase) error {
		if phase == controlplane.PhasePending {
			return errors.New("demo-stop-before-append")
		}
		return nil
	}
	encoded, _ := wire.MarshalCanonical(request)
	response, err := client.Post("https://"+address+controlplane.PrivateControlOperationPath,
		"application/json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusOK || len(runtime.journal.Records) != 1 {
		t.Fatal("未冻结已保存而未提交的 operation")
	}
	original := runtime.journal.Records[0]
	if err := runtime.verifyCommittedHead(context.Background(), original.Candidate); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*controlOperationRecordV1){
		"ca-profile-root": func(r *controlOperationRecordV1) { r.Candidate.Body.Payload.CAProfileRoot = wire.EmptyHashV1 },
		"effective-ssot":  func(r *controlOperationRecordV1) { r.Candidate.Body.Payload.EffectiveSSOTHash = wire.EmptyHashV1 },
		"device-view":     func(r *controlOperationRecordV1) { r.Candidate.Body.Payload.DeviceViewsRoot = wire.EmptyHashV1 },
		"issuer-registry": func(r *controlOperationRecordV1) {
			r.Candidate.Body.Payload.BootstrapIssuerRegistryRoot = wire.EmptyHashV1
		},
		"admin-acl":           func(r *controlOperationRecordV1) { r.Candidate.Body.Payload.AdminACLRoot = wire.EmptyHashV1 },
		"changed-signed-body": func(r *controlOperationRecordV1) { r.Operation.Body.PayloadHash = wire.EmptyHashV1 },
		"unregistered-kind":   func(r *controlOperationRecordV1) { r.Operation.Body.Kind = "demo-unauthorized" },
	} {
		t.Run(name, func(t *testing.T) {
			record := original
			mutate(&record)
			candidate, err := wire.NewHeadEntry(record.Candidate.Body)
			if err != nil {
				t.Fatal(err)
			}
			record.Candidate = candidate
			runtime.journal.Records[0] = record
			if err := runtime.verifyCommittedHead(context.Background(), candidate); err == nil {
				t.Fatal("操作树保持一致仍可修改无关 authority root 或签名对象")
			}
		})
	}
	runtime.journal.Records[0] = original
	if runtime.storage.SnapshotRaft().CommitIndex != status.Raft.CommitIndex {
		t.Fatal("候选验证改变了已提交 Raft prefix")
	}
}
