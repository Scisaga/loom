package main

import (
	"testing"

	"loom/internal/wire"
)

func TestCertifiedApplicationCacheKeepsAuthenticatedCopies(t *testing.T) {
	runtime, _, migration, _ := controlMigratedDeviceRuntime(t, nil)
	original, err := runtime.readDeviceIdentityLocked(migration.DeviceCertificateHash)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := runtime.certifiedApplicationLocked()
	if err != nil {
		t.Fatal(err)
	}
	projection.Devices[0].View.DeviceID = "demo-replaced-copy"
	original.DeviceConfigUpdates[0].RecoveryPolicy.ClusterID = "demo-replaced-copy"
	got, err := runtime.readDeviceIdentityLocked(migration.DeviceCertificateHash)
	if err != nil || got.Record.DeviceID != migration.DeviceID ||
		got.DeviceConfigUpdates[0].RecoveryPolicy.ClusterID != migration.ClusterID {
		t.Fatal("reader 返回值修改了缓存中的认证投影", err)
	}
	var activation *controlOperationRecordV1
	for i := range runtime.journal.Records {
		if runtime.journal.Records[i].Activation != nil {
			activation = &runtime.journal.Records[i]
			break
		}
	}
	before := controlClone(*activation)
	activation.Activation.Application.Devices[0].View.DeviceID = "demo-tampered-preimage"
	if _, err := runtime.certifiedApplicationLocked(); err == nil {
		t.Fatal("同一 Head 下修改日志 preimage 绕过了缓存验证")
	}
	*activation = before
	last := &runtime.journal.Records[len(runtime.journal.Records)-1]
	result := last.Result
	last.Result = nil
	if _, err := runtime.certifiedApplicationLocked(); err == nil {
		t.Fatal("缓存放行了尚未取得认证结果的事务")
	}
	last.Result = result
	again, err := runtime.readDeviceIdentityLocked(migration.DeviceCertificateHash)
	if err != nil || !wire.EqualCanonical(got, again) {
		t.Fatal("原始认证日志未恢复同一结果", err)
	}
}

func TestApplicationRecordCacheIgnoresOnlyDeliveryPhases(t *testing.T) {
	runtime, _, _, _ := controlMigratedDeviceRuntime(t, nil)
	record := controlClone(runtime.journal.Records[len(runtime.journal.Records)-1])
	before, err := controlApplicationRecordKey(record)
	if err != nil {
		t.Fatal(err)
	}
	record.Phases = append(record.Phases, "applied")
	record.Result = nil
	after, err := controlApplicationRecordKey(record)
	if err != nil || before != after {
		t.Fatalf("交付 phase/result 使 application cache 失效: before=%s after=%s err=%v", before, after, err)
	}
	record.Candidate.HeadHash = wire.HashRaw("application-cache-test", []byte("changed"))
	changed, err := controlApplicationRecordKey(record)
	if err != nil || changed == before {
		t.Fatalf("认证投影输入变化未使 application cache 失效: changed=%s err=%v", changed, err)
	}
}
