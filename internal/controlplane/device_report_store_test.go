package controlplane

import (
	"context"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestDeviceReportStoreDurablyRejectsSequenceConflictAndRollback(t *testing.T) {
	fixture := newDeviceReportFixture(t)
	report := fixture.envelope
	verified := VerifiedDeviceReportV2{body: report.Body, payload: append([]byte(nil), report.Payload...), identity: fixture.identity}
	path := filepath.Join(t.TempDir(), "device-reports.json")
	schemas := wire.DeviceReportSchemaRegistry{"health": 1}
	store, err := OpenDeviceReportStore(path, schemas)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(context.Background(), verified); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(context.Background(), verified); err != nil {
		t.Fatal("exact retry 不应失败:", err)
	}
	conflict := verified
	conflict.body.ReportID = "report-conflict"
	if err := store.Commit(context.Background(), conflict); err != ErrDeviceReportSequence {
		t.Fatalf("同 sequence 冲突未被拒绝: %v", err)
	}
	next := verified
	next.body.ReportID = "report-device-1-2"
	next.body.ReportSequence = 2
	if err := store.Commit(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	rollback := verified
	if err := store.Commit(context.Background(), rollback); err != ErrDeviceReportSequence {
		t.Fatalf("sequence rollback 未被拒绝: %v", err)
	}
	reopened, err := OpenDeviceReportStore(path, schemas)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := reopened.Snapshot()
	if len(snapshot.Reports) != 1 || snapshot.Reports[0].Body.ReportSequence != 2 ||
		snapshot.Reports[0].Body.ReportID != next.body.ReportID {
		t.Fatalf("durable latest report 丢失: %#v", snapshot)
	}
}
