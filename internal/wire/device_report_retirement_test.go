package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestReportRetirementPreservesExactSignatureAndDoesNotAcceptForks(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	payload := json.RawMessage(`{"healthy":true,"version":"demo"}`)
	hash, _ := DeviceReportPayloadHash(payload)
	schemas := DeviceReportSchemaRegistry{"health": 1}
	envelope, err := SignDeviceReport(DeviceReportBodyV2{Schema: 2, ClusterID: "cluster", DeviceID: "demo-device",
		ReportID: "demo-report", ReportSequence: 7, GeneratedAt: now.Format(time.RFC3339),
		AcceptedFloors: reportTestFloors(), Kind: "health", PayloadSchema: 1, PayloadHash: hash}, payload, key, schemas)
	if err != nil {
		t.Fatal(err)
	}
	retire := func(value DeviceReportEnvelopeV2, floors ClientFloorsV2, at time.Time) (*RetiredDeviceReportV1, error) {
		return RetireObsoleteDeviceReport(&value, floors, &key.PublicKey, "demo-device", envelope.Signature.IdentitySPKIHash, at, schemas)
	}
	if retired, err := retire(envelope, envelope.Body.AcceptedFloors, now); err != nil || retired != nil {
		t.Fatalf("可重试报告被退休: %v", err)
	}
	next := envelope.Body.AcceptedFloors
	next.AcceptedControlRevision++
	next.HeadHash = HashRaw("demo-head", []byte("next"))
	retired, err := retire(envelope, next, now)
	if err != nil || retired == nil || retired.Reason != "superseded_floors" || !EqualCanonical(retired.Envelope, envelope) {
		t.Fatalf("认证版本前移未保留原报告: %v", err)
	}
	if sequence, err := RetiredDeviceReportSequence(retired, "demo-device"); err != nil || sequence != 7 {
		t.Fatalf("退休序号不可重读: %v", err)
	}
	if retired, err := retire(envelope, envelope.Body.AcceptedFloors, now.Add(25*time.Hour)); err != nil || retired == nil || retired.Reason != "expired" {
		t.Fatalf("过期报告无法退休: %v", err)
	}
	next.AcceptedControlRevision--
	if _, err := retire(envelope, next, now); err == nil {
		t.Fatal("接受了同版本分叉")
	}
	next = envelope.Body.AcceptedFloors
	next.AcceptedControlRevision--
	if _, err := retire(envelope, next, now); err == nil {
		t.Fatal("回退状态退休了较新 pending")
	}
	envelope.Payload = json.RawMessage(`{"healthy":false,"version":"demo"}`)
	if _, err := retire(envelope, envelope.Body.AcceptedFloors, now.Add(25*time.Hour)); err == nil {
		t.Fatal("无效签名被当成过期报告退休")
	}
}
