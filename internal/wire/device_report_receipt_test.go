package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestDeviceReportReceiptBindsExactAttemptAndBoundsObservations(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := json.RawMessage(`{"healthy":true,"version":"demo-build"}`)
	payloadHash, _ := DeviceReportPayloadHash(payload)
	report, err := SignDeviceReport(DeviceReportBodyV2{Schema: 2, ClusterID: "cluster", DeviceID: "demo-device", ReportID: "demo-report", ReportSequence: 7,
		GeneratedAt: "2026-09-11T12:00:00Z", AcceptedFloors: reportTestFloors(), Kind: "health", PayloadSchema: 1, PayloadHash: payloadHash}, payload, key, DeviceReportSchemaRegistry{"health": 1})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := DeviceReportEnvelopeHash(&report)
	receipt, err := NewDeviceReportReceipt(report.Body, hash, []json.RawMessage{json.RawMessage(`{"node":"demo-server","ts":"2026-09-11T12:00:00Z"}`)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := MarshalCanonical(receipt)
	decoded, err := DecodeDeviceReportReceipt(raw, &report)
	if err != nil || !EqualCanonical(decoded, receipt) {
		t.Fatal("valid receipt rejected", err)
	}
	for _, change := range []func(*DeviceReportReceiptV1){
		func(v *DeviceReportReceiptV1) { v.DeviceID = "demo-other" },
		func(v *DeviceReportReceiptV1) { v.ReportSequence++ },
		func(v *DeviceReportReceiptV1) { v.ReportEnvelopeHash = EmptyHashV1 },
		func(v *DeviceReportReceiptV1) { v.Observations = nil },
		func(v *DeviceReportReceiptV1) { v.Observations = []json.RawMessage{json.RawMessage(`[]`)} },
		func(v *DeviceReportReceiptV1) { v.Observations = make([]json.RawMessage, 257) },
	} {
		changed := receipt
		change(&changed)
		raw, _ := MarshalCanonical(changed)
		if _, err := DecodeDeviceReportReceipt(raw, &report); err == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
	changedReport := report
	changedReport.Signature.Signature += "A"
	if _, err := DecodeDeviceReportReceipt(raw, &changedReport); err == nil {
		t.Fatal("receipt accepted another signed attempt")
	}
}
