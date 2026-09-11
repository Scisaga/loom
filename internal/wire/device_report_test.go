package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func TestDeviceReportBindsCanonicalPayloadFloorsAndP256Identity(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := json.RawMessage(`{"healthy":true,"version":"demo"}`)
	payloadHash, _ := DeviceReportPayloadHash(payload)
	body := DeviceReportBodyV2{
		Schema: 2, ClusterID: "cluster", DeviceID: "device-1", ReportID: "report-1", ReportSequence: 7,
		GeneratedAt: "2026-09-11T12:00:00Z", AcceptedFloors: reportTestFloors(),
		Kind: "health", PayloadSchema: 1, PayloadHash: payloadHash,
	}
	schemas := DeviceReportSchemaRegistry{"health": 1}
	envelope, err := SignDeviceReport(body, payload, privateKey, schemas)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDeviceReport(&envelope, &privateKey.PublicKey, body.DeviceID,
		envelope.Signature.IdentitySPKIHash, time.Date(2026, 9, 11, 12, 0, 30, 0, time.UTC),
		5*time.Minute, 30*time.Second, schemas); err != nil {
		t.Fatal(err)
	}
	tampered := envelope
	tampered.Payload = json.RawMessage(`{"healthy":false,"version":"demo"}`)
	if err := VerifyDeviceReport(&tampered, &privateKey.PublicKey, body.DeviceID,
		envelope.Signature.IdentitySPKIHash, time.Date(2026, 9, 11, 12, 0, 30, 0, time.UTC),
		5*time.Minute, 30*time.Second, schemas); err == nil {
		t.Fatal("接受了与 signed payload hash 不一致的报告")
	}
	if _, err := DeviceReportPayloadHash(json.RawMessage(`{ "healthy":true}`)); err == nil {
		t.Fatal("接受了非 canonical payload bytes")
	}
}

func TestDeviceReportRejectsHighSMalleabilityAndStaleReport(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := json.RawMessage(`{"healthy":true}`)
	payloadHash, _ := DeviceReportPayloadHash(payload)
	schemas := DeviceReportSchemaRegistry{"health": 1}
	envelope, err := SignDeviceReport(DeviceReportBodyV2{
		Schema: 2, ClusterID: "cluster", DeviceID: "device-1", ReportID: "report-1", ReportSequence: 1,
		GeneratedAt: "2026-09-11T12:00:00Z", AcceptedFloors: reportTestFloors(),
		Kind: "health", PayloadSchema: 1, PayloadHash: payloadHash,
	}, payload, privateKey, schemas)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(envelope.Signature.Signature)
	var signature struct{ R, S *big.Int }
	_, _ = asn1.Unmarshal(raw, &signature)
	signature.S.Sub(privateKey.Params().N, signature.S)
	highDER, _ := asn1.Marshal(signature)
	envelope.Signature.Signature = base64.RawURLEncoding.EncodeToString(highDER)
	if err := VerifyDeviceReport(&envelope, &privateKey.PublicKey, "device-1", envelope.Signature.IdentitySPKIHash,
		time.Date(2026, 9, 11, 12, 0, 30, 0, time.UTC), 5*time.Minute, 30*time.Second, schemas); err == nil {
		t.Fatal("接受了可塑的 high-S Device report signature")
	}
	fresh, _ := SignDeviceReport(envelope.Body, payload, privateKey, schemas)
	if err := VerifyDeviceReport(&fresh, &privateKey.PublicKey, "device-1", fresh.Signature.IdentitySPKIHash,
		time.Date(2026, 9, 11, 12, 10, 0, 0, time.UTC), 5*time.Minute, 30*time.Second, schemas); err == nil {
		t.Fatal("接受了超出 freshness window 的 Device report")
	}
}

func reportTestFloors() ClientFloorsV2 {
	hash := func(value string) string { return HashRaw("device-report-test", []byte(value)) }
	return ClientFloorsV2{
		Schema: 2, ClusterID: "cluster", AcceptedRecoveryEpoch: 0,
		RecoveryStatementHash: hash("recovery"), RecoveryPolicyHash: hash("policy"),
		AcceptedControlEpoch: 0, ControlSetHash: hash("set"), AcceptedControlRevision: 3,
		HeadHash: hash("head"), DeviceGeneration: 2, DeviceLeafHash: hash("leaf"),
		DeviceViewHash: hash("view"), BootstrapTransitionHash: hash("transition"), V2Latched: true,
	}
}
