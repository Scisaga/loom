package nodepresence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"testing"
	"time"
)

func testIdentity(t *testing.T) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), &key.PublicKey
}

func TestHeartbeatHasOnlyMinimalSignedFields(t *testing.T) {
	key, publicKey := testIdentity(t)
	now := time.Date(2026, 9, 14, 8, 0, 0, 123, time.UTC)
	heartbeat, err := Sign("demo-device", now, key)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.Node != "demo-device" || heartbeat.TS != "2026-09-14T08:00:00.000000123Z" || heartbeat.Signature == "" {
		t.Fatalf("心跳字段=%+v", heartbeat)
	}
	if _, err := Verify(heartbeat, publicKey, now.Add(5*time.Second), MaximumTransit); err != nil {
		t.Fatal(err)
	}
	heartbeat.Node = "demo-other"
	if _, err := Verify(heartbeat, publicKey, now.Add(5*time.Second), MaximumTransit); err == nil {
		t.Fatal("篡改 node 的心跳通过了验证")
	}
}

func TestHeartbeatCanonicalFramingIsStable(t *testing.T) {
	message, err := Message("demo-device", "2026-09-14T08:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	values := []string{"loom-presence-v1", "demo-device", "2026-09-14T08:00:00Z"}
	offset := 0
	for _, want := range values {
		if offset+8 > len(message) {
			t.Fatal("canonical 字段长度前缀被截断")
		}
		size := int(binary.BigEndian.Uint64(message[offset : offset+8]))
		offset += 8
		if size != len(want) || offset+size > len(message) || string(message[offset:offset+size]) != want {
			t.Fatalf("canonical 字段=%q size=%d, want %q", message[offset:offset+size], size, want)
		}
		offset += size
	}
	if offset != len(message) {
		t.Fatal("canonical 原文含额外字段")
	}
}

func TestHeartbeatRejectsStaleFutureAndWrongKey(t *testing.T) {
	key, publicKey := testIdentity(t)
	_, other := testIdentity(t)
	now := time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)
	heartbeat, err := Sign("demo-device", now, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(heartbeat, publicKey, now.Add(MaximumTransit+time.Nanosecond), MaximumTransit); err == nil {
		t.Fatal("过期心跳通过了验证")
	}
	if _, err := Verify(heartbeat, publicKey, now.Add(-MaximumClockLead-time.Nanosecond), MaximumTransit); err == nil {
		t.Fatal("未来心跳通过了验证")
	}
	if _, err := Verify(heartbeat, other, now, MaximumTransit); err == nil {
		t.Fatal("错误身份通过了验证")
	}
	spki, _ := x509.MarshalPKIXPublicKey(publicKey)
	parsed, err := ParsePublicKey(base64.RawStdEncoding.EncodeToString(spki))
	if err != nil || !parsed.Equal(publicKey) {
		t.Fatalf("解析 SPKI=%v err=%v", parsed, err)
	}
}
