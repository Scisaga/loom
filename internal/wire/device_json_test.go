package wire

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDeviceViewEnvelopePreservesEmptySecretRefsAndTombstoneAbsence(t *testing.T) {
	active := DeviceViewEnvelopeV2{Schema: 2, SecretArtifactRefs: []json.RawMessage{}}
	body, err := MarshalCanonical(active)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"secret_artifact_refs":[]`)) {
		t.Fatalf("active 空 secret refs 被省略: %s", body)
	}
	var replay DeviceViewEnvelopeV2
	if _, err := DecodeStrict(body, 1<<20, &replay); err != nil || replay.SecretArtifactRefs == nil || len(replay.SecretArtifactRefs) != 0 {
		t.Fatalf("active 空 secret refs 未跨 wire 保留: %#v err=%v", replay.SecretArtifactRefs, err)
	}

	tombstone := DeviceViewEnvelopeV2{Schema: 2}
	body, err = MarshalCanonical(tombstone)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("secret_artifact_refs")) {
		t.Fatalf("tombstone 意外携带 secret refs: %s", body)
	}
	withNull := append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"secret_artifact_refs":null}`)...)
	if _, err := DecodeStrict(withNull, 1<<20, &replay); err == nil {
		t.Fatal("接受了 ambiguous null secret refs")
	}
}
