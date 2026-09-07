package loomcore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const reportFixtureTimestamp = "2026-09-07T12:34:56.123456789Z"

func signP256Message(t *testing.T, privateKey *ecdsa.PrivateKey, message []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func TestAndroidReportCanonicalBytesMatchAuthoritativeContracts(t *testing.T) {
	attestMessage, err := PrepareObservationAttestation("android-a", "0123456789ab", reportFixtureTimestamp)
	if err != nil {
		t.Fatal(err)
	}
	attestDigest := sha256.Sum256(attestMessage)
	if len(attestMessage) != 338 || hex.EncodeToString(attestDigest[:]) != "12ee43944a5d06fb2e31d88ab58dd670096e0e41779e851015dd2d53bc7f6801" {
		t.Fatalf("loom-attest-v5 bytes drifted: len=%d sha=%x", len(attestMessage), attestDigest)
	}
	problems := []byte(`["missing probe","configuration unknown","missing probe"]`)
	selfCheckMessage, err := PrepareSelfCheckAttestation("android-a", reportFixtureTimestamp, problems)
	if err != nil {
		t.Fatal(err)
	}
	selfCheckDigest := sha256.Sum256(selfCheckMessage)
	if len(selfCheckMessage) != 161 || hex.EncodeToString(selfCheckDigest[:]) != "6bdbd5c7c4170b32a9e2034e741cb214be149c997196b151433e7afe81ed74a0" {
		t.Fatalf("loom-selfcheck-v1 bytes drifted: len=%d sha=%x", len(selfCheckMessage), selfCheckDigest)
	}
}

func TestAssembleObservationProducesExistingFiveFieldWireShape(t *testing.T) {
	privateKey, _, caPEM, certPEM := testP256Identity(t, "android-a")
	problems := []byte(`["missing probe","configuration unknown","missing probe"]`)
	attestMessage, _ := PrepareObservationAttestation("android-a", "0123456789ab", reportFixtureTimestamp)
	selfCheckMessage, _ := PrepareSelfCheckAttestation("android-a", reportFixtureTimestamp, problems)
	body, err := AssembleObservation(
		"android-a", "0123456789ab", reportFixtureTimestamp, problems, certPEM, caPEM,
		signP256Message(t, privateKey, attestMessage), signP256Message(t, privateKey, selfCheckMessage),
	)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 {
		t.Fatalf("unexpected observation fields: %s", body)
	}
	for _, name := range []string{"node", "ts", "applied", "attest", "self_check"} {
		if _, ok := fields[name]; !ok {
			t.Fatal("missing " + name)
		}
	}
	var observation minimalObservation
	if err := decodeStrictJSON(body, 1<<20, &observation); err != nil {
		t.Fatal(err)
	}
	if observation.Attest.CanonicalVersion != 5 ||
		observation.Attest.MeasurementsSHA256 != EmptyMeasurementsDigest() ||
		observation.Attest.Node != observation.Node || observation.Attest.TS != observation.TS ||
		observation.SelfCheck.Node != observation.Node || observation.SelfCheck.TS != observation.TS ||
		observation.SelfCheck.Healthy || len(observation.SelfCheck.Problems) != 2 ||
		observation.SelfCheck.Problems[0] != "configuration unknown" ||
		observation.Attest.Cert != observation.SelfCheck.Cert {
		t.Fatalf("observation binding failed: %+v", observation)
	}
}

func TestAssembleObservationRejectsWrongSignerAndInvalidInput(t *testing.T) {
	privateKey, _, caPEM, certPEM := testP256Identity(t, "android-a")
	otherKey, _, _, _ := testP256Identity(t, "android-a")
	attestMessage, _ := PrepareObservationAttestation("android-a", "0123456789ab", reportFixtureTimestamp)
	selfCheckMessage, _ := PrepareSelfCheckAttestation("android-a", reportFixtureTimestamp, nil)
	_, err := AssembleObservation(
		"android-a", "0123456789ab", reportFixtureTimestamp, nil, certPEM, caPEM,
		signP256Message(t, otherKey, attestMessage), signP256Message(t, privateKey, selfCheckMessage),
	)
	if err == nil || !strings.Contains(err.Error(), "主陈述签名") {
		t.Fatalf("wrong signer error=%v", err)
	}
	if _, err := PrepareObservationAttestation("Android-A", "0123456789ab", reportFixtureTimestamp); err == nil {
		t.Fatal("invalid node id was accepted")
	}
	if _, err := PrepareObservationAttestation("android-a", "0123456789ab", "2026-09-07T12:34:56.123400Z"); err != nil {
		t.Fatalf("valid Java Instant RFC3339 precision was rejected: %v", err)
	}
	if _, err := PrepareSelfCheckAttestation("android-a", reportFixtureTimestamp, []byte(`["bad\nproblem"]`)); err == nil {
		t.Fatal("control character in self-check problem was accepted")
	}
	if _, err := PrepareSelfCheckAttestation("android-a", reportFixtureTimestamp, []byte(`null`)); err == nil {
		t.Fatal("null problems were accepted as an array")
	}
}
