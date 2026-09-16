package loomcore

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func signedCurrentFixture(t *testing.T, privateKey ed25519.PrivateKey, generation uint64, snapshot, nodeID string) []byte {
	t.Helper()
	current := &deploymentCurrent{
		Schema: 1, Generation: generation, Snapshot: snapshot,
		PublishedAt: "2026-09-07T12:00:00Z",
	}
	if nodeID != "" {
		current.Assignments = []deploymentAssignment{{Node: nodeID, Snapshot: snapshot}}
	}
	message, err := current.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	current.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	body, err := marshalCanonical(current)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
