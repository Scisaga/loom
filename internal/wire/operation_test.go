package wire

import (
	"crypto/ed25519"
	"crypto/x509"
	"testing"
	"time"
)

func testOperationBody() ControlOperationBodyV1 {
	hash := func(value string) string { return HashRaw("test-operation-v1", []byte(value)) }
	return ControlOperationBodyV1{
		Schema: 1, ClusterID: "demo-cluster", OperationID: "operation-1", AuthorID: "admin-1",
		AdminCertDigest: hash("cert"), CreatedAt: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T13:00:00Z",
		BaseRecoveryEpoch: 1, BaseRecoveryStatementHash: hash("statement"), BaseRecoveryPolicyHash: hash("policy"),
		BaseControlEpoch: 2, BaseControlSetHash: hash("set"), BaseControlRevision: 7,
		ParentHeadHash: hash("head"), Kind: "create_invite", PayloadSchema: 2,
		PayloadHash: hash("payload"), Reason: "enroll a Linux server",
	}
}

func TestControlOperationHasStrictAdminSignatureAndSchema(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-1] = 9
	privateKey := ed25519.NewKeyFromSeed(seed)
	spki, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	schemas := OperationSchemaRegistry{"create_invite": 2}
	operation, err := NewControlOperation(testOperationBody(), privateKey, schemas)
	if err != nil {
		t.Fatal(err)
	}
	trustedTime := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	objectID, err := ControlOperationObjectID(&operation, spki, trustedTime, schemas)
	if err != nil || objectID == "" {
		t.Fatalf("object ID=%q err=%v", objectID, err)
	}

	operation.Body.Kind = "unknown_mutation"
	if err := VerifyControlOperation(&operation, spki, trustedTime, schemas); err == nil {
		t.Fatal("accepted an unknown operation kind")
	}
	operation.Body.Kind = "create_invite"
	operation.AuthorSignature.Signature = operation.AuthorSignature.Signature[:len(operation.AuthorSignature.Signature)-1] + "A"
	if err := VerifyControlOperation(&operation, spki, trustedTime, schemas); err == nil {
		t.Fatal("accepted a modified signature")
	}
}

func TestControlOperationExpiryAndRootConflict(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	spki, _ := x509.MarshalPKIXPublicKey(privateKey.Public())
	schemas := OperationSchemaRegistry{"create_invite": 2}
	operation, err := NewControlOperation(testOperationBody(), privateKey, schemas)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyControlOperation(&operation, spki, time.Date(2026, 9, 11, 13, 0, 0, 0, time.UTC), schemas); err == nil {
		t.Fatal("accepted operation at its exclusive expiry")
	}
	objectID := HashRaw("test-operation-v1", []byte("one"))
	root, err := ControlOperationRoot([]ControlOperationLeafV1{{Schema: 1, OperationID: "operation-1", ObjectID: objectID}})
	if err != nil || root == "" {
		t.Fatalf("root=%q err=%v", root, err)
	}
	_, err = ControlOperationRoot([]ControlOperationLeafV1{
		{Schema: 1, OperationID: "operation-1", ObjectID: objectID},
		{Schema: 1, OperationID: "operation-1", ObjectID: HashRaw("test-operation-v1", []byte("two"))},
	})
	if err == nil {
		t.Fatal("accepted two objects with the same operation ID")
	}
}

func TestControlOperationInclusionProofUsesCanonicalOperationOrder(t *testing.T) {
	leaves := []ControlOperationLeafV1{
		{Schema: 1, OperationID: "operation-z", ObjectID: HashRaw("test-operation-v1", []byte("z"))},
		{Schema: 1, OperationID: "operation-a", ObjectID: HashRaw("test-operation-v1", []byte("a"))},
		{Schema: 1, OperationID: "operation-m", ObjectID: HashRaw("test-operation-v1", []byte("m"))},
	}
	root, err := ControlOperationRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for _, operationID := range []string{"operation-a", "operation-m", "operation-z"} {
		leaf, index, size, path, err := ControlOperationInclusionProof(leaves, operationID)
		if err != nil {
			t.Fatal(err)
		}
		head := HeadEntryV2{Body: HeadEntryBodyV2{Payload: HeadEntryPayloadV2{OperationRoot: root}}}
		if err := VerifyControlOperationInclusion(&leaf, index, size, path, &head); err != nil {
			t.Fatalf("operation %s inclusion failed: %v", operationID, err)
		}
	}
	if _, _, _, _, err := ControlOperationInclusionProof(leaves, "missing"); err == nil {
		t.Fatal("returned a proof for a missing operation")
	}
}
