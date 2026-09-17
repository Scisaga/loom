//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/clientv2"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

func TestControlCandidateMaterialBindsDeviceKeysAndSealsPeerIdentity(t *testing.T) {
	input, store := controlCandidateTestInput(t)
	request, secrets, err := newControlCandidateMaterial(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateControlCandidateMaterial(&request, &secrets, input.Now); err != nil {
		t.Fatal(err)
	}
	publicKeys := []string{request.Member.MembershipPublicKey, request.Member.ConfigPublicKey,
		request.Member.EnrollmentPublicKey}
	if publicKeys[0] == publicKeys[1] || publicKeys[0] == publicKeys[2] || publicKeys[1] == publicKeys[2] {
		t.Fatal("candidate 复用了 control key purpose")
	}
	requestBytes, err := wire.MarshalCanonical(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{secrets.MembershipPrivateKey, secrets.ConfigPrivateKey,
		secrets.EnrollmentPrivateKey} {
		if bytes.Contains(requestBytes, []byte(private)) {
			t.Fatal("candidate request 泄露 control private key")
		}
	}
	if bytes.Contains(requestBytes, []byte("PRIVATE KEY")) {
		t.Fatal("candidate request 泄露 peer private key PEM")
	}
	envelope, err := store.Get(request.PeerIdentityEvidence.Ref.SealedBlob.CiphertextDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifySealedSecretBinding(&request.PeerIdentityEvidence.Ref, &envelope); err != nil {
		t.Fatal(err)
	}
}

func TestControlCandidateMaterialRejectsPrivateKeyAndArtifactTampering(t *testing.T) {
	input, _ := controlCandidateTestInput(t)
	request, secrets, err := newControlCandidateMaterial(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("control-private-key", func(t *testing.T) {
		tampered := secrets
		tampered.ConfigPrivateKey = secrets.MembershipPrivateKey
		if err := validateControlCandidateMaterial(&request, &tampered, input.Now); err == nil {
			t.Fatal("candidate 接受与 ControlMember 不匹配的私钥")
		}
	})
	t.Run("artifact-owner", func(t *testing.T) {
		tampered := cloneControlCandidateRequest(t, request)
		tampered.PeerIdentityEvidence.Ref.Owner.Device.DeviceID = "demo-other-device"
		if err := validateControlCandidateMaterial(&tampered, &secrets, input.Now); err == nil {
			t.Fatal("candidate 接受了改写 owner 的 peer artifact")
		}
	})
	t.Run("peer-certificate", func(t *testing.T) {
		tampered := cloneControlCandidateRequest(t, request)
		raw, decodeErr := base64.RawURLEncoding.DecodeString(tampered.Peer.PeerCertificateDER)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		raw[len(raw)-1] ^= 1
		tampered.Peer.PeerCertificateDER = base64.RawURLEncoding.EncodeToString(raw)
		if err := validateControlCandidateMaterial(&tampered, &secrets, input.Now); err == nil {
			t.Fatal("candidate 接受了未绑定 artifact 的 peer certificate")
		}
	})
}

func cloneControlCandidateRequest(t *testing.T, request controlCandidateRequestV1) controlCandidateRequestV1 {
	t.Helper()
	body, err := wire.MarshalCanonical(request)
	if err != nil {
		t.Fatal(err)
	}
	var cloned controlCandidateRequestV1
	if _, err := wire.DecodeStrict(body, 8<<20, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func controlCandidateTestInput(t *testing.T) (controlCandidateInput, *enrollmentv2.SealedArtifactStore) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := clientv2.OpenOrCreateEnrollmentIdentity(filepath.Join(root, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := enrollmentv2.OpenSealedArtifactStore(filepath.Join(root, "sealed-artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	identitySPKI, err := base64.RawURLEncoding.DecodeString(identity.IdentityPublicKeySPKI)
	if err != nil {
		t.Fatal(err)
	}
	identityHash, _ := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identitySPKI)
	wrappingSPKI, err := base64.RawURLEncoding.DecodeString(identity.WrappingPublicKeySPKI)
	if err != nil {
		t.Fatal(err)
	}
	wrappingHash, _ := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrappingSPKI)
	membership := wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", membership)
	responsibilitiesHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", grants)
	bundle := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: "demo-cluster",
		DeviceID: "demo-device", DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	bundleHash, err := wire.DeviceEndpointBundleHash(&bundle)
	if err != nil {
		t.Fatal(err)
	}
	secretRoot, _ := wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{})
	view := wire.DeviceViewPayloadV2{Schema: 2, ClusterID: "demo-cluster", DeviceID: "demo-device",
		DeviceGeneration: 1, State: "active", Active: &wire.DeviceActiveViewV1{
			IdentitySPKIHash: identityHash, Membership: membership, MembershipHash: membershipHash,
			Responsibilities: responsibilities, ResponsibilitiesHash: responsibilitiesHash,
			Grants: grants, GrantsHash: grantsHash, EndpointBundle: bundle, EndpointBundleHash: bundleHash,
			ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{}, SecretArtifactRefsRoot: secretRoot}}
	testHash := func(value string) string {
		return wire.HashRaw("loom-control-candidate-test-v1", []byte(value))
	}
	return controlCandidateInput{ClusterID: "demo-cluster", ObservedHeadHash: testHash("head"),
		ObservedControlEpoch: 1, ObservedControlSetHash: testHash("set"), DeviceID: "demo-device",
		DeviceCertificateHash: testHash("certificate"), DeviceIdentitySPKIHash: identityHash,
		DeviceWrappingKeyHash: wrappingHash, DeviceView: view,
		MemberID: "00000000000000000000000000", OverlayIP: "10.40.0.8", RaftPort: 17445,
		FaultDomain: "demo-zone-a", Now: time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC),
		Identity: identity, ArtifactStore: store}, store
}
