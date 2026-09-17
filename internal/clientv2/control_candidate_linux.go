//go:build linux

package clientv2

import (
	"crypto"
	"crypto/rand"
	"errors"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// CreateControlPeerIdentityEvidence 把候选 control peer 私钥仅封装给已入网
// Linux Device 的 exact wrapping key。availability receipt 使用同一 Device 的
// identity key 签名，但两者都不取得 membership authority。
func (state *EnrollmentIdentityV1) CreateControlPeerIdentityEvidence(store *enrollmentv2.SealedArtifactStore,
	clusterID, deviceID, proposalID, secretID, faultDomain string, privatePKCS8 []byte,
	peerSigner crypto.Signer, observedAt time.Time) (enrollmentv2.SealedMaterialEvidenceV1, error) {
	var empty enrollmentv2.SealedMaterialEvidenceV1
	if state == nil || store == nil || clusterID == "" || deviceID == "" || proposalID == "" ||
		secretID == "" || faultDomain == "" || len(privatePKCS8) == 0 || peerSigner == nil ||
		observedAt.IsZero() || observedAt != observedAt.UTC().Truncate(time.Second) {
		return empty, errors.New("[control candidate] peer artifact 输入无效")
	}
	identityKey, wrappingKey, err := state.keys()
	if err != nil {
		return empty, err
	}
	defer identityKey.D.SetInt64(0)
	defer wrappingKey.D.SetInt64(0)
	wrappingPublic, err := enrollmentv2.MaterialAuthorityKey(wrappingKey.Public())
	if err != nil {
		return empty, err
	}
	sealing := wire.P256RootOnlySealingPolicyV1()
	recipient := wire.SealedBlobRecipientKeyRefV1{RecipientID: deviceID, RecipientKeyGeneration: 1,
		RecipientKeyID: wrappingPublic.KeyID, RecipientKeyProfile: sealing.RecipientKeyProfile,
		RecipientPublicKey: wrappingPublic}
	sealingHash, err := wire.SealingPolicyHash(&sealing)
	if err != nil {
		return empty, err
	}
	recipientHash, err := wire.SealedSecretRecipientSetHash([]wire.SealedBlobRecipientKeyRefV1{recipient})
	if err != nil {
		return empty, err
	}
	owner := wire.SecretArtifactOwnerV1{Kind: "device",
		Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: deviceID}}
	context := wire.SealedSecretContextV1{Schema: 1, ClusterID: clusterID,
		ProposalID: proposalID, SecretID: secretID, Purpose: "control_peer_identity",
		Owner: owner, Generation: 1, SealingPolicyHash: sealingHash, RecipientSetHash: recipientHash}
	reporterPublic, err := enrollmentv2.MaterialAuthorityKey(identityKey.Public())
	if err != nil {
		return empty, err
	}
	policy := wire.ArtifactAvailabilityPolicyV1{Schema: 1, ClusterID: clusterID,
		PolicyID: "control-candidate-local-v1", Generation: 1, RequiredReceiptCount: 1,
		RequiredFaultDomainCount: 1, MaxReceiptAgeSeconds: 300,
		Reporters: []wire.ArtifactAvailabilityReporterRefV1{{ReporterID: deviceID,
			ReporterKey: reporterPublic, FaultDomain: faultDomain,
			AllowedPurposes: []string{"control_peer_identity"}}}}
	if err := wire.ValidateArtifactAvailabilityPolicy(&policy); err != nil {
		return empty, err
	}
	return enrollmentv2.CreateLocalSealedMaterial(store, context, sealing,
		[]wire.SealedBlobRecipientKeyRefV1{recipient}, privatePKCS8, peerSigner, policy,
		deviceID, identityKey, observedAt, rand.Reader)
}
