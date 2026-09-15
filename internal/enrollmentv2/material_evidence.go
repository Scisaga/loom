package enrollmentv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"loom/internal/wire"
)

// SealedMaterialEvidenceV1 保存 verifier 实际需要的 preimages；不能仅提交
// 自选的 availability/PoP hash。秘密本身只进入独立的 sealed artifact store。
type SealedMaterialEvidenceV1 struct {
	Ref      wire.SecretArtifactRefV2             `json:"ref"`
	Proof    *wire.SecretPossessionProofV1        `json:"proof,omitempty"`
	Policy   wire.ArtifactAvailabilityPolicyV1    `json:"policy"`
	Receipts []wire.ArtifactAvailabilityReceiptV1 `json:"receipts"`
}

// CreateLocalSealedMaterial 面向单副本软件 executor：它只能满足 policy 中
// 明确要求一份本机回执的门槛，不能代签其他副本或声称多个故障域可用。
// 调用方通过 first-result journal 固定结果，重复 proposal 不得重新调用生成器。
func CreateLocalSealedMaterial(store *SealedArtifactStore, context wire.SealedSecretContextV1,
	sealing wire.SealingPolicyV1, recipients []wire.SealedBlobRecipientKeyRefV1, plaintext []byte,
	secretSigner crypto.Signer, policy wire.ArtifactAvailabilityPolicyV1, reporterID string,
	reporterSigner crypto.Signer, observedAt time.Time, entropy io.Reader) (SealedMaterialEvidenceV1, error) {
	var result SealedMaterialEvidenceV1
	policyHash, err := wire.ArtifactAvailabilityPolicyHash(&policy)
	if err != nil || policy.ClusterID != context.ClusterID || policy.RequiredReceiptCount != 1 ||
		policy.RequiredFaultDomainCount != 1 || observedAt.IsZero() || observedAt != observedAt.UTC().Truncate(time.Second) {
		return result, errors.New("[secret artifact] 本机回执不满足当前 availability policy")
	}
	var reporter *wire.ArtifactAvailabilityReporterRefV1
	for i := range policy.Reporters {
		if policy.Reporters[i].ReporterID == reporterID {
			reporter = &policy.Reporters[i]
		}
	}
	if reporter == nil || reporterSigner == nil || len(recipients) == 0 {
		return result, errors.New("[secret artifact] 本机 reporter 或 recipient 未获授权")
	}
	key, err := MaterialAuthorityKey(reporterSigner.Public())
	if err != nil || !wire.EqualCanonical(key, reporter.ReporterKey) {
		return result, errors.New("[secret artifact] reporter signer 与认证公钥不匹配")
	}
	allowed := false
	for _, purpose := range reporter.AllowedPurposes {
		allowed = allowed || purpose == context.Purpose
	}
	if !allowed {
		return result, errors.New("[secret artifact] reporter 未获本用途授权")
	}
	// 私钥型 secret 的 PoP 必须证明被封装的同一把 key，不能只证明另一个 signer。
	var public *wire.AuthorityProofKeyV1
	if secretSigner != nil {
		parsed, err := x509.ParsePKCS8PrivateKey(plaintext)
		storedSigner, ok := parsed.(crypto.Signer)
		if err != nil || !ok {
			return result, errors.New("[secret artifact] 私钥材料必须是规范 PKCS#8")
		}
		canonical, err := x509.MarshalPKCS8PrivateKey(parsed)
		if err != nil || !bytes.Equal(canonical, plaintext) {
			clear(canonical)
			return result, errors.New("[secret artifact] 私钥材料不是 exact PKCS#8")
		}
		clear(canonical)
		key, err := MaterialAuthorityKey(secretSigner.Public())
		storedKey, storedErr := MaterialAuthorityKey(storedSigner.Public())
		if err != nil || storedErr != nil || !wire.EqualCanonical(key, storedKey) {
			return result, errors.New("[secret artifact] PoP signer 与封装私钥不同")
		}
		public = &key
	}
	envelope, err := wire.SealSecret(entropy, context, &sealing, recipients, plaintext)
	if err != nil {
		return result, err
	}
	digest, err := wire.SealedSecretEnvelopeHash(&envelope)
	if err != nil {
		return result, err
	}
	ref := wire.SecretArtifactRefV2{Schema: 2, ClusterID: context.ClusterID, ProposalID: context.ProposalID,
		SecretID: context.SecretID, Purpose: context.Purpose, Owner: context.Owner, Generation: context.Generation,
		PublicKey: public, ImmutableRef: "sealed:" + digest, BackendKind: "sealed_blob",
		SealedBlob: &wire.SealedBlobRefV1{CiphertextDigest: digest, SealingPolicy: sealing,
			SealingPolicyHash: context.SealingPolicyHash, RecipientKeyVersions: recipients}, AvailabilityPolicyHash: policyHash}
	if secretSigner != nil {
		proof := &wire.SecretPossessionProofV1{Body: wire.SecretPossessionProofBodyV1{Schema: 1,
			ClusterID: context.ClusterID, ProposalID: context.ProposalID, SecretID: context.SecretID,
			Generation: context.Generation, Purpose: context.Purpose, Owner: context.Owner,
			ImmutableRef: ref.ImmutableRef, PublicKey: *public}}
		proof.ProofSignature, err = signMaterialProof(secretSigner, wire.DomainSecretPossessionProofSignature, proof.Body)
		if err != nil {
			return result, err
		}
		hash, err := wire.SecretPossessionProofHash(proof)
		if err != nil {
			return result, err
		}
		ref.PossessionProofHash, result.Proof = &hash, proof
	}
	if err := store.PutEnvelope(&envelope); err != nil {
		return result, err
	}
	readback, err := store.Get(digest)
	if err != nil || !wire.EqualCanonical(readback, envelope) {
		return result, errors.New("[secret artifact] 耐久存储回读与本次密文不一致")
	}
	receipt := wire.ArtifactAvailabilityReceiptV1{Body: wire.ArtifactAvailabilityReceiptBodyV1{
		Schema: 1, ClusterID: context.ClusterID, ProposalID: context.ProposalID, SecretID: context.SecretID,
		Generation: context.Generation, Purpose: context.Purpose, ImmutableRef: ref.ImmutableRef,
		ArtifactOrVersionDigest: digest, ReporterID: reporterID, RecipientKeyRef: &recipients[0],
		ObservedAt: observedAt.Format(time.RFC3339)}}
	receipt.ReporterSignature, err = signMaterialProof(reporterSigner, wire.DomainArtifactAvailabilityReceiptSign, receipt.Body)
	if err != nil {
		return result, err
	}
	receiptHash, err := wire.ArtifactAvailabilityReceiptHash(&receipt)
	if err != nil {
		return result, err
	}
	leaf, err := wire.MarshalCanonical(wire.ArtifactAvailabilityReceiptLeafV1{Schema: 1, ReporterID: reporterID, ReceiptHash: receiptHash})
	if err != nil {
		return result, err
	}
	ref.AvailabilityReceiptsRoot = fmt.Sprintf("sha256:%x", wire.MerkleRoot([][]byte{leaf}))
	result.Ref, result.Policy, result.Receipts = ref, policy, []wire.ArtifactAvailabilityReceiptV1{receipt}
	if err := wire.VerifySecretArtifactEvidence(&result.Ref, result.Proof, &result.Policy, result.Receipts, observedAt, 0, digest); err != nil {
		return SealedMaterialEvidenceV1{}, err
	}
	if err := store.Put(&result.Ref, &readback); err != nil {
		return SealedMaterialEvidenceV1{}, err
	}
	return result, nil
}

func MaterialAuthorityKey(public crypto.PublicKey) (wire.AuthorityProofKeyV1, error) {
	var key wire.AuthorityProofKeyV1
	switch public.(type) {
	case ed25519.PublicKey:
		key.Algorithm = "ed25519"
	case *ecdsa.PublicKey:
		key.Algorithm = "ecdsa-p256-sha256"
	case *rsa.PublicKey:
		key.Algorithm = "rsa2048-pkcs1v15-sha256"
	default:
		return key, errors.New("[secret artifact] 不支持的 signer key profile")
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return key, err
	}
	key.PublicKeySPKIDER = base64.RawURLEncoding.EncodeToString(spki)
	key.KeyID, err = wire.AuthorityProofKeyID(spki)
	if err != nil {
		return key, err
	}
	_, err = wire.ParseAuthorityProofKey(&key)
	return key, err
}

func signMaterialProof(signer crypto.Signer, domain string, value any) (wire.AuthorityProofSignatureV1, error) {
	var signature wire.AuthorityProofSignatureV1
	key, err := MaterialAuthorityKey(signer.Public())
	if err != nil {
		return signature, err
	}
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return signature, err
	}
	message, err := wire.Frame(domain, body)
	if err != nil {
		return signature, err
	}
	toSign, hash := message, crypto.Hash(0)
	if key.Algorithm != "ed25519" {
		digest := sha256.Sum256(message)
		toSign, hash = digest[:], crypto.SHA256
	}
	signed, err := signer.Sign(rand.Reader, toSign, hash)
	if err != nil {
		return signature, err
	}
	if public, ok := signer.Public().(*ecdsa.PublicKey); ok {
		var pair struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signed, &pair)
		if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil || pair.R.Sign() <= 0 ||
			pair.S.Sign() <= 0 || pair.R.Cmp(public.Params().N) >= 0 || pair.S.Cmp(public.Params().N) >= 0 {
			return signature, errors.New("[secret artifact] signer 返回非法 ECDSA signature")
		}
		if pair.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(public.Params().N), 1)) > 0 {
			pair.S.Sub(public.Params().N, pair.S)
		}
		signed = make([]byte, 64)
		pair.R.FillBytes(signed[:32])
		pair.S.FillBytes(signed[32:])
	}
	signature = wire.AuthorityProofSignatureV1{Algorithm: key.Algorithm, KeyID: key.KeyID,
		Signature: base64.RawURLEncoding.EncodeToString(signed)}
	if err := wire.VerifyAuthorityProofSignature(&key, &signature, message); err != nil {
		return wire.AuthorityProofSignatureV1{}, err
	}
	return signature, nil
}
