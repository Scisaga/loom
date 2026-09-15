package wire

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
)

type RecipientWrapContextV1 struct {
	Schema                  int                         `json:"schema"`
	SealedSecretContextHash string                      `json:"sealed_secret_context_hash"`
	RecipientKey            SealedBlobRecipientKeyRefV1 `json:"recipient_key"`
	EphemeralSPKIHash       string                      `json:"ephemeral_spki_hash"`
}

type P256UnsealInputsV1 struct {
	Schema           int                         `json:"schema"`
	Context          SealedSecretContextV1       `json:"context"`
	RecipientKey     SealedBlobRecipientKeyRefV1 `json:"recipient_key"`
	EphemeralSPKIDER string                      `json:"ephemeral_spki_der"`
	WrapNonce        string                      `json:"wrap_nonce"`
	WrappedCEKAndTag string                      `json:"wrapped_cek_and_tag"`
	WrapContext      RecipientWrapContextV1      `json:"wrap_context"`
	WrapAAD          string                      `json:"wrap_aad"`
	ContentNonce     string                      `json:"content_nonce"`
	CiphertextAndTag string                      `json:"ciphertext_and_tag"`
	PayloadAAD       string                      `json:"payload_aad"`
}

type RSAUnsealInputsV1 struct {
	Schema           int                   `json:"schema"`
	Context          SealedSecretContextV1 `json:"context"`
	WrappedCEK       string                `json:"wrapped_cek"`
	ContentNonce     string                `json:"content_nonce"`
	CiphertextAndTag string                `json:"ciphertext_and_tag"`
	PayloadAAD       string                `json:"payload_aad"`
}

func P256SealingPolicyV1() SealingPolicyV1 {
	return SealingPolicyV1{
		Schema: 1, PolicyID: "sealed-p256-v1", Generation: 1,
		RecipientKeyProfile: "p256-keystore-ecdh-v1",
		PlaintextFormat:     "jcs-sealed-secret-plaintext-v1", ContentAEAD: "aes-256-gcm",
		CEKBytes: 32, ContentNonceBytes: 12, TagBytes: 16, KeyWrapKind: "p256_ecdh",
		P256ECDH: &P256ECDHSealingPolicyV1{
			Curve: "p256", SharedSecret: "x-coordinate-be32", KDF: "hkdf-sha256",
			SaltProfile: "context-sha256-v1", InfoProfile: "recipient-context-frame-v1",
			WrapAEAD: "aes-256-gcm", WrapNonceBytes: 12,
		},
	}
}

// P256RootOnlySealingPolicyV1 使用本地受保护软件 wrapping key；独立的
// profile/hash 明确其保管方式，不将 PKCS#8 文件声称为不可导出 Keystore key。
func P256RootOnlySealingPolicyV1() SealingPolicyV1 {
	policy := P256SealingPolicyV1()
	policy.PolicyID = "sealed-p256-root-only-v1"
	policy.RecipientKeyProfile = "p256-root-only-pkcs8-ecdh-v1"
	return policy
}

func RSASealingPolicyV1() SealingPolicyV1 {
	return SealingPolicyV1{
		Schema: 1, PolicyID: "sealed-rsa2048-v1", Generation: 1,
		RecipientKeyProfile: "rsa2048-keystore-decrypt-v1",
		PlaintextFormat:     "jcs-sealed-secret-plaintext-v1", ContentAEAD: "aes-256-gcm",
		CEKBytes: 32, ContentNonceBytes: 12, TagBytes: 16, KeyWrapKind: "rsa_oaep",
		RSAOAEP: &RSAOAEPSealingPolicyV1{
			ModulusBits: 2048, PublicExponent: 65537, Digest: "sha256", MGF1Digest: "sha1", Label: "empty",
		},
	}
}

// NewSealedSecretContext 只从 proposal 固定坐标、policy 与 recipient set 构造
// context；随机数和当前时间都不参与权威 identity（D124）。
func NewSealedSecretContext(clusterID, proposalID, secretID, purpose string, owner SecretArtifactOwnerV1, generation int64, policy *SealingPolicyV1, recipients []SealedBlobRecipientKeyRefV1) (SealedSecretContextV1, error) {
	policyHash, err := SealingPolicyHash(policy)
	if err != nil {
		return SealedSecretContextV1{}, err
	}
	for i := range recipients {
		if err := validateRecipientKeyRef(&recipients[i], policy.RecipientKeyProfile); err != nil {
			return SealedSecretContextV1{}, err
		}
	}
	recipientSetHash, err := SealedSecretRecipientSetHash(recipients)
	if err != nil {
		return SealedSecretContextV1{}, err
	}
	context := SealedSecretContextV1{
		Schema: 1, ClusterID: clusterID, ProposalID: proposalID, SecretID: secretID,
		Purpose: purpose, Owner: owner, Generation: generation,
		SealingPolicyHash: policyHash, RecipientSetHash: recipientSetHash,
	}
	if err := validateSealedContext(&context); err != nil {
		return SealedSecretContextV1{}, err
	}
	return context, nil
}

// SealSecret 的 entropy 由调用方显式注入；proposal 重试必须复用首次生成的
// envelope，而不是再次调用本函数（D124）。
func SealSecret(entropy io.Reader, context SealedSecretContextV1, policy *SealingPolicyV1, recipients []SealedBlobRecipientKeyRefV1, secret []byte) (SealedSecretEnvelopeV1, error) {
	if entropy == nil || len(secret) == 0 {
		return SealedSecretEnvelopeV1{}, errors.New("[D124 sealed secret] entropy/secret 缺失")
	}
	expected, err := NewSealedSecretContext(context.ClusterID, context.ProposalID, context.SecretID, context.Purpose, context.Owner, context.Generation, policy, recipients)
	if err != nil || !sameSealedContext(context, expected) {
		return SealedSecretEnvelopeV1{}, errors.New("[D124 sealed secret] context 与 policy/recipient set 不匹配")
	}
	cek := make([]byte, 32)
	contentNonce := make([]byte, 12)
	if _, err := io.ReadFull(entropy, cek); err != nil {
		return SealedSecretEnvelopeV1{}, errors.New("[D124 sealed secret] 生成 CEK 失败")
	}
	if _, err := io.ReadFull(entropy, contentNonce); err != nil {
		return SealedSecretEnvelopeV1{}, errors.New("[D124 sealed secret] 生成 content nonce 失败")
	}
	plaintext, err := MarshalCanonical(SealedSecretPlaintextV1{
		Schema: 1, Context: context, SecretBytes: base64.RawURLEncoding.EncodeToString(secret),
	})
	if err != nil {
		return SealedSecretEnvelopeV1{}, err
	}
	contextCanonical, _ := MarshalCanonical(context)
	payloadAAD, _ := Frame(DomainSealedSecretPayloadAAD, contextCanonical)
	ciphertext, err := sealAESGCM(cek, contentNonce, plaintext, payloadAAD)
	if err != nil {
		return SealedSecretEnvelopeV1{}, err
	}
	envelope := SealedSecretEnvelopeV1{
		Schema: 1, Context: context,
		ContentNonce:       base64.RawURLEncoding.EncodeToString(contentNonce),
		CiphertextAndTag:   base64.RawURLEncoding.EncodeToString(ciphertext),
		RecipientEnvelopes: make([]SealedSecretRecipientEnvelopeV1, len(recipients)),
	}
	contextHash, _ := SealedSecretContextHash(&context)
	for i := range recipients {
		entry := SealedSecretRecipientEnvelopeV1{RecipientKey: recipients[i], KeyWrapKind: policy.KeyWrapKind}
		public, _ := ParseAuthorityProofKey(&recipients[i].RecipientPublicKey)
		switch policy.KeyWrapKind {
		case "p256_ecdh":
			wrapped, err := sealCEKForP256(entropy, contextHash, recipients[i], public.(*ecdsa.PublicKey), cek)
			if err != nil {
				return SealedSecretEnvelopeV1{}, err
			}
			entry.P256ECDH = &wrapped
		case "rsa_oaep":
			wrapped, err := encryptOAEPWithMGF1SHA1(entropy, public.(*rsa.PublicKey), cek)
			if err != nil {
				return SealedSecretEnvelopeV1{}, err
			}
			entry.RSAOAEP = &SealedSecretRSARecipientEnvelopeV1{WrappedCEK: base64.RawURLEncoding.EncodeToString(wrapped)}
		default:
			return SealedSecretEnvelopeV1{}, errors.New("[D124 sealed secret] 未知 key wrap kind")
		}
		envelope.RecipientEnvelopes[i] = entry
	}
	if err := ValidateSealedSecretEnvelope(&envelope); err != nil {
		return SealedSecretEnvelopeV1{}, err
	}
	return envelope, nil
}

func sameSealedContext(left, right SealedSecretContextV1) bool {
	leftBytes, leftErr := MarshalCanonical(left)
	rightBytes, rightErr := MarshalCanonical(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func sealCEKForP256(entropy io.Reader, contextHash string, recipient SealedBlobRecipientKeyRefV1, public *ecdsa.PublicKey, cek []byte) (SealedSecretP256RecipientEnvelopeV1, error) {
	recipientECDH, err := public.ECDH()
	if err != nil {
		return SealedSecretP256RecipientEnvelopeV1{}, errors.New("[D124 sealed secret] recipient P-256 key 无效")
	}
	ephemeral, err := ecdh.P256().GenerateKey(entropy)
	if err != nil {
		return SealedSecretP256RecipientEnvelopeV1{}, errors.New("[D124 sealed secret] 生成 ephemeral P-256 key 失败")
	}
	ephemeralDER, err := x509.MarshalPKIXPublicKey(ephemeral.PublicKey())
	if err != nil {
		return SealedSecretP256RecipientEnvelopeV1{}, err
	}
	ephemeralHash, _ := HashBytes(DomainSealedSecretEphemeralSPKI, ephemeralDER)
	wrapContext := RecipientWrapContextV1{
		Schema: 1, SealedSecretContextHash: contextHash, RecipientKey: recipient, EphemeralSPKIHash: ephemeralHash,
	}
	kek, err := deriveRecipientKEK(ephemeral, recipientECDH, wrapContext)
	if err != nil {
		return SealedSecretP256RecipientEnvelopeV1{}, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		return SealedSecretP256RecipientEnvelopeV1{}, errors.New("[D124 sealed secret] 生成 wrap nonce 失败")
	}
	wrapCanonical, _ := MarshalCanonical(wrapContext)
	aad, _ := Frame(DomainSealedSecretWrapAAD, wrapCanonical)
	wrapped, err := sealAESGCM(kek, nonce, cek, aad)
	if err != nil {
		return SealedSecretP256RecipientEnvelopeV1{}, err
	}
	return SealedSecretP256RecipientEnvelopeV1{
		EphemeralSPKIDER: base64.RawURLEncoding.EncodeToString(ephemeralDER), EphemeralSPKIHash: ephemeralHash,
		WrapNonce: base64.RawURLEncoding.EncodeToString(nonce), WrappedCEKAndTag: base64.RawURLEncoding.EncodeToString(wrapped),
	}, nil
}

func deriveRecipientKEK(private *ecdh.PrivateKey, public *ecdh.PublicKey, context RecipientWrapContextV1) ([]byte, error) {
	shared, err := private.ECDH(public)
	if err != nil || len(shared) != 32 {
		return nil, errors.New("[D124 sealed secret] P-256 ECDH shared secret 无效")
	}
	return DeriveSealedSecretP256KEK(shared, context)
}

// DeriveSealedSecretP256KEK 接收 profile 对应的软件或 Keystore ECDH 返回的
// x-coordinate；此函数不接收私钥，HKDF 由共享 wire 实现（D124）。
func DeriveSealedSecretP256KEK(shared []byte, context RecipientWrapContextV1) ([]byte, error) {
	if len(shared) != 32 || context.Schema != 1 {
		return nil, errors.New("[D124 sealed secret] P-256 shared secret/wrap context 无效")
	}
	if _, err := ParseHash(context.SealedSecretContextHash); err != nil {
		return nil, err
	}
	if !isP256SealingProfile(context.RecipientKey.RecipientKeyProfile) {
		return nil, errors.New("[D124 sealed secret] P-256 wrapping profile 无效")
	}
	if err := validateRecipientKeyRef(&context.RecipientKey, context.RecipientKey.RecipientKeyProfile); err != nil {
		return nil, err
	}
	if _, err := ParseHash(context.EphemeralSPKIHash); err != nil {
		return nil, err
	}
	canonical, err := MarshalCanonical(context)
	if err != nil {
		return nil, err
	}
	saltFrame, _ := Frame(DomainSealedSecretHKDFSalt, canonical)
	salt := sha256.Sum256(saltFrame)
	info, _ := Frame(DomainSealedSecretKEKInfo, canonical)
	return hkdf.Key(sha256.New, shared, salt[:], string(info), 32)
}

func deriveRecipientKEKForUnseal(private *ecdsa.PrivateKey, public *ecdh.PublicKey, context RecipientWrapContextV1) ([]byte, error) {
	privateECDH, err := private.ECDH()
	if err != nil {
		return nil, errors.New("[D124 sealed secret] local P-256 private key 无效")
	}
	return deriveRecipientKEK(privateECDH, public, context)
}

func sealAESGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("[D124 sealed secret] AES-256 key 无效")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, errors.New("[D124 sealed secret] AES-GCM nonce 无效")
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func openAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("[D124 sealed secret] AES-256 key 无效")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() || len(ciphertext) < gcm.Overhead() {
		return nil, errors.New("[D124 sealed secret] AES-GCM 输入无效")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("[D124 sealed secret] AES-GCM authentication 失败")
	}
	return plaintext, nil
}

// UnsealSecretP256 在解密前验证 envelope/context/recipient 的 exact binding，
// 并在解密后再次核对 plaintext 内嵌 context（D124）。
func UnsealSecretP256(envelope *SealedSecretEnvelopeV1, recipient SealedBlobRecipientKeyRefV1, private *ecdsa.PrivateKey) ([]byte, error) {
	if err := ValidateSealedSecretEnvelope(envelope); err != nil {
		return nil, err
	}
	if private == nil || !isP256SealingProfile(recipient.RecipientKeyProfile) {
		return nil, errors.New("[D124 sealed secret] local P-256 recipient key 缺失")
	}
	entry := findRecipientEnvelope(envelope.RecipientEnvelopes, recipient)
	if entry == nil || entry.P256ECDH == nil || entry.KeyWrapKind != "p256_ecdh" {
		return nil, errors.New("[D124 sealed secret] recipient envelope 不存在/类型不匹配")
	}
	localDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil || base64.RawURLEncoding.EncodeToString(localDER) != recipient.RecipientPublicKey.PublicKeySPKIDER {
		return nil, errors.New("[D124 sealed secret] local private key 与 recipient SPKI 不匹配")
	}
	ephemeralDER, _ := decodeCanonicalBase64URL(entry.P256ECDH.EphemeralSPKIDER)
	ephemeralAny, _ := x509.ParsePKIXPublicKey(ephemeralDER)
	ephemeralECDSA := ephemeralAny.(*ecdsa.PublicKey)
	ephemeralECDH, err := ephemeralECDSA.ECDH()
	if err != nil {
		return nil, errors.New("[D124 sealed secret] ephemeral ECDH key 无效")
	}
	contextHash, _ := SealedSecretContextHash(&envelope.Context)
	wrapContext := RecipientWrapContextV1{
		Schema: 1, SealedSecretContextHash: contextHash, RecipientKey: recipient,
		EphemeralSPKIHash: entry.P256ECDH.EphemeralSPKIHash,
	}
	kek, err := deriveRecipientKEKForUnseal(private, ephemeralECDH, wrapContext)
	if err != nil {
		return nil, err
	}
	wrapNonce, _ := decodeRawURL(entry.P256ECDH.WrapNonce, 12)
	wrapped, _ := decodeRawURL(entry.P256ECDH.WrappedCEKAndTag, 48)
	wrapCanonical, _ := MarshalCanonical(wrapContext)
	wrapAAD, _ := Frame(DomainSealedSecretWrapAAD, wrapCanonical)
	cek, err := openAESGCM(kek, wrapNonce, wrapped, wrapAAD)
	if err != nil || len(cek) != 32 {
		return nil, errors.New("[D124 sealed secret] wrapped CEK authentication 失败")
	}
	contentNonce, _ := decodeRawURL(envelope.ContentNonce, 12)
	ciphertext, _ := decodeCanonicalBase64URL(envelope.CiphertextAndTag)
	contextCanonical, _ := MarshalCanonical(envelope.Context)
	payloadAAD, _ := Frame(DomainSealedSecretPayloadAAD, contextCanonical)
	plaintextBytes, err := openAESGCM(cek, contentNonce, ciphertext, payloadAAD)
	if err != nil {
		return nil, err
	}
	var plaintext SealedSecretPlaintextV1
	canonical, err := DecodeStrict(plaintextBytes, 32<<20, &plaintext)
	if err != nil || !bytes.Equal(canonical, plaintextBytes) || plaintext.Schema != 1 || !sameSealedContext(plaintext.Context, envelope.Context) {
		return nil, errors.New("[D124 sealed secret] plaintext context/canonical wire 无效")
	}
	secret, err := decodeCanonicalBase64URL(plaintext.SecretBytes)
	if err != nil {
		return nil, errors.New("[D124 sealed secret] plaintext secret encoding 无效")
	}
	return secret, nil
}

// PrepareP256UnsealInputs 对私有 envelope 做全部公开材料校验，再把唯一需要
// Keystore 私钥的 ECDH 步骤所需输入投影给 Android/Linux host（D124）。
func PrepareP256UnsealInputs(envelope *SealedSecretEnvelopeV1, recipientID string, recipientGeneration int64, recipientSPKIDER []byte) (P256UnsealInputsV1, error) {
	if err := ValidateSealedSecretEnvelope(envelope); err != nil {
		return P256UnsealInputsV1{}, err
	}
	if !validIdentifier(recipientID, 128) || recipientGeneration < 1 || len(recipientSPKIDER) == 0 {
		return P256UnsealInputsV1{}, errors.New("[D124 sealed secret] expected recipient identity 无效")
	}
	encodedSPKI := base64.RawURLEncoding.EncodeToString(recipientSPKIDER)
	var entry *SealedSecretRecipientEnvelopeV1
	for i := range envelope.RecipientEnvelopes {
		candidate := &envelope.RecipientEnvelopes[i]
		if candidate.RecipientKey.RecipientID == recipientID && candidate.RecipientKey.RecipientKeyGeneration == recipientGeneration {
			if entry != nil {
				return P256UnsealInputsV1{}, errors.New("[D124 sealed secret] recipient identity 命中多个 key version")
			}
			entry = candidate
		}
	}
	if entry == nil || entry.KeyWrapKind != "p256_ecdh" || entry.P256ECDH == nil ||
		entry.RecipientKey.RecipientPublicKey.PublicKeySPKIDER != encodedSPKI {
		return P256UnsealInputsV1{}, errors.New("[D124 sealed secret] envelope 不含本机 exact P-256 wrapping key")
	}
	contextHash, _ := SealedSecretContextHash(&envelope.Context)
	wrapContext := RecipientWrapContextV1{
		Schema: 1, SealedSecretContextHash: contextHash, RecipientKey: entry.RecipientKey,
		EphemeralSPKIHash: entry.P256ECDH.EphemeralSPKIHash,
	}
	wrapCanonical, _ := MarshalCanonical(wrapContext)
	wrapAAD, _ := Frame(DomainSealedSecretWrapAAD, wrapCanonical)
	contextCanonical, _ := MarshalCanonical(envelope.Context)
	payloadAAD, _ := Frame(DomainSealedSecretPayloadAAD, contextCanonical)
	return P256UnsealInputsV1{
		Schema: 1, Context: envelope.Context, RecipientKey: entry.RecipientKey,
		EphemeralSPKIDER: entry.P256ECDH.EphemeralSPKIDER, WrapNonce: entry.P256ECDH.WrapNonce,
		WrappedCEKAndTag: entry.P256ECDH.WrappedCEKAndTag, WrapContext: wrapContext,
		WrapAAD: base64.RawURLEncoding.EncodeToString(wrapAAD), ContentNonce: envelope.ContentNonce,
		CiphertextAndTag: envelope.CiphertextAndTag, PayloadAAD: base64.RawURLEncoding.EncodeToString(payloadAAD),
	}, nil
}

// PrepareRSAUnsealInputs 只投影 Android API 26–30 exact OAEP 所需字段；CEK
// 解密仍在仅有 PURPOSE_DECRYPT 的 Keystore alias 内完成（D124）。
func PrepareRSAUnsealInputs(envelope *SealedSecretEnvelopeV1, recipientID string, recipientGeneration int64, recipientSPKIDER []byte) (RSAUnsealInputsV1, error) {
	if err := ValidateSealedSecretEnvelope(envelope); err != nil {
		return RSAUnsealInputsV1{}, err
	}
	if !validIdentifier(recipientID, 128) || recipientGeneration < 1 || len(recipientSPKIDER) == 0 {
		return RSAUnsealInputsV1{}, errors.New("[D124 sealed secret] expected recipient identity 无效")
	}
	encodedSPKI := base64.RawURLEncoding.EncodeToString(recipientSPKIDER)
	var entry *SealedSecretRecipientEnvelopeV1
	for i := range envelope.RecipientEnvelopes {
		candidate := &envelope.RecipientEnvelopes[i]
		if candidate.RecipientKey.RecipientID == recipientID && candidate.RecipientKey.RecipientKeyGeneration == recipientGeneration {
			if entry != nil {
				return RSAUnsealInputsV1{}, errors.New("[D124 sealed secret] recipient identity 命中多个 key version")
			}
			entry = candidate
		}
	}
	if entry == nil || entry.KeyWrapKind != "rsa_oaep" || entry.RSAOAEP == nil ||
		entry.RecipientKey.RecipientPublicKey.PublicKeySPKIDER != encodedSPKI {
		return RSAUnsealInputsV1{}, errors.New("[D124 sealed secret] envelope 不含本机 exact RSA wrapping key")
	}
	contextCanonical, _ := MarshalCanonical(envelope.Context)
	payloadAAD, _ := Frame(DomainSealedSecretPayloadAAD, contextCanonical)
	return RSAUnsealInputsV1{
		Schema: 1, Context: envelope.Context, WrappedCEK: entry.RSAOAEP.WrappedCEK,
		ContentNonce: envelope.ContentNonce, CiphertextAndTag: envelope.CiphertextAndTag,
		PayloadAAD: base64.RawURLEncoding.EncodeToString(payloadAAD),
	}, nil
}

// FinishSealedSecretPlaintext 在 host 解开 AES-GCM 后重新检查 exact JCS 与内嵌
// context，防止只认证 ciphertext 却忽略 authority 坐标（D124）。
func FinishSealedSecretPlaintext(plaintextBytes []byte, expectedContext SealedSecretContextV1) ([]byte, error) {
	if err := validateSealedContext(&expectedContext); err != nil {
		return nil, err
	}
	var plaintext SealedSecretPlaintextV1
	canonical, err := DecodeStrict(plaintextBytes, 32<<20, &plaintext)
	if err != nil || !bytes.Equal(canonical, plaintextBytes) || plaintext.Schema != 1 || !sameSealedContext(plaintext.Context, expectedContext) {
		return nil, errors.New("[D124 sealed secret] plaintext context/canonical wire 无效")
	}
	secret, err := decodeCanonicalBase64URL(plaintext.SecretBytes)
	if err != nil {
		return nil, errors.New("[D124 sealed secret] plaintext secret encoding 无效")
	}
	return secret, nil
}

func findRecipientEnvelope(entries []SealedSecretRecipientEnvelopeV1, recipient SealedBlobRecipientKeyRefV1) *SealedSecretRecipientEnvelopeV1 {
	for i := range entries {
		if entries[i].RecipientKey == recipient {
			return &entries[i]
		}
	}
	return nil
}

// encryptOAEPWithMGF1SHA1 实现 Android Keystore profile 固定的
// SHA-256 OAEP + MGF1-SHA-1；crypto/rsa 的高层 API 只支持二者同 hash。
func encryptOAEPWithMGF1SHA1(entropy io.Reader, public *rsa.PublicKey, message []byte) ([]byte, error) {
	if public == nil || public.N.BitLen() != 2048 || public.E != 65537 {
		return nil, errors.New("[D124 sealed secret] RSA-OAEP public key profile 无效")
	}
	k, hLen := public.Size(), sha256.Size
	if len(message) > k-2*hLen-2 {
		return nil, errors.New("[D124 sealed secret] RSA-OAEP plaintext 过长")
	}
	lHash := sha256.Sum256(nil)
	db := make([]byte, k-hLen-1)
	copy(db, lHash[:])
	db[len(db)-len(message)-1] = 1
	copy(db[len(db)-len(message):], message)
	seed := make([]byte, hLen)
	if _, err := io.ReadFull(entropy, seed); err != nil {
		return nil, errors.New("[D124 sealed secret] 生成 RSA-OAEP seed 失败")
	}
	dbMask := mgf1SHA1(seed, len(db))
	for i := range db {
		db[i] ^= dbMask[i]
	}
	seedMask := mgf1SHA1(db, hLen)
	for i := range seed {
		seed[i] ^= seedMask[i]
	}
	encoded := make([]byte, k)
	copy(encoded[1:1+hLen], seed)
	copy(encoded[1+hLen:], db)
	value := new(big.Int).SetBytes(encoded)
	if value.Cmp(public.N) >= 0 {
		return nil, errors.New("[D124 sealed secret] RSA-OAEP encoded message 越界")
	}
	value.Exp(value, big.NewInt(int64(public.E)), public.N)
	return value.FillBytes(make([]byte, k)), nil
}

func mgf1SHA1(seed []byte, length int) []byte {
	result := make([]byte, 0, length)
	var counter [4]byte
	for i := uint32(0); len(result) < length; i++ {
		counter[0], counter[1], counter[2], counter[3] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		digest := sha1.New()
		digest.Write(seed)
		digest.Write(counter[:])
		result = append(result, digest.Sum(nil)...)
	}
	return result[:length]
}
