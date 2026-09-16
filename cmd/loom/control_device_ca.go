package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// prepareDeviceCA 保存首份 CA/profile 后返回；重复准备读取同一 profile 与
// 封装版本。该文件仅是待认证材料，正式签发须由当前 certified CA registry 选取。
func (material *controlSoftwareMaterial) prepareDeviceCA(clusterID, proposalID string, now time.Time) (wire.DeviceCertificateProfileStateV1, error) {
	unlock, err := lockControlState(filepath.Join(material.dir, "software-material"))
	if err != nil {
		return wire.DeviceCertificateProfileStateV1{}, err
	}
	defer unlock()
	path := filepath.Join(material.dir, "software-material", "device-ca-prepared.json")
	var profile wire.DeviceCertificateProfileStateV1
	if err := readCanonicalFile(path, 4<<20, &profile); err == nil {
		if profile.ClusterID != clusterID || profile.ProfileID != "device-identity" {
			return profile, errors.New("[Device CA] 已有准备材料属于不同网络或 profile")
		}
		preparedAt, err := wire.ParseTimeZ(profile.StatusChangedAt)
		if err != nil {
			return profile, err
		}
		signer, err := material.LoadSigner(profile.ProfileIntent.IssuerKeyArtifactHash, "ca_private_key", preparedAt)
		if err != nil {
			return profile, err
		}
		defer clearControlSigner(signer)
		return profile, verifyControlDeviceIssuer(profile, signer)
	} else if !errors.Is(err, os.ErrNotExist) {
		return profile, err
	}
	if now.IsZero() || now != now.UTC().Truncate(time.Second) {
		return profile, errors.New("[Device CA] 准备时间无效")
	}
	_, issuer, key, err := makeCertificateAuthority("Loom Device CA", now, now.Add(2*365*24*time.Hour))
	if err != nil {
		return profile, err
	}
	defer clear(key)
	secret, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return profile, err
	}
	defer clear(secret)
	recipient, err := material.recipient()
	if err != nil {
		return profile, err
	}
	sealing := wire.P256RootOnlySealingPolicyV1()
	recipients := []wire.SealedBlobRecipientKeyRefV1{recipient}
	context, err := wire.NewSealedSecretContext(clusterID, proposalID, "device-ca", "ca_private_key",
		wire.SecretArtifactOwnerV1{Kind: "device", Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: material.deviceID}},
		1, &sealing, recipients)
	if err != nil {
		return profile, err
	}
	policy, err := material.availabilityPolicy(clusterID)
	if err != nil {
		return profile, err
	}
	evidence, err := enrollmentv2.CreateLocalSealedMaterial(material.store, context, sealing, recipients, secret, key,
		policy, material.deviceID, material.reporter, now, rand.Reader)
	if err != nil {
		return profile, err
	}
	artifactHash, err := material.saveEvidence(evidence)
	if err != nil {
		return profile, err
	}
	chain := []string{base64.RawURLEncoding.EncodeToString(issuer.Raw)}
	issuerHash, err := wire.HashBytes(wire.DomainDeviceIssuerCertificateDER, issuer.Raw)
	if err != nil {
		return profile, err
	}
	chainHash, err := wire.HashObject(wire.DomainDeviceIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{1, chain})
	if err != nil {
		return profile, err
	}
	intent := wire.DeviceCertificateProfileIntentV1{Schema: 1, ClusterID: clusterID, ProfileID: "device-identity", Generation: 1,
		TargetStatus: "active", IssuerID: material.deviceID, IssuerGeneration: 1, IssuerFencingEpoch: 1,
		IssuanceNotBefore: now.Format(time.RFC3339), IssuanceNotAfter: now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		ProfileKind: "loom-device-x509-v1", IssuerCertificateDER: chain[0], IssuerCertificateHash: issuerHash,
		IssuerChainDER: chain, IssuerChainHash: chainHash, IssuerKeyArtifactHash: artifactHash,
		AllowedPlatforms:        []string{"windows-desktop", "android", "linux-server"},
		AllowedResponsibilities: []string{"use_loom", "forward", "internet_egress"}, ValiditySeconds: 30 * 24 * 60 * 60,
		AllowedSubjectKeyAlgorithm: "p256", SignatureAlgorithm: "ed25519", SubjectMode: "empty",
		SANURIPrefix: "spiffe://loom.internal/" + url.PathEscape(clusterID) + "/device/", KeyUsageBits: []string{"digital_signature"},
		RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"}, RequiredPolicyOIDs: []string{"1.3.6.1.4.1.55555.2"},
		ExtensionOrderOIDs: []string{"2.5.29.15", "2.5.29.37", "2.5.29.19", "2.5.29.35", "2.5.29.17", "2.5.29.32"}}
	intentHash, err := wire.DeviceCertificateProfileIntentHash(&intent)
	if err != nil {
		return profile, err
	}
	profile = wire.DeviceCertificateProfileStateV1{Schema: 1, ClusterID: clusterID, ProfileID: intent.ProfileID,
		Generation: 1, ProfileIntent: intent, DeviceCertificateProfileIntentHash: intentHash,
		Status: "active", StatusChangedAt: now.Format(time.RFC3339)}
	if err := verifyControlDeviceIssuer(profile, key); err != nil {
		return profile, err
	}
	return profile, writeCanonicalAtomic(path, profile, 0o600)
}

func verifyControlDeviceIssuer(profile wire.DeviceCertificateProfileStateV1, signer crypto.Signer) error {
	if err := wire.ValidateDeviceCertificateProfileState(&profile); err != nil {
		return err
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	der, decodeErr := base64.RawURLEncoding.DecodeString(profile.ProfileIntent.IssuerCertificateDER)
	issuer, parseErr := x509.ParseCertificate(der)
	if err != nil || decodeErr != nil || parseErr != nil ||
		base64.RawURLEncoding.EncodeToString(public) != base64.RawURLEncoding.EncodeToString(issuer.RawSubjectPublicKeyInfo) {
		return errors.New("[Device CA] 封装密钥不属于 exact issuer certificate")
	}
	return nil
}

func (runtime *controlRuntime) loadDeviceIssuer(profile wire.DeviceCertificateProfileStateV1) (crypto.Signer, error) {
	material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, false)
	if err != nil {
		return nil, err
	}
	defer material.Close()
	issuedAt, err := wire.ParseTimeZ(profile.StatusChangedAt)
	if err != nil {
		return nil, err
	}
	key, err := material.LoadSigner(profile.ProfileIntent.IssuerKeyArtifactHash, "ca_private_key", issuedAt)
	if err != nil {
		return nil, err
	}
	if err := verifyControlDeviceIssuer(profile, key); err != nil {
		clearControlSigner(key)
		return nil, err
	}
	return key, nil
}

func clearControlSigner(signer crypto.Signer) {
	if key, ok := signer.(ed25519.PrivateKey); ok {
		clear(key)
	}
}
