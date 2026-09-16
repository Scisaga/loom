package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type controlSoftwareCustodyV1 struct {
	Schema        int    `json:"schema"`
	DeviceID      string `json:"device_id"`
	WrappingPKCS8 string `json:"wrapping_pkcs8"`
	ReporterPKCS8 string `json:"reporter_pkcs8"`
}

type controlSoftwareMaterial struct {
	dir      string
	deviceID string
	wrapping *ecdsa.PrivateKey
	reporter ed25519.PrivateKey
	store    *enrollmentv2.SealedArtifactStore
}

// 软件 custody 的两个用途使用不同密钥。它不复用 Device、管理员、QC 或
// Enrollment signing key，也不把本地 PKCS#8 声称为不可导出的硬件密钥。
func openControlSoftwareMaterial(dir, deviceID string, create bool) (*controlSoftwareMaterial, error) {
	root := filepath.Join(dir, "software-material")
	if create {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("[software custody] 缺受保护的本机密钥目录")
	}
	unlock, err := lockControlState(root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	path := filepath.Join(root, "custody.json")
	var stored controlSoftwareCustodyV1
	err = readCanonicalFile(path, 64<<10, &stored)
	if errors.Is(err, os.ErrNotExist) && create {
		wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		defer wrapping.D.SetInt64(0)
		_, reporter, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		defer clear(reporter)
		wrapDER, err := x509.MarshalPKCS8PrivateKey(wrapping)
		if err != nil {
			return nil, err
		}
		defer clear(wrapDER)
		reportDER, err := x509.MarshalPKCS8PrivateKey(reporter)
		if err != nil {
			return nil, err
		}
		defer clear(reportDER)
		stored = controlSoftwareCustodyV1{Schema: 1, DeviceID: deviceID,
			WrappingPKCS8: base64.RawURLEncoding.EncodeToString(wrapDER), ReporterPKCS8: base64.RawURLEncoding.EncodeToString(reportDER)}
		if err := writeCanonicalAtomic(path, stored, 0o600); err != nil {
			return nil, err
		}
		// 写后回读后才让任何 ref 依赖此 custody。
		if err := readCanonicalFile(path, 64<<10, &stored); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if stored.Schema != 1 || stored.DeviceID != deviceID || deviceID == "" {
		return nil, errors.New("[software custody] 本机 Device 绑定不匹配")
	}
	wrapDER, err := base64.RawURLEncoding.DecodeString(stored.WrappingPKCS8)
	if err != nil {
		return nil, err
	}
	defer clear(wrapDER)
	parsed, err := x509.ParsePKCS8PrivateKey(wrapDER)
	wrapping, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || wrapping.Curve != elliptic.P256() {
		return nil, errors.New("[software custody] wrapping key 无效")
	}
	reportDER, err := base64.RawURLEncoding.DecodeString(stored.ReporterPKCS8)
	if err != nil {
		wrapping.D.SetInt64(0)
		return nil, err
	}
	defer clear(reportDER)
	parsed, err = x509.ParsePKCS8PrivateKey(reportDER)
	reporter, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(reporter) != ed25519.PrivateKeySize {
		wrapping.D.SetInt64(0)
		return nil, errors.New("[software custody] reporter key 无效")
	}
	store, err := enrollmentv2.OpenSealedArtifactStore(filepath.Join(dir, "sealed-artifacts"))
	if err != nil {
		wrapping.D.SetInt64(0)
		clear(reporter)
		return nil, err
	}
	return &controlSoftwareMaterial{dir: dir, deviceID: deviceID, wrapping: wrapping, reporter: reporter, store: store}, nil
}

func (material *controlSoftwareMaterial) Close() {
	material.wrapping.D.SetInt64(0)
	clear(material.reporter)
}

func (material *controlSoftwareMaterial) recipient() (wire.SealedBlobRecipientKeyRefV1, error) {
	key, err := enrollmentv2.MaterialAuthorityKey(material.wrapping.Public())
	if err != nil {
		return wire.SealedBlobRecipientKeyRefV1{}, err
	}
	return wire.SealedBlobRecipientKeyRefV1{RecipientID: material.deviceID, RecipientKeyGeneration: 1,
		RecipientKeyID: key.KeyID, RecipientKeyProfile: wire.P256RootOnlySealingPolicyV1().RecipientKeyProfile, RecipientPublicKey: key}, nil
}

func (material *controlSoftwareMaterial) availabilityPolicy(clusterID string) (wire.ArtifactAvailabilityPolicyV1, error) {
	key, err := enrollmentv2.MaterialAuthorityKey(material.reporter.Public())
	if err != nil {
		return wire.ArtifactAvailabilityPolicyV1{}, err
	}
	policy := wire.ArtifactAvailabilityPolicyV1{Schema: 1, ClusterID: clusterID, PolicyID: "local-software-artifacts", Generation: 1,
		RequiredReceiptCount: 1, RequiredFaultDomainCount: 1, MaxReceiptAgeSeconds: 300,
		Reporters: []wire.ArtifactAvailabilityReporterRefV1{{ReporterID: material.deviceID, ReporterKey: key,
			FaultDomain: material.deviceID, AllowedPurposes: []string{"invite_token", "device_credential", "data_plane_credential",
				"tls_private_key", "ca_private_key", "control_peer_identity", "recovery_private_key"}}}}
	return policy, wire.ValidateArtifactAvailabilityPolicy(&policy)
}

func (material *controlSoftwareMaterial) saveEvidence(evidence enrollmentv2.SealedMaterialEvidenceV1) (string, error) {
	hash, err := wire.SecretArtifactRefHash(&evidence.Ref)
	if err != nil {
		return "", err
	}
	root := filepath.Join(material.dir, "secret-evidence")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(root, strings.TrimPrefix(hash, "sha256:")+".json")
	if prior, err := readOwnerOnlyFile(path, 4<<20); err == nil {
		body, encodeErr := wire.MarshalCanonical(evidence)
		if encodeErr != nil || !bytes.Equal(body, prior) {
			return "", errors.New("[secret artifact] 同一引用已有不同证据")
		}
		return hash, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return hash, writeCanonicalAtomic(path, evidence, 0o600)
}

// LoadSigner 由已认证的 profile 指定 exact artifact；解封失败不重生成密钥。
func (material *controlSoftwareMaterial) LoadSigner(hash, purpose string, certifiedAt time.Time) (crypto.Signer, error) {
	if _, err := wire.ParseHash(hash); err != nil {
		return nil, err
	}
	var evidence enrollmentv2.SealedMaterialEvidenceV1
	if err := readCanonicalFile(filepath.Join(material.dir, "secret-evidence", strings.TrimPrefix(hash, "sha256:")+".json"), 4<<20, &evidence); err != nil {
		return nil, err
	}
	actual, err := wire.SecretArtifactRefHash(&evidence.Ref)
	if err != nil || actual != hash || evidence.Ref.Purpose != purpose || evidence.Ref.Owner.Device == nil ||
		evidence.Ref.Owner.Device.DeviceID != material.deviceID || evidence.Ref.SealedBlob == nil || evidence.Ref.PublicKey == nil {
		return nil, errors.New("[software custody] exact key artifact 的用途或 executor 不匹配")
	}
	if err := wire.VerifySecretArtifactEvidence(&evidence.Ref, evidence.Proof, &evidence.Policy, evidence.Receipts,
		certifiedAt, 0, ""); err != nil {
		return nil, err
	}
	envelope, err := material.store.Get(evidence.Ref.SealedBlob.CiphertextDigest)
	if err != nil {
		return nil, err
	}
	if err := wire.VerifySealedSecretBinding(&evidence.Ref, &envelope); err != nil {
		return nil, err
	}
	recipient, err := material.recipient()
	if err != nil {
		return nil, err
	}
	secret, err := wire.UnsealSecretP256(&envelope, recipient, material.wrapping)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	parsed, err := x509.ParsePKCS8PrivateKey(secret)
	signer, ok := parsed.(crypto.Signer)
	if err != nil || !ok {
		return nil, errors.New("[software custody] 封装材料不是 signing key")
	}
	key, err := enrollmentv2.MaterialAuthorityKey(signer.Public())
	if err != nil || !wire.EqualCanonical(key, *evidence.Ref.PublicKey) {
		return nil, errors.New("[software custody] 解封密钥与已认证 SPKI 不匹配")
	}
	return signer, nil
}
