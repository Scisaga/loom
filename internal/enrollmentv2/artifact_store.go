package enrollmentv2

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"loom/internal/wire"
)

const maximumSealedArtifactBytes = 4 << 20

// ReleasedEnrollmentArtifactReader 只返回已经由 completion Head 原子授权释放、
// 且属于同一 Invite 的 immutable sealed artifact（D124、D130、D131）。
type ReleasedEnrollmentArtifactReader func(context.Context, string, string, string) (wire.SealedSecretEnvelopeV1, error)

// SealedArtifactStore 保存 ciphertext-addressed canonical envelope。目录和文件权限
// 是服务端私有边界的一部分，不能把该目录挂到 public distribution（D124）。
type SealedArtifactStore struct {
	mu   sync.Mutex
	root string
}

func OpenSealedArtifactStore(root string) (*SealedArtifactStore, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("[D124 secret artifact] store root 必须是规范绝对路径")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("[D124 secret artifact] store root 必须是 0700 实体目录")
	}
	return &SealedArtifactStore{root: root}, nil
}

// Put 先验证 ref/envelope exact binding，再以 O_EXCL 等价的 hard-link publish
// 原子固定 first bytes；同摘要只能重放完全相同的 canonical envelope（D124）。
func (store *SealedArtifactStore) Put(ref *wire.SecretArtifactRefV2,
	envelope *wire.SealedSecretEnvelopeV1) error {
	if store == nil || ref == nil || envelope == nil || ref.SealedBlob == nil {
		return errors.New("[D124 secret artifact] store put 输入不完整")
	}
	if err := wire.ValidateSecretArtifactRef(ref); err != nil {
		return err
	}
	if err := wire.VerifySealedSecretBinding(ref, envelope); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(envelope)
	if err != nil || len(body) == 0 || len(body) > maximumSealedArtifactBytes {
		return errors.New("[D124 secret artifact] canonical envelope 无效或过大")
	}
	path, err := store.path(ref.SealedBlob.CiphertextDigest)
	if err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, readErr := store.read(path, ref.SealedBlob.CiphertextDigest); readErr == nil {
		existingBody, _ := wire.MarshalCanonical(existing)
		if !bytes.Equal(existingBody, body) {
			return errors.New("[D124 secret artifact] 同 ciphertext digest 已有不同 bytes")
		}
		return nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	temporary, err := os.CreateTemp(store.root, ".sealed-artifact-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(body)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := store.read(path, ref.SealedBlob.CiphertextDigest)
		if readErr != nil {
			return readErr
		}
		existingBody, _ := wire.MarshalCanonical(existing)
		if !bytes.Equal(existingBody, body) {
			return errors.New("[D124 secret artifact] 并发 publish 产生不同 first bytes")
		}
		return nil
	}
	directory, err := os.Open(store.root)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr = directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (store *SealedArtifactStore) Get(ciphertextDigest string) (wire.SealedSecretEnvelopeV1, error) {
	if store == nil {
		return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] store 未初始化")
	}
	path, err := store.path(ciphertextDigest)
	if err != nil {
		return wire.SealedSecretEnvelopeV1{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.read(path, ciphertextDigest)
}

func (store *SealedArtifactStore) path(ciphertextDigest string) (string, error) {
	raw, err := wire.ParseHash(ciphertextDigest)
	if err != nil {
		return "", err
	}
	return filepath.Join(store.root, hex.EncodeToString(raw)+".json"), nil
}

func (store *SealedArtifactStore) read(path, ciphertextDigest string) (wire.SealedSecretEnvelopeV1, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return wire.SealedSecretEnvelopeV1{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() < 1 || info.Size() > maximumSealedArtifactBytes {
		return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] stored envelope 不是 0600 有界普通文件")
	}
	file, err := os.Open(path)
	if err != nil {
		return wire.SealedSecretEnvelopeV1{}, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] stored envelope 在读取时发生替换")
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximumSealedArtifactBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return wire.SealedSecretEnvelopeV1{}, readErr
	}
	if closeErr != nil {
		return wire.SealedSecretEnvelopeV1{}, closeErr
	}
	if len(body) == 0 || len(body) > maximumSealedArtifactBytes {
		return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] stored envelope 大小无效")
	}
	var envelope wire.SealedSecretEnvelopeV1
	canonical, err := wire.DecodeStrict(body, maximumSealedArtifactBytes, &envelope)
	if err != nil || !bytes.Equal(canonical, body) {
		return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] stored envelope 不是 exact canonical wire")
	}
	digest, err := wire.SealedSecretEnvelopeHash(&envelope)
	if err != nil || digest != ciphertextDigest {
		return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] stored envelope digest 不匹配")
	}
	return envelope, nil
}

// NewReleasedEnrollmentArtifactReader 把 ciphertext store 与 durable Enrollment
// transaction 结合：artifact 存在并不等于获授权，只有 completed completion projection
// 的 release 状态可以被 private service 读取（D124、D130）。
func NewReleasedEnrollmentArtifactReader(transactions *Store,
	artifacts *SealedArtifactStore) (ReleasedEnrollmentArtifactReader, error) {
	if transactions == nil || artifacts == nil {
		return nil, errors.New("[D124 secret artifact] release reader stores 不完整")
	}
	return func(ctx context.Context, clusterID, inviteID, ciphertextDigest string) (wire.SealedSecretEnvelopeV1, error) {
		if err := ctx.Err(); err != nil {
			return wire.SealedSecretEnvelopeV1{}, err
		}
		if clusterID == "" || inviteID == "" {
			return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] release identity 无效")
		}
		if _, err := wire.ParseHash(ciphertextDigest); err != nil {
			return wire.SealedSecretEnvelopeV1{}, err
		}
		record, found := transactions.SnapshotRecord(inviteID)
		if !found || validateDurableRecord(&record) != nil || record.State.ClusterID != clusterID ||
			record.State.Status != "completed" || record.ResultArtifact == nil ||
			record.CompletionProjection == nil || record.CompletionProjection.ResultReleaseStatus != "authorized" {
			return wire.SealedSecretEnvelopeV1{}, errors.New("[D130 Enrollment] artifact 尚未获得 completion release authorization")
		}
		var exactRef *wire.SecretArtifactRefV2
		for index := range record.ResultArtifact.SecretArtifactRefs {
			candidate := &record.ResultArtifact.SecretArtifactRefs[index]
			if candidate.SealedBlob != nil && candidate.SealedBlob.CiphertextDigest == ciphertextDigest {
				if exactRef != nil {
					return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] completed result 含重复 ciphertext digest")
				}
				exactRef = candidate
			}
		}
		if exactRef == nil {
			return wire.SealedSecretEnvelopeV1{}, errors.New("[D124 secret artifact] ciphertext 不属于该 Invite result")
		}
		envelope, err := artifacts.Get(ciphertextDigest)
		if err != nil {
			return wire.SealedSecretEnvelopeV1{}, err
		}
		if err := wire.VerifySealedSecretBinding(exactRef, &envelope); err != nil {
			return wire.SealedSecretEnvelopeV1{}, err
		}
		return envelope, nil
	}, nil
}
