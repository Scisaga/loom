//go:build linux

package clientv2

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"loom/internal/wire"
)

type PendingClaimV2 struct {
	Schema        int                        `json:"schema"`
	ClaimCore     wire.EnrollmentClaimCoreV2 `json:"claim_core"`
	ClaimCoreHash string                     `json:"claim_core_hash"`
}

// OpenOrCreatePendingClaim 保证 CSR/client nonce/core 只生成一次；跨 ingress 重试只重签新 challenge。
func OpenOrCreatePendingClaim(path string, identity *EnrollmentIdentityV1, input ClaimCoreInputV2) (*PendingClaimV2, error) {
	if path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return nil, errors.New("[D129 Linux] pending claim path 必须是规范绝对路径")
	}
	if identity == nil {
		return nil, errors.New("[D129 Linux] enrollment identity 不能为空")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openPrivateLock(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if pending, err := loadPendingClaim(path, identity, input); err == nil {
		return pending, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if input.ClientNonce == "" {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		input.ClientNonce = base64.RawURLEncoding.EncodeToString(nonce)
	}
	core, coreHash, err := identity.PrepareClaimCore(input)
	if err != nil {
		return nil, err
	}
	pending := &PendingClaimV2{Schema: 2, ClaimCore: core, ClaimCoreHash: coreHash}
	if err := persistProtectedCanonical(path, pending); err != nil {
		return nil, err
	}
	return loadPendingClaim(path, identity, input)
}

func loadPendingClaim(path string, identity *EnrollmentIdentityV1, input ClaimCoreInputV2) (*PendingClaimV2, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > 1<<20 {
		return nil, errors.New("[D129 Linux] pending claim 必须是 0600 小型普通文件")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("[D129 Linux] pending claim owner 不是当前服务账号")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pending PendingClaimV2
	canonical, err := wire.DecodeStrict(body, 1<<20, &pending)
	if err != nil || !bytes.Equal(canonical, body) || pending.Schema != 2 {
		return nil, errors.New("[D129 Linux] pending claim wire 无效")
	}
	coreHash, err := wire.EnrollmentClaimCoreHash(&pending.ClaimCore)
	if err != nil || coreHash != pending.ClaimCoreHash {
		return nil, errors.New("[D129 Linux] pending claim core hash 不匹配")
	}
	if !claimCoreMatchesInput(pending.ClaimCore, input) {
		return nil, errors.New("[D129 Linux] pending claim 与本次 Invite/authority 不一致")
	}
	identityKey, wrappingKey, err := identity.keys()
	if err != nil {
		return nil, err
	}
	identitySPKI, _ := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	wrappingSPKI, _ := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if pending.ClaimCore.DeviceIdentityPublicKey != base64.RawURLEncoding.EncodeToString(identitySPKI) ||
		pending.ClaimCore.WrappingPublicKey != base64.RawURLEncoding.EncodeToString(wrappingSPKI) {
		return nil, errors.New("[D129 Linux] pending claim 不属于当前 identity/wrapping keys")
	}
	return &pending, nil
}

func claimCoreMatchesInput(core wire.EnrollmentClaimCoreV2, input ClaimCoreInputV2) bool {
	if core.ClusterID != input.ClusterID || core.InviteID != input.InviteID || core.RequestID != input.RequestID ||
		core.CertifiedInviteRecordHash != input.CertifiedInviteRecordHash ||
		core.DeviceEnrollmentIntentCommitmentHash != input.DeviceEnrollmentIntentCommitmentHash ||
		core.DeviceEnrollmentIntentOpeningHash != input.DeviceEnrollmentIntentOpeningHash ||
		core.AcceptedDeviceEnrollmentIntentHash != input.AcceptedDeviceEnrollmentIntentHash ||
		core.BaseRecoveryEpoch != input.BaseRecoveryEpoch || core.BaseControlEpoch != input.BaseControlEpoch ||
		core.BaseControlSetHash != input.BaseControlSetHash || core.BaseHeadHash != input.BaseHeadHash ||
		core.ClientPlatform != "linux-server" {
		return false
	}
	return input.ClientNonce == "" || core.ClientNonce == input.ClientNonce
}

func persistProtectedCanonical(path string, value any) error {
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".pending-v2-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	_, err = temporary.Write(body)
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
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}
